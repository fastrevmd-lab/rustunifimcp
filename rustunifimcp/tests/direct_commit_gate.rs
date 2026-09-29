//! `--allow-direct-commit` gates the operational tools that mutate a device
//! or client in one call with no independent second-principal approval.
//!
//! `unifi_device_action`'s `restart`, `adopt`, `upgrade`, and `port_action`,
//! and `unifi_client_action`'s `block`, `unblock`, and `reconnect` act on the
//! controller immediately -- there is no change set to route an operational
//! command like "restart this device" through. Without the flag, the server
//! must refuse those calls before they ever reach the controller, over stdio
//! (no caller context at all) exactly as over HTTP. With the flag, the call
//! proceeds past the gate and the audit trail shows it ran under the flag --
//! for `adopt`, `upgrade`, and `port_action` it then fails on the follow-up
//! `stat/device` lookup those three make before dispatching (nothing listens
//! at `127.0.0.1:1` in this test), and `restart` fails dispatching directly.
//! Either way that failure must surface as `result=error` on the *same*
//! audit record the gate produced, not `result=ok`: the gate's `AuditScope`
//! stays open until the mutation actually runs, rather than being dropped --
//! and so emitted -- the moment the gate itself passes. This is exactly the
//! signal these tests need: it proves both that the gate passed and that the
//! audit outcome reflects the real call, without requiring a real UniFi
//! controller.
//!
//! `locate` is deliberately not gated (it is self-reverting), which
//! `stdio_locate_is_not_gated_by_direct_commit` pins so a future change to
//! the gated-action list is a visible decision, not a silent drift either
//! way.

use mecmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};
use mecmcp_transport::{LimitsConfig, serve_router, test_client::McpClient};
use rustunifimcp::grant::UnifiGrant;
use rustunifimcp::server::UnifiServer;
use rustunifimcp_core::inventory::ControllerRegistry;
use rustunifimcp_core::tools::TOOL_NAMES;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------
// stdio harness
// ---------------------------------------------------------------------

/// A controllers file naming one controller, `home`, at an address nothing
/// listens on (`https://127.0.0.1:1`). A call that gets past the
/// direct-commit gate fails fast on a connection error rather than reaching
/// a real network, which is exactly the signal these tests need: it proves
/// the gate passed without requiring a real UniFi controller.
fn controllers_file() -> tempfile::NamedTempFile {
    let mut key = tempfile::NamedTempFile::new().expect("create api key file");
    key.write_all(b"dummy-api-key\n").expect("write api key");
    key.flush().expect("flush api key");
    secure(key.path());
    let key_path = key.into_temp_path().keep().expect("persist api key file");

    let mut file = tempfile::NamedTempFile::new().expect("create controllers file");
    let body = format!(
        r#"{{"version":1,"devices":{{"home":{{"endpoint":"https://127.0.0.1:1","site":"default","api_key_file":"{}","allow_private_api":true}}}}}}"#,
        key_path.display()
    );
    file.write_all(body.as_bytes())
        .expect("write controllers file");
    file.flush().expect("flush controllers file");
    secure(file.path());
    file
}

fn secure(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Spawn `rustunifimcp` over stdio with `extra_args`, send `initialize` then
/// `request`, and return every stderr line it produced (default logging
/// writes `target: "audit"` records to stderr with no `--audit-*` flags
/// needed).
fn stderr_for_request(extra_args: &[&str], request: &str) -> Vec<String> {
    let controllers = controllers_file();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rustunifimcp"));
    cmd.args([
        "--controllers-file",
        controllers.path().to_str().expect("utf-8 path"),
    ]);
    for a in extra_args {
        cmd.arg(a);
    }

    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rustunifimcp");

    {
        let stdin = child.stdin.as_mut().expect("stdin");
        for line in [
            r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            request,
        ] {
            writeln!(stdin, "{line}").expect("write request");
        }
        stdin.flush().expect("flush");
    }
    drop(child.stdin.take());

    let stderr = child.stderr.take().expect("stderr");
    let lines: Vec<String> = BufReader::new(stderr)
        .lines()
        .map_while(Result::ok)
        .collect();
    let _ = child.wait();
    lines
}

fn audit_lines(lines: &[String]) -> Vec<&String> {
    lines.iter().filter(|line| line.contains("audit")).collect()
}

const RESTART_REQUEST: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"unifi_device_action","arguments":{"controller":"home","device":"aa:bb:cc:dd:ee:ff","action":"restart"}}}"#;
const LOCATE_REQUEST: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"unifi_device_action","arguments":{"controller":"home","device":"aa:bb:cc:dd:ee:ff","action":"locate"}}}"#;
const ADOPT_REQUEST: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"unifi_device_action","arguments":{"controller":"home","device":"aa:bb:cc:dd:ee:ff","action":"adopt","expected_model":"U6-LR"}}}"#;
const UPGRADE_REQUEST: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"unifi_device_action","arguments":{"controller":"home","device":"aa:bb:cc:dd:ee:ff","action":"upgrade","firmware_version":"7.1.66.15380"}}}"#;
const PORT_ACTION_REQUEST: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"unifi_device_action","arguments":{"controller":"home","device":"aa:bb:cc:dd:ee:ff","action":"port_action","port_index":1}}}"#;
const BLOCK_REQUEST: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"unifi_client_action","arguments":{"controller":"home","client":"aa:bb:cc:dd:ee:ff","action":"block"}}}"#;

/// Without `--allow-direct-commit`, a stdio session -- which carries no
/// caller context at all -- is refused before the controller is ever
/// touched, and the refusal is audited as a denial.
#[test]
fn stdio_refuses_device_restart_without_the_flag() {
    let lines = stderr_for_request(&[], RESTART_REQUEST);

    let audits = audit_lines(&lines);
    let record = audits
        .iter()
        .find(|line| line.contains("unifi_device_action") && line.contains("direct_commit"))
        .unwrap_or_else(|| panic!("no direct-commit gate audit record among: {audits:#?}"));
    assert!(
        record.contains("authorization=denied") && record.contains("direct_commit_disabled"),
        "refusal must be audited as a denial naming the reason: {record}"
    );
}

/// With `--allow-direct-commit`, the same stdio call passes the gate -- it
/// then fails for an unrelated reason (nothing listens at 127.0.0.1:1 in
/// this test), but that failure must not be the direct-commit refusal, and
/// the audit trail must show the flag was exercised. The *same* audit record
/// must also show the mutation's real outcome, not the gate's: the
/// `AuditScope` the gate opens stays open until `ops::device_action` actually
/// runs, so a controller that never even accepts the connection must be
/// recorded as `result=error`, not `result=ok`.
#[test]
fn stdio_allows_device_restart_with_the_flag() {
    let lines = stderr_for_request(&["--allow-direct-commit"], RESTART_REQUEST);

    let audits = audit_lines(&lines);
    let record = audits
        .iter()
        .find(|line| line.contains("unifi_device_action") && line.contains("direct_commit"))
        .unwrap_or_else(|| panic!("no direct-commit gate audit record among: {audits:#?}"));
    assert!(
        !record.contains("direct_commit_disabled"),
        "the flag must let the call proceed past the gate: {record}"
    );
    assert!(
        record.contains("direct_commit_allowed=true"),
        "an allowed direct-commit call must be tagged in the audit trail: {record}"
    );
    assert!(
        record.contains("result=error") && !record.contains("result=ok"),
        "the audit record must reflect the mutation's real outcome (a connection failure), not \
         the gate's success: {record}"
    );
}

/// `adopt`, `upgrade`, and `port_action` are each gated identically to
/// `restart`, refused before the controller is ever touched.
#[test]
fn stdio_refuses_device_adopt_upgrade_and_port_action_without_the_flag() {
    for (name, request) in [
        ("adopt", ADOPT_REQUEST),
        ("upgrade", UPGRADE_REQUEST),
        ("port_action", PORT_ACTION_REQUEST),
    ] {
        let lines = stderr_for_request(&[], request);

        let audits = audit_lines(&lines);
        let record = audits
            .iter()
            .find(|line| line.contains("unifi_device_action") && line.contains("direct_commit"))
            .unwrap_or_else(|| {
                panic!("{name}: no direct-commit gate audit record among: {audits:#?}")
            });
        assert!(
            record.contains("authorization=denied") && record.contains("direct_commit_disabled"),
            "{name}: refusal must be audited as a denial naming the reason: {record}"
        );
    }
}

/// With `--allow-direct-commit`, `adopt`, `upgrade`, and `port_action` each
/// pass the gate -- each then fails on the `stat/device` lookup it makes
/// before dispatching (nothing listens at 127.0.0.1:1 in this test), but
/// that failure must not be the direct-commit refusal, and the audit trail
/// must show the flag was exercised. As with `restart` above, the *same*
/// audit record must show the follow-up failure, not a gate-time success --
/// and, for `upgrade` and `port_action`, must carry the caller-supplied
/// `firmware_version` / `port_idx` the gate's metadata attaches, so the
/// record names what was actually requested.
#[test]
fn stdio_allows_device_adopt_upgrade_and_port_action_with_the_flag() {
    for (name, request) in [
        ("adopt", ADOPT_REQUEST),
        ("upgrade", UPGRADE_REQUEST),
        ("port_action", PORT_ACTION_REQUEST),
    ] {
        let lines = stderr_for_request(&["--allow-direct-commit"], request);

        let audits = audit_lines(&lines);
        let record = audits
            .iter()
            .find(|line| line.contains("unifi_device_action") && line.contains("direct_commit"))
            .unwrap_or_else(|| {
                panic!("{name}: no direct-commit gate audit record among: {audits:#?}")
            });
        assert!(
            !record.contains("direct_commit_disabled"),
            "{name}: the flag must let the call proceed past the gate: {record}"
        );
        assert!(
            record.contains("direct_commit_allowed=true"),
            "{name}: an allowed direct-commit call must be tagged in the audit trail: {record}"
        );
        assert!(
            record.contains("result=error") && !record.contains("result=ok"),
            "{name}: the audit record must reflect the mutation's real outcome (a connection \
             failure), not the gate's success: {record}"
        );
        if name == "upgrade" {
            assert!(
                record.contains("firmware_version=7.1.66.15380"),
                "{name}: the requested firmware version must reach the audit record: {record}"
            );
        }
        if name == "port_action" {
            assert!(
                record.contains("port_idx=1"),
                "{name}: the requested port index must reach the audit record: {record}"
            );
        }
    }
}

/// `block` is gated identically to `restart`.
#[test]
fn stdio_refuses_client_block_without_the_flag() {
    let lines = stderr_for_request(&[], BLOCK_REQUEST);

    let audits = audit_lines(&lines);
    let record = audits
        .iter()
        .find(|line| line.contains("unifi_client_action") && line.contains("direct_commit"))
        .unwrap_or_else(|| panic!("no direct-commit gate audit record among: {audits:#?}"));
    assert!(
        record.contains("authorization=denied") && record.contains("direct_commit_disabled"),
        "refusal must be audited as a denial naming the reason: {record}"
    );
}

/// `locate` is self-reverting and is deliberately not routed through the
/// direct-commit gate: no gate audit record should exist for it at all, with
/// or without the flag.
#[test]
fn stdio_locate_is_not_gated_by_direct_commit() {
    let lines = stderr_for_request(&[], LOCATE_REQUEST);

    let audits = audit_lines(&lines);
    assert!(
        !audits
            .iter()
            .any(|line| line.contains("direct_commit_disabled")),
        "locate must never be refused by the direct-commit gate: {audits:#?}"
    );
}

/// The refusal reaches the JSON-RPC caller as a tool error, not just the log.
#[test]
fn stdio_refusal_is_visible_to_the_caller() {
    let controllers = controllers_file();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rustunifimcp"));
    cmd.args([
        "--controllers-file",
        controllers.path().to_str().expect("utf-8 path"),
    ]);

    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rustunifimcp");

    {
        let stdin = child.stdin.as_mut().expect("stdin");
        for line in [
            r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            RESTART_REQUEST,
        ] {
            writeln!(stdin, "{line}").expect("write request");
        }
        stdin.flush().expect("flush");
    }

    let stdout = child.stdout.take().expect("stdout");
    let mut response_line = None;
    for line in BufReader::new(stdout).lines().map_while(Result::ok) {
        if line.contains("\"id\":2") {
            response_line = Some(line);
            break;
        }
    }
    drop(child.stdin.take());
    let _ = child.wait();

    let text = response_line.expect("a response to the tools/call request");
    assert!(
        text.contains("allow-direct-commit") || text.contains("direct-commit"),
        "the caller must be told why the call was refused: {text}"
    );
}

// ---------------------------------------------------------------------
// HTTP harness
// ---------------------------------------------------------------------

fn mint_token(path: &std::path::Path, name: &str, tools: &[&str]) -> String {
    let known = KnownNames {
        devices: None,
        tools: TOOL_NAMES,
    };
    let secret = TokenStoreFile::<UnifiGrant>::add(
        path,
        name,
        ScopeSet::Wildcard,
        ScopeSet::Allowlist(tools.iter().map(|t| (*t).to_owned()).collect()),
        &known,
    )
    .expect("mint token");
    secret.expose_secret().to_owned()
}

fn registry_with_unreachable_controller() -> Arc<ControllerRegistry> {
    let mut key = tempfile::NamedTempFile::new().expect("create api key file");
    key.write_all(b"dummy-api-key\n").expect("write api key");
    key.flush().expect("flush api key");
    secure(key.path());
    let key_path = key.into_temp_path().keep().expect("persist api key file");

    let mut controllers = tempfile::NamedTempFile::new().expect("create controllers file");
    let body = format!(
        r#"{{"version":1,"devices":{{"home":{{"endpoint":"https://127.0.0.1:1","site":"default","api_key_file":"{}","allow_private_api":true}}}}}}"#,
        key_path.display()
    );
    controllers
        .write_all(body.as_bytes())
        .expect("write controllers file");
    controllers.flush().expect("flush controllers file");
    secure(controllers.path());

    Arc::new(ControllerRegistry::load(controllers.path()).expect("load controllers"))
}

async fn start_server(
    token_store: Arc<TokenStoreFile<UnifiGrant>>,
    allow_direct_commit: bool,
) -> (String, CancellationToken, tokio::task::JoinHandle<()>) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let registry = registry_with_unreachable_controller();
    let coordinator = rustunifimcp::changeset_state::build_coordinator(
        None,
        Duration::from_secs(300),
        false,
        None,
    )
    .expect("coordinator");
    let handler = UnifiServer::new(
        registry,
        false,
        coordinator,
        None,
        mecmcp_audit::DirectCommitPolicy::new(allow_direct_commit),
    )
    .expect("server");

    let shutdown = CancellationToken::new();
    let plan = rustunifimcp::http_transport::build_http_router(
        handler,
        Some(token_store),
        Vec::new(),
        Vec::new(),
        LimitsConfig::default(),
        false,
        false,
        shutdown.clone(),
    )
    .expect("build router");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);

    let shutdown_for_task = shutdown.clone();
    let task = tokio::spawn(async move {
        serve_router(
            plan,
            format!("127.0.0.1:{port}").parse().expect("address"),
            None,
            Duration::from_millis(50),
        )
        .await
        .expect("serve_router");
        drop(shutdown_for_task);
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    (format!("http://127.0.0.1:{port}"), shutdown, task)
}

fn call_tool(
    base_url: String,
    bearer: String,
    tool: &str,
    args: serde_json::Value,
) -> serde_json::Value {
    let tool = tool.to_owned();
    let session_id = {
        let base_url = base_url.clone();
        let bearer = bearer.clone();
        McpClient::new(base_url)
            .expect("client")
            .with_bearer(bearer)
            .initialize()
            .expect("initialize")
    };

    McpClient::new(base_url)
        .expect("client")
        .with_bearer(bearer)
        .tools_call(&session_id, &tool, args)
        .expect("tools/call")
}

/// The gate applies identically over HTTP: an authenticated caller with the
/// right tool scope is refused on exactly the same terms as the stdio
/// session above, and the flag lifts the refusal for HTTP too.
#[tokio::test]
async fn http_device_restart_gate_matches_stdio_with_and_without_the_flag() {
    let tokens_dir = tempfile::tempdir().expect("tempdir");
    let tokens_path = tokens_dir.path().join("tokens.json");
    let bearer = mint_token(
        &tokens_path,
        "direct-commit-gate-test",
        &["unifi_device_action"],
    );
    let store = Arc::new(TokenStoreFile::<UnifiGrant>::load(&tokens_path).expect("load store"));

    let args = serde_json::json!({
        "controller": "home",
        "device": "aa:bb:cc:dd:ee:ff",
        "action": "restart",
    });

    // Without the flag: refused.
    {
        let (base_url, shutdown, task) = start_server(Arc::clone(&store), false).await;
        let result = tokio::task::spawn_blocking({
            let bearer = bearer.clone();
            let args = args.clone();
            move || call_tool(base_url, bearer, "unifi_device_action", args)
        })
        .await
        .expect("blocking task");
        let text = result["content"][0]["text"].as_str().unwrap_or_default();
        assert!(
            result["isError"].as_bool().unwrap_or(false),
            "restart must be refused without the flag, got: {result}"
        );
        assert!(
            text.contains("allow-direct-commit") || text.contains("direct-commit"),
            "HTTP call must be refused with the same reason as stdio: {text}"
        );
        shutdown.cancel();
        task.abort();
    }

    // With the flag: passes the gate (fails later for lack of a real
    // controller, which is not what this test is about).
    {
        let (base_url, shutdown, task) = start_server(Arc::clone(&store), true).await;
        let result = tokio::task::spawn_blocking(move || {
            call_tool(base_url, bearer, "unifi_device_action", args)
        })
        .await
        .expect("blocking task");
        let text = result["content"][0]["text"].as_str().unwrap_or_default();
        assert!(
            !text.contains("allow-direct-commit"),
            "the flag must lift the refusal over HTTP too: {text}"
        );
        shutdown.cancel();
        task.abort();
    }
}

/// `adopt`, `upgrade`, and `port_action` are each gated identically to
/// `restart` over HTTP too.
#[tokio::test]
async fn http_device_action_gate_covers_adopt_upgrade_and_port_action() {
    let tokens_dir = tempfile::tempdir().expect("tempdir");
    let tokens_path = tokens_dir.path().join("tokens.json");
    let bearer = mint_token(&tokens_path, "device-gate-test", &["unifi_device_action"]);
    let store = Arc::new(TokenStoreFile::<UnifiGrant>::load(&tokens_path).expect("load store"));

    for args in [
        serde_json::json!({
            "controller": "home",
            "device": "aa:bb:cc:dd:ee:ff",
            "action": "adopt",
            "expected_model": "U6-LR",
        }),
        serde_json::json!({
            "controller": "home",
            "device": "aa:bb:cc:dd:ee:ff",
            "action": "upgrade",
            "firmware_version": "7.1.66.15380",
        }),
        serde_json::json!({
            "controller": "home",
            "device": "aa:bb:cc:dd:ee:ff",
            "action": "port_action",
            "port_index": 1,
        }),
    ] {
        let action = args["action"].as_str().expect("action").to_owned();
        let (base_url, shutdown, task) = start_server(Arc::clone(&store), false).await;
        let result = tokio::task::spawn_blocking({
            let bearer = bearer.clone();
            move || call_tool(base_url, bearer, "unifi_device_action", args)
        })
        .await
        .expect("blocking task");
        let text = result["content"][0]["text"].as_str().unwrap_or_default();
        assert!(
            result["isError"].as_bool().unwrap_or(false),
            "{action} must be refused without the flag, got: {result}"
        );
        assert!(
            text.contains("allow-direct-commit") || text.contains("direct-commit"),
            "{action} must be refused by the direct-commit gate without the flag, got: {text}"
        );
        shutdown.cancel();
        task.abort();
    }
}

/// `block`, `unblock`, and `reconnect` are each gated; `authorize` and
/// `limit_bandwidth` are refused for being unwired, not by the direct-commit
/// gate, so they must not carry the direct-commit refusal text.
#[tokio::test]
async fn http_client_action_gate_covers_block_unblock_reconnect_only() {
    let tokens_dir = tempfile::tempdir().expect("tempdir");
    let tokens_path = tokens_dir.path().join("tokens.json");
    let bearer = mint_token(&tokens_path, "client-gate-test", &["unifi_client_action"]);
    let store = Arc::new(TokenStoreFile::<UnifiGrant>::load(&tokens_path).expect("load store"));

    for action in ["block", "unblock", "reconnect"] {
        let (base_url, shutdown, task) = start_server(Arc::clone(&store), false).await;
        let result = tokio::task::spawn_blocking({
            let bearer = bearer.clone();
            let action = action.to_owned();
            move || {
                call_tool(
                    base_url,
                    bearer,
                    "unifi_client_action",
                    serde_json::json!({
                        "controller": "home",
                        "client": "aa:bb:cc:dd:ee:ff",
                        "action": action,
                    }),
                )
            }
        })
        .await
        .expect("blocking task");
        let text = result["content"][0]["text"].as_str().unwrap_or_default();
        assert!(
            text.contains("allow-direct-commit") || text.contains("direct-commit"),
            "{action} must be refused by the direct-commit gate without the flag, got: {text}"
        );
        shutdown.cancel();
        task.abort();
    }

    let (base_url, shutdown, task) = start_server(Arc::clone(&store), false).await;
    let result = tokio::task::spawn_blocking({
        let bearer = bearer.clone();
        move || {
            call_tool(
                base_url,
                bearer,
                "unifi_client_action",
                serde_json::json!({
                    "controller": "home",
                    "client": "aa:bb:cc:dd:ee:ff",
                    "action": "authorize",
                }),
            )
        }
    })
    .await
    .expect("blocking task");
    let text = result["content"][0]["text"].as_str().unwrap_or_default();
    assert!(
        !text.contains("allow-direct-commit") && !text.contains("direct-commit"),
        "authorize is unwired, not direct-commit gated, and must not carry the gate's text: {text}"
    );
    shutdown.cancel();
    task.abort();
}

/// A malformed MAC address is refused before dispatch, over the real
/// authenticated HTTP path -- not just in `ops::tests`' unit coverage.
#[tokio::test]
async fn http_rejects_a_malformed_device_mac() {
    let tokens_dir = tempfile::tempdir().expect("tempdir");
    let tokens_path = tokens_dir.path().join("tokens.json");
    let bearer = mint_token(
        &tokens_path,
        "mac-validation-test",
        &["unifi_device_action"],
    );
    let store = Arc::new(TokenStoreFile::<UnifiGrant>::load(&tokens_path).expect("load store"));

    // Direct-commit is allowed here so a failure can only be the MAC check,
    // not the direct-commit gate.
    let (base_url, shutdown, task) = start_server(store, true).await;
    let result = tokio::task::spawn_blocking(move || {
        call_tool(
            base_url,
            bearer,
            "unifi_device_action",
            serde_json::json!({
                "controller": "home",
                "device": "not-a-mac-address",
                "action": "restart",
            }),
        )
    })
    .await
    .expect("blocking task");

    let text = result["content"][0]["text"].as_str().unwrap_or_default();
    assert!(
        result["isError"].as_bool().unwrap_or(false),
        "a malformed MAC must be refused, got: {result}"
    );
    assert!(
        text.contains("MAC address"),
        "the refusal must name the reason, got: {text}"
    );

    shutdown.cancel();
    task.abort();
}
