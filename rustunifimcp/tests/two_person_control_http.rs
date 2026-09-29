//! Proves the call-time two-person-control refusal fires on the real
//! request path, not only in a unit test of the helper it calls.
//!
//! `main.rs` refuses to *mint* a token combining `unifi_stage_change` and
//! `unifi_approve_change_set` (see `cli_refusal_stderr.rs`), but that check
//! sits at issuance and a token store loaded from a hand-edited file never
//! goes through issuance at all. `UnifiServer::holds_combined_two_person_control_scope`
//! is the check a hand-edited store cannot bypass -- it re-checks at call
//! time in `unifi_stage_change` and `unifi_approve_change_set`. That check
//! already had unit test coverage for its own logic, but nothing proved the
//! two handlers still called it: a mutation removing either call site left
//! every existing test green. This drives a token minted directly through
//! `TokenStoreFile::add` (bypassing the CLI's issuance refusal, exactly the
//! hand-edited-store scenario the call-time check exists for) at a real,
//! authenticated HTTP endpoint, and calls both tools end to end.

use mecmcp_auth::{KnownNames, NoGrant, ScopeSet, TokenStoreFile};
use mecmcp_transport::{LimitsConfig, serve_router, test_client::McpClient};
use rustunifimcp::server::UnifiServer;
use rustunifimcp_core::inventory::ControllerRegistry;
use rustunifimcp_core::tools::TOOL_NAMES;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// An empty controller inventory. The two-person-control check runs before
/// either handler ever looks up a controller, so no controller needs to
/// exist for this test.
fn empty_registry() -> Arc<ControllerRegistry> {
    let mut file = tempfile::NamedTempFile::new().expect("create controllers file");
    file.write_all(br#"{"version":1,"devices":{}}"#)
        .expect("write controllers file");
    file.flush().expect("flush controllers file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))
            .expect("chmod 600");
    }
    Arc::new(ControllerRegistry::load(file.path()).expect("load empty registry"))
}

/// Mint a token whose tool scope is exactly `tools`, writing straight to the
/// token store file. This is deliberately not the CLI: it is the
/// hand-edited-store scenario the call-time check exists to cover, so this
/// test must not route the mint through `main.rs`'s issuance refusal.
fn mint_token(path: &std::path::Path, name: &str, tools: &[&str]) -> String {
    let known = KnownNames {
        devices: None,
        tools: TOOL_NAMES,
    };
    let secret = TokenStoreFile::<NoGrant>::add(
        path,
        name,
        ScopeSet::Wildcard,
        ScopeSet::Allowlist(tools.iter().map(|t| (*t).to_owned()).collect()),
        &known,
    )
    .expect("mint token");
    secret.expose_secret().to_owned()
}

/// Start the real authenticated HTTP router on loopback and return its base
/// URL plus the tasks to keep alive.
async fn start_server(
    token_store: Arc<TokenStoreFile<NoGrant>>,
) -> (String, CancellationToken, tokio::task::JoinHandle<()>) {
    start_server_with_lab_mode(token_store, false).await
}

async fn start_server_with_lab_mode(
    token_store: Arc<TokenStoreFile<NoGrant>>,
    lab_mode: bool,
) -> (String, CancellationToken, tokio::task::JoinHandle<()>) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let registry = empty_registry();
    let coordinator = rustunifimcp::changeset_state::build_coordinator(
        None,
        Duration::from_secs(300),
        lab_mode,
        None,
    )
    .expect("coordinator");
    let handler = UnifiServer::new(registry, lab_mode, coordinator, None).expect("server");

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

/// A token holding both `unifi_stage_change` and `unifi_approve_change_set`
/// must be refused by `unifi_stage_change` at call time, even though nothing
/// at issuance stopped it from existing.
#[tokio::test]
async fn a_token_with_both_scopes_is_refused_calling_stage_change() {
    let tokens_dir = tempfile::tempdir().expect("tempdir");
    let tokens_path = tokens_dir.path().join("tokens.json");
    let bearer = mint_token(
        &tokens_path,
        "both-scopes",
        &["unifi_stage_change", "unifi_approve_change_set"],
    );
    let store = Arc::new(TokenStoreFile::<NoGrant>::load(&tokens_path).expect("load store"));

    let (base_url, shutdown, task) = start_server(store).await;

    let session_id = tokio::task::spawn_blocking({
        let base_url = base_url.clone();
        let bearer = bearer.clone();
        move || {
            McpClient::new(base_url)
                .expect("client")
                .with_bearer(bearer)
                .initialize()
                .expect("initialize")
        }
    })
    .await
    .expect("blocking task");

    let result = tokio::task::spawn_blocking(move || {
        McpClient::new(base_url)
            .expect("client")
            .with_bearer(bearer)
            .tools_call(
                &session_id,
                "unifi_stage_change",
                serde_json::json!({
                    "controller": "home",
                    "change_set_id": "does-not-matter",
                    "mutations": [],
                }),
            )
            .expect("tools/call")
    })
    .await
    .expect("blocking task");

    let text = result["content"][0]["text"].as_str().expect("text content");
    assert!(
        result["isError"].as_bool().unwrap_or(false),
        "a token combining both scopes must be refused, got: {result}"
    );
    assert!(
        text.contains("two-person control")
            && text.contains("unifi_stage_change")
            && text.contains("unifi_approve_change_set"),
        "the refusal must name both scopes, got: {text}"
    );

    shutdown.cancel();
    task.abort();
}

/// MEC-503 F2: under `--lab-mode` a single operator's combined-scope token is
/// deliberately allowed (the change-set waiver records the self-approval), so
/// the call-time two-person refusal must not fire.
#[tokio::test]
async fn lab_mode_does_not_refuse_a_combined_scope_token() {
    let tokens_dir = tempfile::tempdir().expect("tempdir");
    let tokens_path = tokens_dir.path().join("tokens.json");
    let bearer = mint_token(
        &tokens_path,
        "lab-operator",
        &["unifi_stage_change", "unifi_approve_change_set"],
    );
    let store = Arc::new(TokenStoreFile::<NoGrant>::load(&tokens_path).expect("load store"));

    let (base_url, shutdown, task) = start_server_with_lab_mode(store, true).await;

    let session_id = tokio::task::spawn_blocking({
        let base_url = base_url.clone();
        let bearer = bearer.clone();
        move || {
            McpClient::new(base_url)
                .expect("client")
                .with_bearer(bearer)
                .initialize()
                .expect("initialize")
        }
    })
    .await
    .expect("blocking task");

    let result = tokio::task::spawn_blocking(move || {
        McpClient::new(base_url)
            .expect("client")
            .with_bearer(bearer)
            .tools_call(
                &session_id,
                "unifi_stage_change",
                serde_json::json!({
                    "controller": "home",
                    "change_set_id": "does-not-matter",
                    "mutations": [],
                }),
            )
            .expect("tools/call")
    })
    .await
    .expect("blocking task");

    let text = result["content"][0]["text"].as_str().unwrap_or_default();
    assert!(
        !text.contains("two-person control"),
        "lab mode must not apply the call-time two-person refusal, got: {text}"
    );
    assert!(
        !text.is_empty(),
        "the call must still get a real answer: {result}"
    );

    shutdown.cancel();
    task.abort();
}

/// The same refusal must fire for `unifi_approve_change_set`.
#[tokio::test]
async fn a_token_with_both_scopes_is_refused_calling_approve_change_set() {
    let tokens_dir = tempfile::tempdir().expect("tempdir");
    let tokens_path = tokens_dir.path().join("tokens.json");
    let bearer = mint_token(
        &tokens_path,
        "both-scopes",
        &["unifi_stage_change", "unifi_approve_change_set"],
    );
    let store = Arc::new(TokenStoreFile::<NoGrant>::load(&tokens_path).expect("load store"));

    let (base_url, shutdown, task) = start_server(store).await;

    let session_id = tokio::task::spawn_blocking({
        let base_url = base_url.clone();
        let bearer = bearer.clone();
        move || {
            McpClient::new(base_url)
                .expect("client")
                .with_bearer(bearer)
                .initialize()
                .expect("initialize")
        }
    })
    .await
    .expect("blocking task");

    let result = tokio::task::spawn_blocking(move || {
        McpClient::new(base_url)
            .expect("client")
            .with_bearer(bearer)
            .tools_call(
                &session_id,
                "unifi_approve_change_set",
                serde_json::json!({
                    "controller": "home",
                    "change_set_id": "does-not-matter",
                }),
            )
            .expect("tools/call")
    })
    .await
    .expect("blocking task");

    let text = result["content"][0]["text"].as_str().expect("text content");
    assert!(
        result["isError"].as_bool().unwrap_or(false),
        "a token combining both scopes must be refused, got: {result}"
    );
    assert!(
        text.contains("two-person control")
            && text.contains("unifi_stage_change")
            && text.contains("unifi_approve_change_set"),
        "the refusal must name both scopes, got: {text}"
    );

    shutdown.cancel();
    task.abort();
}

/// A token holding only `unifi_stage_change` must reach past the
/// two-person-control check -- it should fail later, on the missing change
/// set, not on the scope combination.
#[tokio::test]
async fn a_token_with_only_stage_scope_is_not_refused_by_two_person_control() {
    let tokens_dir = tempfile::tempdir().expect("tempdir");
    let tokens_path = tokens_dir.path().join("tokens.json");
    let bearer = mint_token(&tokens_path, "stager", &["unifi_stage_change"]);
    let store = Arc::new(TokenStoreFile::<NoGrant>::load(&tokens_path).expect("load store"));

    let (base_url, shutdown, task) = start_server(store).await;

    let session_id = tokio::task::spawn_blocking({
        let base_url = base_url.clone();
        let bearer = bearer.clone();
        move || {
            McpClient::new(base_url)
                .expect("client")
                .with_bearer(bearer)
                .initialize()
                .expect("initialize")
        }
    })
    .await
    .expect("blocking task");

    let result = tokio::task::spawn_blocking(move || {
        McpClient::new(base_url)
            .expect("client")
            .with_bearer(bearer)
            .tools_call(
                &session_id,
                "unifi_stage_change",
                serde_json::json!({
                    "controller": "home",
                    "change_set_id": "does-not-exist",
                    "mutations": [],
                }),
            )
            .expect("tools/call")
    })
    .await
    .expect("blocking task");

    let text = result["content"][0]["text"].as_str().expect("text content");
    assert!(
        !text.contains("two-person control"),
        "a single-scope token must not be refused by two-person control, got: {text}"
    );

    shutdown.cancel();
    task.abort();
}
