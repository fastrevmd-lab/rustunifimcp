//! Server-level contract for the per-kind writable-field allowlist
//! (`check_writable_fields`, `rustunifimcp-core/src/changeset/validate.rs`).
//!
//! `rustunifimcp-core`'s own unit tests exercise the allowlist function in
//! isolation. These drive the real tool router instead, because the point of
//! staging the check *before* the pre-image is captured is that a refused
//! mutation never reaches the controller and never enters a change set a
//! human could approve -- neither is observable from calling the function
//! directly.

use rmcp::{ServiceExt, model::CallToolRequestParams};
use rustunifimcp::changeset_state::build_coordinator;
use rustunifimcp::server::UnifiServer;
use rustunifimcp_core::inventory::ControllerRegistry;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

const CONTROLLER: &str = "home";

fn secure(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// A controller whose endpoint is never reachable and, for every mutation
/// these tests stage, never contacted: the writable-field gate runs before
/// the first controller read, so a passing test here never depends on the
/// network.
fn server() -> UnifiServer {
    // `UnifiClient::new` builds a TLS-capable HTTP client even for a
    // controller that is never contacted, so the process-global crypto
    // provider `main.rs` installs at startup has to be installed here too.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut key = tempfile::NamedTempFile::new().expect("create api key file");
    key.write_all(b"dummy-api-key\n").expect("write api key");
    key.flush().expect("flush api key");
    secure(key.path());
    // Leak the key file so it outlives the controllers file read below.
    let key_path = key.into_temp_path().keep().expect("persist api key file");

    let mut controllers = tempfile::NamedTempFile::new().expect("create controllers file");
    let body = format!(
        r#"{{"version":1,"devices":{{"{CONTROLLER}":{{"endpoint":"https://unifi.example.org","site":"default","api_key_file":"{}","allow_private_api":true}}}}}}"#,
        key_path.display()
    );
    controllers
        .write_all(body.as_bytes())
        .expect("write controllers file");
    controllers.flush().expect("flush controllers file");
    secure(controllers.path());

    let registry =
        Arc::new(ControllerRegistry::load(controllers.path()).expect("load controllers"));
    let coordinator =
        build_coordinator(None, Duration::from_secs(300), true, None).expect("coordinator");
    UnifiServer::new(registry, true, coordinator, None, None).expect("server")
}

/// Drive one tool call over an in-process transport, the way a real MCP
/// client would. `Ok` carries the parsed JSON envelope; `Err` carries the
/// tool's error text.
async fn call(
    handler: UnifiServer,
    tool: &str,
    arguments: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        handler
            .serve(server_transport)
            .await
            .expect("server initialization")
            .waiting()
            .await
    });
    let client = ().serve(client_transport).await.expect("client initialization");
    let result = client
        .call_tool(
            CallToolRequestParams::new(tool.to_owned())
                .with_arguments(serde_json::from_value(arguments).expect("arguments")),
        )
        .await;
    client.cancel().await.expect("client shutdown");
    server_task.abort();

    let result = result.map_err(|error| error.to_string())?;
    let text = result.content[0]
        .as_text()
        .expect("text result")
        .text
        .clone();
    if result.is_error == Some(true) {
        return Err(text);
    }
    Ok(serde_json::from_str(&text).expect("JSON envelope"))
}

async fn create_change_set(handler: UnifiServer) -> String {
    let created = call(
        handler,
        "unifi_create_change_set",
        serde_json::json!({"controller": CONTROLLER, "description": "test"}),
    )
    .await
    .expect("create");
    created["change_set_id"]
        .as_str()
        .expect("change_set_id")
        .to_owned()
}

/// `device` is served from the Integration API and has no verified write
/// route -- `client.rs` refuses `kind == "device"` at apply, and
/// `check_writable_fields` is what closes the same gap at staging, before a
/// change set exists for a human to approve.
#[tokio::test]
async fn staging_a_read_only_kind_is_refused_and_persists_nothing() {
    let handler = server();
    let id = create_change_set(handler.clone()).await;

    let refused = call(
        handler.clone(),
        "unifi_stage_change",
        serde_json::json!({
            "controller": CONTROLLER,
            "change_set_id": id,
            "mutations": [
                {"operation": "update", "kind": "device", "id": "abc123",
                 "body": {"name": "renamed-ap"}}
            ]
        }),
    )
    .await;
    let error = refused.expect_err("a device write has no verified route");
    assert!(error.contains("device"), "{error}");

    // The change set was never staged into, so it must still be exactly the
    // unpersisted draft `unifi_create_change_set` handed back -- not a
    // change set the coordinator ever stored.
    let fetched = call(
        handler,
        "unifi_get_change_set",
        serde_json::json!({"controller": CONTROLLER, "change_set_id": id}),
    )
    .await
    .expect("get");
    assert_eq!(
        fetched["state"], "draft",
        "a refused first stage must leave the change set an unpersisted draft, got: {fetched}"
    );
    assert_eq!(fetched["mutation_count"], 0);
}

/// Controller-managed identity fields must never be settable through a
/// staged body, for any kind -- a body naming `_id` is trying to reassign
/// identity, not configure the resource.
#[tokio::test]
async fn staging_a_controller_managed_id_field_is_refused_and_persists_nothing() {
    let handler = server();
    let id = create_change_set(handler.clone()).await;

    let refused = call(
        handler.clone(),
        "unifi_stage_change",
        serde_json::json!({
            "controller": CONTROLLER,
            "change_set_id": id,
            "mutations": [
                {"operation": "update", "kind": "network", "id": "aaaaaaaaaaaaaaaaaaaaaaaa",
                 "body": {"name": "corp", "_id": "attacker-chosen"}}
            ]
        }),
    )
    .await;
    let error = refused.expect_err("_id must never be settable through a staged body");
    assert!(error.contains("_id"), "{error}");

    let fetched = call(
        handler,
        "unifi_get_change_set",
        serde_json::json!({"controller": CONTROLLER, "change_set_id": id}),
    )
    .await
    .expect("get");
    assert_eq!(fetched["state"], "draft");
    assert_eq!(fetched["mutation_count"], 0);
}
