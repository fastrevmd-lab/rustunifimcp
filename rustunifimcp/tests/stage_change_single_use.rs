//! `unifi_stage_change` can only be staged into once per `change_set_id`.
//!
//! mecmcp-changeset v0.25.0 (MEC-525) fixes a change set's owner, device and
//! plan digest at creation: `update_change_set_from` now refuses any write
//! that would change the digest, which a second stage always would. This
//! drives the real tool router to pin that a second stage is refused with a
//! clear instruction, before anything is sent to a (never-reachable)
//! controller -- not left to fail confusingly inside the coordinator.

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

/// A controller whose endpoint is never reachable and, for the `create`
/// mutation this test stages, never contacted: `create` has no pre-image to
/// fetch, so a passing test here never depends on the network.
fn server() -> UnifiServer {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut key = tempfile::NamedTempFile::new().expect("create api key file");
    key.write_all(b"dummy-api-key\n").expect("write api key");
    key.flush().expect("flush api key");
    secure(key.path());
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
        build_coordinator(None, Duration::from_secs(300), true, None, None).expect("coordinator");
    UnifiServer::new(
        registry,
        true,
        coordinator,
        None,
        mecmcp_audit::DirectCommitPolicy::new(false),
    )
    .expect("server")
}

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

fn create_policy_mutation(name: &str) -> serde_json::Value {
    serde_json::json!({
        "controller": CONTROLLER,
        "mutations": [
            {"operation": "create", "kind": "firewall_policy", "body": {"name": name}}
        ]
    })
}

/// The first stage on a draft succeeds and turns it into a real change set.
#[tokio::test]
async fn first_stage_on_a_draft_succeeds() {
    let handler = server();
    let id = create_change_set(handler.clone()).await;

    let mut args = create_policy_mutation("a");
    args["change_set_id"] = serde_json::Value::String(id.clone());
    let staged = call(handler.clone(), "unifi_stage_change", args)
        .await
        .expect("first stage must succeed");
    assert_eq!(staged["staged_count"], 1);

    let fetched = call(
        handler,
        "unifi_get_change_set",
        serde_json::json!({"controller": CONTROLLER, "change_set_id": id}),
    )
    .await
    .expect("get");
    assert_eq!(fetched["state"], "planned");
    assert_eq!(fetched["mutation_count"], 1);
}

/// A second stage into the same change set must be refused up front, with an
/// error naming the fix (cancel and recreate) -- not the coordinator's
/// "owner, device and plan digest are fixed at creation" error, which never
/// tells the caller what to do about it.
#[tokio::test]
async fn second_stage_into_an_existing_change_set_is_refused() {
    let handler = server();
    let id = create_change_set(handler.clone()).await;

    let mut first = create_policy_mutation("a");
    first["change_set_id"] = serde_json::Value::String(id.clone());
    call(handler.clone(), "unifi_stage_change", first)
        .await
        .expect("first stage must succeed");

    let mut second = create_policy_mutation("b");
    second["change_set_id"] = serde_json::Value::String(id.clone());
    let refused = call(handler.clone(), "unifi_stage_change", second)
        .await
        .expect_err("a second stage must be refused, not silently re-plan the change set");
    assert!(
        refused.contains("staged into a second time") && refused.contains("create a new"),
        "error must tell the caller to create a new change set, got: {refused}"
    );

    // The first stage's plan must be untouched by the refused second call.
    let fetched = call(
        handler,
        "unifi_get_change_set",
        serde_json::json!({"controller": CONTROLLER, "change_set_id": id}),
    )
    .await
    .expect("get");
    assert_eq!(fetched["state"], "planned");
    assert_eq!(
        fetched["mutation_count"], 1,
        "the refused second stage must not have merged into the stored plan"
    );
}
