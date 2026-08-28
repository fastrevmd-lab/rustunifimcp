//! Administration tools — inventory listing, server status, and add-controller.

use crate::client::UnifiClient;
use crate::error::UnifiError;
use crate::inventory::{Controller, ControllerRegistry};
use crate::tools::{TOOL_NAMES, WRITE_TOOLS};
use serde_json::{Value, json};

/// Build a redacted view of one controller for list_controllers.
///
/// The view names the endpoint, site, and surface posture, but never discloses
/// where the credential lives. Naming `api_key_file`'s path tells a caller
/// exactly which file to attack.
fn redacted_controller_view(name: &str, controller: &Controller) -> Value {
    json!({
        "name": name,
        "endpoint": controller.endpoint,
        "site": controller.site,
        "allow_private_api": controller.allow_private_api,
        "allow_cloud": controller.allow_cloud,
        "reachable": "unknown"
    })
}

/// List all controllers without disclosing credential locations.
///
/// Returns name, endpoint, site, and surface posture for each controller.
/// Deliberately excludes `api_key_file` and `api_key_env` to avoid telling a
/// caller where to look for credentials.
///
/// # Errors
///
/// Returns [`UnifiError::Inventory`] if the registry cannot be accessed.
pub async fn unifi_list_controllers(registry: &ControllerRegistry) -> Result<Value, UnifiError> {
    let names = registry.names();
    let mut controllers = Vec::new();

    for name in &names {
        let controller = registry.get(name)?;
        controllers.push(redacted_controller_view(name, &controller));
    }

    Ok(json!({
        "controllers": controllers,
        "count": controllers.len()
    }))
}

/// Report server status and per-controller reachability.
///
/// This is the tool an operator calls first, so it answers "is this working and
/// what is it talking to" in one response: server version, the pinned `mecmcp`
/// version, transport, whether lab mode is on, tool count, and per-controller
/// reachability with the controller version each reports.
///
/// A controller that is unreachable shows as unreachable with the reason, not
/// silently omitted.
///
/// # Errors
///
/// Returns [`UnifiError::Inventory`] if the registry cannot be accessed.
pub async fn unifimcp_status(
    registry: &ControllerRegistry,
    lab_mode: bool,
) -> Result<Value, UnifiError> {
    let names = registry.names();
    let mut controller_status = Vec::new();

    for name in &names {
        let controller = match registry.get(name) {
            Ok(c) => c,
            Err(e) => {
                controller_status.push(json!({
                    "name": name,
                    "reachable": false,
                    "error": e.to_string()
                }));
                continue;
            }
        };

        let client = match UnifiClient::new(controller) {
            Ok(c) => c,
            Err(e) => {
                controller_status.push(json!({
                    "name": name,
                    "reachable": false,
                    "error": e.to_string()
                }));
                continue;
            }
        };

        match client.controller_version().await {
            Ok(version) => {
                controller_status.push(json!({
                    "name": name,
                    "reachable": true,
                    "controller_version": version
                }));
            }
            Err(e) => {
                controller_status.push(json!({
                    "name": name,
                    "reachable": false,
                    "error": e.to_string()
                }));
            }
        }
    }

    Ok(json!({
        "server_version": env!("CARGO_PKG_VERSION"),
        "mecmcp_version": "0.20.0",
        "lab_mode": lab_mode,
        "tool_count": TOOL_NAMES.len(),
        "write_tool_count": WRITE_TOOLS.len(),
        "controllers": controller_status,
        "controller_count": names.len()
    }))
}

/// Attempt to add a controller to the inventory.
///
/// This tool deliberately fails under the production systemd unit, which runs
/// with `ProtectSystem=strict` and `/etc/unifimcp` read-only to the service.
/// The fleet's documented preference is a narrow sandbox over a working
/// `add_*` tool.
///
/// # Errors
///
/// Always returns [`UnifiError::Malformed`] naming the hand-edit path:
/// edit `/etc/unifimcp/controllers.json` as root, then
/// `systemctl kill -s HUP rustunifimcp.service`.
pub async fn unifi_add_controller(
    _name: &str,
    _endpoint: &str,
    _site: &str,
    _api_key_env: Option<&str>,
    _api_key_file: Option<&str>,
) -> Result<Value, UnifiError> {
    Err(UnifiError::Malformed(
        "add_controller is not supported; the service runs with a read-only /etc/unifimcp. \
         Edit /etc/unifimcp/controllers.json as root, then \
         systemctl kill -s HUP rustunifimcp.service"
            .to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::redacted_controller_view;
    use crate::inventory::Controller;

    /// list_controllers must not disclose credential locations. Naming the file
    /// path tells a caller exactly which file to attack.
    #[test]
    fn the_controller_view_hides_credential_locations() {
        let controller: Controller = serde_json::from_str(
            r#"{
                "endpoint": "https://unifi.example.org",
                "site": "default",
                "api_key_file": "/etc/unifimcp/api.key"
            }"#,
        )
        .expect("parses");

        let view = redacted_controller_view("home", &controller);
        let rendered = serde_json::to_string(&view).expect("serializes");

        assert!(!rendered.contains("/etc/unifimcp/api.key"), "{rendered}");
        assert!(!rendered.contains("api_key_file"), "{rendered}");
        assert!(rendered.contains("unifi.example.org"), "{rendered}");
    }

    /// The view must say whether private surfaces are reachable, because that
    /// is what a caller needs to know before choosing a resource kind.
    #[test]
    fn the_controller_view_states_its_surface_posture() {
        let controller: Controller = serde_json::from_str(
            r#"{
                "endpoint": "https://unifi.example.org",
                "site": "default",
                "api_key_env": "K",
                "allow_private_api": true
            }"#,
        )
        .expect("parses");

        let view = redacted_controller_view("home", &controller);
        let rendered = serde_json::to_string(&view).expect("serializes");
        assert!(rendered.contains("allow_private_api"), "{rendered}");
    }
}
