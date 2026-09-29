//! Operational actions.
//!
//! These are commands, not configuration, so they do not go through change
//! control. Each is individually scoped and audited, and both are in
//! [`crate::tools::WRITE_TOOLS`] -- a wildcard token reaches neither of them.
//!
//! Restoring a controller backup overwrites the entire configuration, which is
//! a larger blast radius than any change set this server will ever carry, so
//! it is a change-set operation instead. See `tools::changeset`.
//!
//! Only the actions with a confirmed command spelling from the controller are
//! advertised here. `adopt`, `upgrade`, `port_action`, `authorize`, and
//! `limit_bandwidth` are deliberately absent: the controller returns
//! `{"meta":{"rc":"ok"}}` for commands that do not exist (it validates the
//! device or client, not the command), so a guessed spelling would look like
//! success. See `docs/MIGRATING-FROM-UNIFI-MCP.md` for the refusal-over-guessing
//! rationale, and `docs/PARITY-AUDIT.md` for what would confirm each spelling.
//! Backup actions (trigger/list/download/validate) and the speed test are
//! absent for the same reason -- no endpoint spelling has been verified from a
//! live controller.

use schemars::JsonSchema;
use serde::Deserialize;

/// What to do to an adopted device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DeviceAction {
    /// Reboot the device.
    Restart,
    /// Flash the locate LED. This is self-reverting — the LED will turn off
    /// automatically after a short time.
    Locate,
}

/// Arguments to `unifi_device_action`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceActionArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// Device MAC address.
    pub device: String,
    /// What to do.
    pub action: DeviceAction,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
}

/// Characters permitted in a caller-supplied site identifier.
///
/// UniFi site ids are opaque slugs (`default`, or a short generated id) with
/// no meaningful characters outside this set. `device_action` and
/// `client_action` build their request path with this value, so this check
/// is a second, independent layer of defence in front of
/// `mecmcp_openapi::expand_path`'s traversal check at the HTTP layer: a
/// caller cannot steer either request onto a different path or site even if
/// a future refactor ever drops the `expand_path` routing.
///
/// # Errors
///
/// Returns [`crate::error::UnifiError::Malformed`] if `site` is `Some` and
/// contains anything other than ASCII alphanumerics, `-`, or `_`, or is
/// empty or longer than 64 bytes.
fn validate_site(site: &Option<String>) -> Result<(), crate::error::UnifiError> {
    if let Some(site) = site {
        let is_valid = !site.is_empty()
            && site.len() <= 64
            && site
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !is_valid {
            return Err(crate::error::UnifiError::Malformed(format!(
                "site {site:?} is not a valid site identifier"
            )));
        }
    }
    Ok(())
}

impl DeviceActionArgs {
    /// Check the cross-field invariants `serde` cannot express.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::UnifiError::Malformed`] if `site` is not a
    /// valid site identifier.
    pub fn validate(&self) -> Result<(), crate::error::UnifiError> {
        validate_site(&self.site)
    }
}

/// What to do to a connected client/station.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ClientAction {
    /// Block the client from the network.
    Block,
    /// Unblock a previously blocked client.
    Unblock,
    /// Disconnect and force the client to reconnect.
    Reconnect,
}

/// Arguments to `unifi_client_action`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientActionArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// Client MAC address.
    pub client: String,
    /// What to do.
    pub action: ClientAction,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
}

impl ClientActionArgs {
    /// Check the cross-field invariants `serde` cannot express.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::UnifiError::Malformed`] if `site` is not a
    /// valid site identifier.
    pub fn validate(&self) -> Result<(), crate::error::UnifiError> {
        validate_site(&self.site)
    }
}

/// Execute an operational action on a device.
///
/// Wired actions: `restart`, `locate`. The controller validates devices but
/// not commands — a misspelled command returns `rc: "ok"`, so command strings
/// are closed and validated here.
///
/// # Errors
///
/// Returns [`crate::error::UnifiError::Malformed`] if `site` is not a valid
/// site identifier.
pub async fn device_action(
    args: DeviceActionArgs,
    client: &crate::client::UnifiClient,
) -> Result<serde_json::Value, crate::error::UnifiError> {
    args.validate()?;

    let site = args
        .site
        .as_deref()
        .unwrap_or_else(|| client.default_site());

    // Map enum to controller command string. Command spellings are closed —
    // the controller returns `rc: "ok"` for garbage commands, so validation
    // happens here.
    let cmd = match args.action {
        DeviceAction::Restart => "restart",
        DeviceAction::Locate => "set-locate",
    };

    let body = serde_json::json!({
        "cmd": cmd,
        "mac": args.device
    });

    client
        .post(
            crate::ApiSurface::PrivateV1,
            "/proxy/network/api/s/{site}/cmd/devmgr",
            &[("site", site)],
            &[],
            &body,
        )
        .await
}

/// Execute an operational action on a client/station.
///
/// Wired actions: `block`, `unblock`, `reconnect`. The controller validates
/// clients but not commands, so command strings are closed and validated here.
///
/// # Errors
///
/// Returns [`crate::error::UnifiError::Malformed`] if `site` is not a valid
/// site identifier.
pub async fn client_action(
    args: ClientActionArgs,
    client: &crate::client::UnifiClient,
) -> Result<serde_json::Value, crate::error::UnifiError> {
    args.validate()?;

    let site = args
        .site
        .as_deref()
        .unwrap_or_else(|| client.default_site());

    // Map enum to controller command string. Conservative: only wire what we
    // have evidence for.
    let cmd = match args.action {
        ClientAction::Block => "block-sta",
        ClientAction::Unblock => "unblock-sta",
        ClientAction::Reconnect => "kick-sta",
    };

    let body = serde_json::json!({
        "cmd": cmd,
        "mac": args.client
    });

    client
        .post(
            crate::ApiSurface::PrivateV1,
            "/proxy/network/api/s/{site}/cmd/stamgr",
            &[("site", site)],
            &[],
            &body,
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::{ClientAction, DeviceAction, DeviceActionArgs};

    #[test]
    fn device_actions_parse_from_their_documented_spellings() {
        for (raw, expected) in [
            ("restart", DeviceAction::Restart),
            ("locate", DeviceAction::Locate),
        ] {
            let json = format!(r#""{raw}""#);
            let parsed: DeviceAction =
                serde_json::from_str(&json).unwrap_or_else(|e| panic!("{raw}: {e}"));
            assert_eq!(parsed, expected);
        }
    }

    /// An action the server does not implement must be a parse error, not a
    /// request that reaches the controller as an unrecognised command. This
    /// also covers the sub-actions removed from the advertised catalog
    /// (`adopt`, `upgrade`, `port_action`) — no command spelling for any of
    /// them has been verified from a live controller, so they must not parse.
    #[test]
    fn an_unadvertised_device_action_is_refused() {
        for raw in ["factory_reset", "adopt", "upgrade", "port_action"] {
            let json = format!(r#""{raw}""#);
            let parsed: Result<DeviceAction, _> = serde_json::from_str(&json);
            assert!(parsed.is_err(), "{raw} must not parse");
        }
    }

    #[test]
    fn client_actions_parse_from_their_documented_spellings() {
        for raw in ["block", "unblock", "reconnect"] {
            let json = format!(r#""{raw}""#);
            let parsed: Result<ClientAction, _> = serde_json::from_str(&json);
            assert!(parsed.is_ok(), "{raw} must parse");
        }
    }

    /// `authorize` and `limit_bandwidth` were removed from the advertised
    /// catalog alongside the device sub-actions above — same reason, no
    /// confirmed command spelling.
    #[test]
    fn an_unadvertised_client_action_is_refused() {
        for raw in ["authorize", "limit_bandwidth"] {
            let json = format!(r#""{raw}""#);
            let parsed: Result<ClientAction, _> = serde_json::from_str(&json);
            assert!(parsed.is_err(), "{raw} must not parse");
        }
    }

    /// `device_action` and `client_action` used to build their request path
    /// with a raw `format!`, bypassing the traversal check every other
    /// request path gets from `mecmcp_openapi::expand_path` (see
    /// `client.rs`'s `a_traversing_site_id_is_rejected_not_sanitised`). A
    /// `site` such as `../../v2/api/site/default` would have reached the
    /// controller unvalidated, redirecting the call onto a different
    /// site/API path than the one it was authorized against.
    ///
    /// The request path is now built from the same `{site}` template and
    /// `expand_path` as every other request, but that alone is not what this
    /// test proves: calling `expand_path` on a copied template literal, as an
    /// earlier version of this test did, still passes even if `device_action`
    /// or `client_action` reverts to a raw `format!`, because the copy and
    /// the production code can drift apart silently. This test instead
    /// drives the real entry point every caller of these tools goes through
    /// -- `DeviceActionArgs::validate` / `ClientActionArgs::validate`, called
    /// before either function touches the client -- so it fails the moment
    /// that path-rejection is missing, regardless of how the request path
    /// happens to be built downstream.
    #[test]
    fn a_traversing_site_is_rejected_by_device_and_client_action_validation() {
        use super::ClientActionArgs;

        let device_args = DeviceActionArgs {
            controller: "home".to_owned(),
            device: "aa:bb:cc:dd:ee:ff".to_owned(),
            action: DeviceAction::Restart,
            site: Some("../../v2/api/site/default".to_owned()),
        };
        assert!(
            device_args.validate().is_err(),
            "a traversing site must be rejected by DeviceActionArgs::validate"
        );

        let client_args = ClientActionArgs {
            controller: "home".to_owned(),
            client: "aa:bb:cc:dd:ee:ff".to_owned(),
            action: ClientAction::Block,
            site: Some("../../v2/api/site/default".to_owned()),
        };
        assert!(
            client_args.validate().is_err(),
            "a traversing site must be rejected by ClientActionArgs::validate"
        );
    }

    /// A site with extra path segments -- not a `../` traversal, but still an
    /// attempt to steer the request onto a different path than the template
    /// names -- must be rejected the same way, again through the real
    /// `validate()` entry point (see the comment above).
    #[test]
    fn a_site_with_extra_path_segments_is_rejected_by_device_and_client_action_validation() {
        use super::ClientActionArgs;

        let device_args = DeviceActionArgs {
            controller: "home".to_owned(),
            device: "aa:bb:cc:dd:ee:ff".to_owned(),
            action: DeviceAction::Restart,
            site: Some("default/extra".to_owned()),
        };
        assert!(
            device_args.validate().is_err(),
            "extra path segments in site must be rejected by DeviceActionArgs::validate"
        );

        let client_args = ClientActionArgs {
            controller: "home".to_owned(),
            client: "aa:bb:cc:dd:ee:ff".to_owned(),
            action: ClientAction::Block,
            site: Some("default/extra".to_owned()),
        };
        assert!(
            client_args.validate().is_err(),
            "extra path segments in site must be rejected by ClientActionArgs::validate"
        );
    }

    /// A well-formed site must still be accepted -- the new validation must
    /// not be so strict that it refuses ordinary UniFi site identifiers.
    #[test]
    fn an_ordinary_site_is_accepted_by_device_and_client_action_validation() {
        use super::ClientActionArgs;

        let device_args = DeviceActionArgs {
            controller: "home".to_owned(),
            device: "aa:bb:cc:dd:ee:ff".to_owned(),
            action: DeviceAction::Restart,
            site: Some("default".to_owned()),
        };
        assert!(device_args.validate().is_ok());

        let client_args = ClientActionArgs {
            controller: "home".to_owned(),
            client: "aa:bb:cc:dd:ee:ff".to_owned(),
            action: ClientAction::Block,
            site: Some("my-site_01".to_owned()),
        };
        assert!(client_args.validate().is_ok());
    }
}
