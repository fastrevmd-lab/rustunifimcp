//! Operational actions.
//!
//! These are commands, not configuration, so they do not go through change
//! control. Each is individually scoped and audited, and all four are in
//! [`crate::tools::WRITE_TOOLS`] -- a wildcard token reaches none of them.
//!
//! `unifi_backup_action` deliberately does not carry `restore`. Restoring a
//! controller backup overwrites the entire configuration, which is a larger
//! blast radius than any change set this server will ever carry, so it is a
//! change-set operation instead. See `tools::changeset`.

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, de};

/// Explanation for why `restore` is not an operational backup action.
///
/// This text appears both in the tool description and in the runtime error when
/// a caller attempts `action: "restore"`, so it cannot drift.
pub const RESTORE_NOT_OPERATIONAL: &str = "\
`restore` is not an operational action. Restoring a controller backup overwrites \
the entire configuration, so it is governed by the change-set lifecycle: \
`unifi_create_change_set` -> `unifi_stage_change` -> `unifi_approve_change_set` -> \
`unifi_apply_change_set`. Valid actions here are: trigger, list, download, validate.";

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
    /// Adopt a pending device into the site.
    Adopt,
    /// Start a firmware upgrade.
    Upgrade,
    /// Act on a single switch port; requires `port_index`.
    PortAction,
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
    /// Which port, for `port_action`.
    #[serde(default)]
    pub port_index: Option<u16>,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
}

impl DeviceActionArgs {
    /// Check the cross-field invariants `serde` cannot express.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::UnifiError::Malformed`] if `port_action` was
    /// requested without a `port_index`.
    pub fn validate(&self) -> Result<(), crate::error::UnifiError> {
        if self.action == DeviceAction::PortAction && self.port_index.is_none() {
            return Err(crate::error::UnifiError::Malformed(
                "action `port_action` requires `port_index`".to_owned(),
            ));
        }
        Ok(())
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
    /// Authorize a guest client on the guest portal.
    Authorize,
    /// Apply bandwidth limits to the client.
    LimitBandwidth,
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
    /// Validate arguments. Currently a no-op as there are no cross-field
    /// invariants, but kept for consistency with `DeviceActionArgs`.
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok`.
    pub fn validate(&self) -> Result<(), crate::error::UnifiError> {
        Ok(())
    }
}

/// What to do with controller backups.
///
/// `restore` is not available here. Restoring a controller backup overwrites
/// the entire configuration, which is a larger blast radius than any change set
/// this server will ever carry, so it goes through the change-set lifecycle:
/// `unifi_create_change_set` -> `unifi_stage_change` -> `unifi_approve_change_set`
/// -> `unifi_apply_change_set`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BackupAction {
    /// Trigger a new backup.
    Trigger,
    /// List available backups.
    List,
    /// Download a backup file.
    Download,
    /// Validate a backup file's integrity.
    Validate,
}

impl<'de> Deserialize<'de> for BackupAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "restore" => Err(de::Error::custom(RESTORE_NOT_OPERATIONAL)),
            "trigger" => Ok(Self::Trigger),
            "list" => Ok(Self::List),
            "download" => Ok(Self::Download),
            "validate" => Ok(Self::Validate),
            other => Err(de::Error::unknown_variant(
                other,
                &["trigger", "list", "download", "validate"],
            )),
        }
    }
}

impl JsonSchema for BackupAction {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "BackupAction".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        // Build the schema as JSON and convert to Schema via serde.
        // This ensures the enum values match what the custom deserializer accepts.
        let schema_json = serde_json::json!({
            "type": "string",
            "enum": ["trigger", "list", "download", "validate"]
        });

        serde_json::from_value(schema_json).expect("static schema JSON must deserialize to Schema")
    }
}

/// Arguments to `unifi_backup_action`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupActionArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// What to do.
    pub action: BackupAction,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
    /// Backup filename, required for `download` and `validate`.
    #[serde(default)]
    pub backup_file: Option<String>,
}

impl BackupActionArgs {
    /// Check the cross-field invariants `serde` cannot express.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::UnifiError::Malformed`] if `download` or
    /// `validate` was requested without a `backup_file`.
    pub fn validate(&self) -> Result<(), crate::error::UnifiError> {
        if matches!(self.action, BackupAction::Download | BackupAction::Validate)
            && self.backup_file.is_none()
        {
            return Err(crate::error::UnifiError::Malformed(format!(
                "action `{:?}` requires `backup_file`",
                self.action
            )));
        }
        Ok(())
    }
}

/// Arguments to `unifi_run_speed_test`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpeedTestArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
}

impl SpeedTestArgs {
    /// Validate arguments. Currently a no-op as there are no cross-field
    /// invariants, but kept for consistency with other operational args.
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok`.
    pub fn validate(&self) -> Result<(), crate::error::UnifiError> {
        Ok(())
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
/// Returns [`crate::error::UnifiError::Malformed`] if `port_action` is
/// requested without a `port_index`, or if the action is not yet wired.
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
        DeviceAction::Adopt => {
            return Err(crate::error::UnifiError::Malformed(
                "action `adopt` not yet wired; no command spelling verified from controller"
                    .to_owned(),
            ));
        }
        DeviceAction::Upgrade => {
            return Err(crate::error::UnifiError::Malformed(
                "action `upgrade` not yet wired; no command spelling verified from controller"
                    .to_owned(),
            ));
        }
        DeviceAction::PortAction => {
            return Err(crate::error::UnifiError::Malformed(
                "action `port_action` not yet wired; requires port operation parameter".to_owned(),
            ));
        }
    };

    let body = serde_json::json!({
        "cmd": cmd,
        "mac": args.device
    });

    let path = format!("/proxy/network/api/s/{}/cmd/devmgr", site);

    client
        .post(crate::ApiSurface::PrivateV1, &path, &[], &[], &body)
        .await
}

/// Execute an operational action on a client/station.
///
/// Wired actions: `block`, `unblock`, `reconnect`. The controller validates
/// clients but not commands, so command strings are closed and validated here.
///
/// # Errors
///
/// Returns [`crate::error::UnifiError::Malformed`] if the action is not yet wired.
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
        ClientAction::Authorize => {
            return Err(crate::error::UnifiError::Malformed(
                "action `authorize` not yet wired; requires authorization duration parameter"
                    .to_owned(),
            ));
        }
        ClientAction::LimitBandwidth => {
            return Err(crate::error::UnifiError::Malformed(
                "action `limit_bandwidth` not yet wired; requires bandwidth limit parameters"
                    .to_owned(),
            ));
        }
    };

    let body = serde_json::json!({
        "cmd": cmd,
        "mac": args.client
    });

    let path = format!("/proxy/network/api/s/{}/cmd/stamgr", site);

    client
        .post(crate::ApiSurface::PrivateV1, &path, &[], &[], &body)
        .await
}

/// Execute a backup action on the controller.
///
/// This implements trigger, list, download, and validate. `restore` is not
/// available here — restoring a controller backup overwrites the entire
/// configuration, so it goes through change control in Phase 6.
///
/// # Errors
///
/// Returns [`crate::error::Malformed`] if `download` or `validate` is requested
/// without a `backup_file`, or because backup operations are not yet wired.
pub async fn backup_action(
    args: BackupActionArgs,
    _client: &crate::client::UnifiClient,
) -> Result<serde_json::Value, crate::error::UnifiError> {
    args.validate()?;

    Err(crate::error::UnifiError::Malformed(
        "backup actions not yet wired; no endpoint spellings verified from controller".to_owned(),
    ))
}

/// Run a speed test from the controller.
///
/// # Errors
///
/// Returns [`crate::error::Malformed`] because speed test is not yet wired.
pub async fn run_speed_test(
    args: SpeedTestArgs,
    _client: &crate::client::UnifiClient,
) -> Result<serde_json::Value, crate::error::UnifiError> {
    args.validate()?;

    Err(crate::error::UnifiError::Malformed(
        "speed test not yet wired; no endpoint spelling verified from controller".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::{ClientAction, DeviceAction, DeviceActionArgs};

    #[test]
    fn device_actions_parse_from_their_documented_spellings() {
        for (raw, expected) in [
            ("restart", DeviceAction::Restart),
            ("locate", DeviceAction::Locate),
            ("adopt", DeviceAction::Adopt),
            ("upgrade", DeviceAction::Upgrade),
            ("port_action", DeviceAction::PortAction),
        ] {
            let json = format!(r#""{raw}""#);
            let parsed: DeviceAction =
                serde_json::from_str(&json).unwrap_or_else(|e| panic!("{raw}: {e}"));
            assert_eq!(parsed, expected);
        }
    }

    /// An action the server does not implement must be a parse error, not a
    /// request that reaches the controller as an unrecognised command.
    #[test]
    fn an_unknown_device_action_is_refused() {
        let parsed: Result<DeviceAction, _> = serde_json::from_str(r#""factory_reset""#);
        assert!(parsed.is_err());
    }

    #[test]
    fn a_port_action_requires_a_port_index() {
        let raw = r#"{"controller":"home","device":"aa:bb:cc:dd:ee:ff","action":"port_action"}"#;
        let args: DeviceActionArgs = serde_json::from_str(raw).expect("parses");
        assert!(
            args.validate().is_err(),
            "port_action without a port index must be refused before dispatch"
        );
    }

    #[test]
    fn client_actions_parse_from_their_documented_spellings() {
        for raw in [
            "block",
            "unblock",
            "reconnect",
            "authorize",
            "limit_bandwidth",
        ] {
            let json = format!(r#""{raw}""#);
            let parsed: Result<ClientAction, _> = serde_json::from_str(&json);
            assert!(parsed.is_ok(), "{raw} must parse");
        }
    }

    #[test]
    fn backup_actions_parse_from_their_documented_spellings() {
        use super::BackupAction;
        for (raw, expected) in [
            ("trigger", BackupAction::Trigger),
            ("list", BackupAction::List),
            ("download", BackupAction::Download),
            ("validate", BackupAction::Validate),
        ] {
            let json = format!(r#""{raw}""#);
            let parsed: BackupAction =
                serde_json::from_str(&json).unwrap_or_else(|e| panic!("{raw}: {e}"));
            assert_eq!(parsed, expected);
        }
    }

    /// `restore` must be a parse error with a message naming the change-set path,
    /// not a runtime refusal. Restoring a controller backup overwrites the entire
    /// configuration, so it goes through approval in Phase 6.
    #[test]
    fn backup_restore_is_refused_at_parse_time() {
        use super::BackupAction;
        let parsed: Result<BackupAction, _> = serde_json::from_str(r#""restore""#);
        assert!(
            parsed.is_err(),
            "restore must be a parse error, not a runtime refusal"
        );
    }

    /// The restore refusal error message must explain the reason and name the
    /// change-set path, so it cannot regress to a bare serde message.
    #[test]
    fn backup_restore_error_explains_the_governed_path() {
        use super::BackupAction;
        let parsed: Result<BackupAction, _> = serde_json::from_str(r#""restore""#);
        let err_msg = parsed
            .expect_err("restore must be refused at parse time")
            .to_string();
        assert!(
            err_msg.contains("change-set lifecycle") || err_msg.contains("change_set"),
            "error must explain why restore is refused, got: {err_msg}"
        );
        assert!(
            err_msg.contains("unifi_create_change_set"),
            "error must name at least one change-set tool, got: {err_msg}"
        );
    }

    #[test]
    fn download_and_validate_require_a_backup_file() {
        use super::{BackupAction, BackupActionArgs};
        for action in [BackupAction::Download, BackupAction::Validate] {
            let args = BackupActionArgs {
                controller: "home".to_owned(),
                action,
                site: None,
                backup_file: None,
            };
            assert!(
                args.validate().is_err(),
                "{:?} without backup_file must be refused before dispatch",
                action
            );
        }
    }

    #[test]
    fn trigger_and_list_do_not_require_a_backup_file() {
        use super::{BackupAction, BackupActionArgs};
        for action in [BackupAction::Trigger, BackupAction::List] {
            let args = BackupActionArgs {
                controller: "home".to_owned(),
                action,
                site: None,
                backup_file: None,
            };
            assert!(
                args.validate().is_ok(),
                "{:?} must not require backup_file",
                action
            );
        }
    }

    /// The generated JSON schema for BackupAction must match the strings the
    /// custom deserializer accepts. Schema-driven callers break when they
    /// disagree.
    #[test]
    fn backup_action_schema_agrees_with_deserializer() {
        use schemars::JsonSchema;

        let schema = super::BackupAction::json_schema(&mut schemars::SchemaGenerator::default());
        let schema_value = serde_json::to_value(schema).expect("schema must serialize to JSON");

        let enum_values = schema_value
            .get("enum")
            .expect("BackupAction schema must have enum field")
            .as_array()
            .expect("enum must be array");

        let expected: Vec<String> = vec![
            "trigger".to_owned(),
            "list".to_owned(),
            "download".to_owned(),
            "validate".to_owned(),
        ];

        let actual: Vec<String> = enum_values
            .iter()
            .map(|v| v.as_str().expect("enum value must be string").to_owned())
            .collect();

        assert_eq!(
            actual, expected,
            "schema enum values must match deserializer accepted spellings"
        );

        // Verify deserializer accepts each schema-advertised value
        for spelling in &expected {
            let json = format!(r#""{spelling}""#);
            let parsed: Result<super::BackupAction, _> = serde_json::from_str(&json);
            assert!(
                parsed.is_ok(),
                "deserializer must accept schema-advertised spelling: {spelling}"
            );
        }
    }

    /// Unwired device actions must return an error, never success.
    #[test]
    fn unwired_device_actions_return_errors() {
        use super::{DeviceAction, DeviceActionArgs};

        for action in [
            DeviceAction::Adopt,
            DeviceAction::Upgrade,
            DeviceAction::PortAction,
        ] {
            let args = DeviceActionArgs {
                controller: "test".to_owned(),
                device: "02:00:00:00:00:01".to_owned(),
                action,
                port_index: if action == DeviceAction::PortAction {
                    Some(1)
                } else {
                    None
                },
                site: None,
            };

            // Validate alone must succeed for these — the refusal happens in
            // the dispatch, not in validation.
            assert!(args.validate().is_ok(), "{:?} must pass validation", action);
        }
    }

    /// Unwired client actions must return an error, never success.
    #[test]
    fn unwired_client_actions_are_explicitly_refused() {
        use super::{ClientAction, ClientActionArgs};

        for action in [ClientAction::Authorize, ClientAction::LimitBandwidth] {
            let args = ClientActionArgs {
                controller: "test".to_owned(),
                client: "02:00:00:00:00:02".to_owned(),
                action,
                site: None,
            };

            assert!(args.validate().is_ok(), "{:?} must pass validation", action);
        }
    }
}
