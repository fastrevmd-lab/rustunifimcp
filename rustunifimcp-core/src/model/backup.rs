//! UniFi controller backup resource model.

use crate::error::UnifiError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One entry from the controller's backup list.
///
/// Field set is conservative: `filename` is the only field every known
/// UniFi controller version has reported through `cmd/backup`
/// `list-backups`. `size` and `time` are carried when present but are not
/// required, so a controller version that omits either still parses instead
/// of failing the whole list.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Backup {
    /// The backup's filename on the controller, used as the identifier for
    /// `unifi_backup_action action=download` and `action=validate`.
    pub filename: String,
    /// Size in bytes, when the controller reports it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Creation time, as a Unix timestamp in seconds, when the controller
    /// reports it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<i64>,
}

/// Parses backup entries from the Private v1 `cmd/backup` response.
///
/// # Errors
///
/// Returns [`UnifiError::Malformed`] if the response is not an enveloped
/// `data` array, or an entry does not carry a `filename`.
pub fn parse_backups(val: &serde_json::Value) -> Result<Vec<Backup>, UnifiError> {
    let data = super::unwrap_enveloped_data(val)?;
    data.iter()
        .map(|item| {
            serde_json::from_value(item.clone())
                .map_err(|e| UnifiError::Malformed(format!("backup entry parse failed: {e}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_backups;
    use crate::testing::{DEFAULT_FIXTURE_VERSION, fixture};

    /// Backups must parse from the committed synthetic fixture.
    #[test]
    fn backups_parse_from_the_synthetic_fixture() {
        let raw = fixture(DEFAULT_FIXTURE_VERSION, "backup");
        let backups = parse_backups(&raw).expect("backup parse");
        assert!(
            !backups.is_empty(),
            "the synthetic fixture must carry at least one backup"
        );
        assert_eq!(backups[0].filename, "autobackup_9.1.120_20260928.unf");
        assert_eq!(backups[0].size, Some(4_194_304));
    }

    /// A backup entry missing a controller-reported `size`/`time` must still
    /// parse — those fields are not guaranteed across controller versions.
    #[test]
    fn a_backup_entry_without_size_or_time_still_parses() {
        let raw = serde_json::json!({
            "meta": {"rc": "ok"},
            "data": [{"filename": "autobackup_minimal.unf"}]
        });
        let backups = parse_backups(&raw).expect("backup parse");
        assert_eq!(backups.len(), 1);
        assert_eq!(backups[0].filename, "autobackup_minimal.unf");
        assert_eq!(backups[0].size, None);
        assert_eq!(backups[0].time, None);
    }

    /// A backup entry missing `filename` must be a parse error, not a panic
    /// or a silently absent identifier a caller cannot use to download it.
    #[test]
    fn a_backup_entry_without_a_filename_is_rejected() {
        let raw = serde_json::json!({
            "meta": {"rc": "ok"},
            "data": [{"size": 1024}]
        });
        assert!(parse_backups(&raw).is_err());
    }
}
