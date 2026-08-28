//! Client-side validation for staged mutations.
//!
//! UniFi has no server-side dry-run validation, so referential integrity and
//! schema constraints must be checked locally before apply.

use crate::error::UnifiError;
use serde_json::Value;

use super::preimage::{Preimage, StagedMutation};

/// Validate that all staged mutations are covered by the pre-image.
///
/// # Errors
///
/// Returns an error if any mutation references a resource not in the pre-image.
pub fn validate_locally(
    preimage: &Preimage,
    mutations: &[StagedMutation],
) -> Result<(), UnifiError> {
    for mutation in mutations {
        if !preimage.covers(mutation) {
            return Err(UnifiError::Malformed(format!(
                "mutation {} references a resource not in the pre-image",
                mutation.preview()
            )));
        }
    }
    Ok(())
}

/// Check referential integrity for staged mutations.
///
/// # Errors
///
/// Returns an error if any mutation references a zone or resource that does
/// not exist in the provided data.
pub fn check_references(data: &Value, mutations: &[StagedMutation]) -> Result<(), UnifiError> {
    // Extract zone IDs from the data
    let zone_ids: Vec<String> = if let Some(zones) = data.as_array() {
        zones
            .iter()
            .filter_map(|zone| zone.get("_id").and_then(|id| id.as_str()).map(String::from))
            .collect()
    } else {
        Vec::new()
    };

    for mutation in mutations {
        // Check if this mutation references a zone
        let body = match mutation {
            StagedMutation::Create { body, .. } | StagedMutation::Update { body, .. } => body,
            StagedMutation::Delete { .. } => continue,
        };

        // Check if the body references a zone_id
        if let Some(source) = body.get("source")
            && let Some(zone_id) = source.get("zone_id").and_then(|id| id.as_str())
            && !zone_ids.contains(&zone_id.to_owned())
        {
            return Err(UnifiError::Malformed(format!(
                "mutation references non-existent zone '{zone_id}'"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::testing::{fixture, DEFAULT_FIXTURE_VERSION};

    /// Referential checks are local because no controller-side dry run exists.
    #[test]
    fn a_policy_referencing_an_absent_zone_is_refused() {
        let zones = fixture(DEFAULT_FIXTURE_VERSION, "zones");
        let staged = super::StagedMutation::create(
            "firewall_policy",
            serde_json::json!({ "source": { "zone_id": "does-not-exist" } }),
        );
        assert!(super::check_references(&zones, &[staged]).is_err());
    }
}
