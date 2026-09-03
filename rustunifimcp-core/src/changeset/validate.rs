//! Client-side validation for staged mutations.
//!
//! UniFi has no server-side dry-run validation, so referential integrity and
//! schema constraints must be checked locally before apply.

use crate::error::UnifiError;
use serde_json::Value;
use std::collections::BTreeMap;

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

/// The firewall zones a staged mutation is allowed to reference.
///
/// Built from the controller's live zone list, never from the pre-image. A
/// create records no prior state at all, so a pre-image-derived index is empty
/// for exactly the mutations that need checking, and every zone reference in a
/// `firewall_policy` create was reported missing.
#[derive(Debug, Clone, Default)]
pub struct ZoneIndex {
    /// Zone `_id` to zone name.
    by_id: BTreeMap<String, String>,
    /// Zone `external_id` to the `_id` the controller wants instead.
    by_external_id: BTreeMap<String, String>,
}

/// What a zone identifier in a staged body resolves to.
enum ZoneLookup<'index> {
    /// The identifier is a zone `_id` on this controller.
    Known,
    /// The identifier is a zone's `external_id`; the `_id` is carried along
    /// because naming it is the whole fix.
    ExternalId(&'index str),
    /// The identifier is neither.
    Absent,
}

impl ZoneIndex {
    /// Build the index from the controller's firewall zone list.
    ///
    /// # Errors
    ///
    /// Returns [`UnifiError::Malformed`] if the response is not an array of
    /// zone objects each carrying an `_id`. Read that as "the zone list could
    /// not be read", which needs a different operator response from "the zone
    /// is not there" — conflating the two is what made this check unusable.
    pub fn from_zone_list(raw: &Value) -> Result<Self, UnifiError> {
        let items = raw.as_array().ok_or_else(|| {
            UnifiError::Malformed("firewall zone list is not an array".to_owned())
        })?;

        let mut by_id = BTreeMap::new();
        let mut by_external_id = BTreeMap::new();

        for (position, item) in items.iter().enumerate() {
            let id = item
                .get("_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    UnifiError::Malformed(format!(
                        "firewall zone at position {position} has no `_id`"
                    ))
                })?
                .to_owned();

            if let Some(external) = item.get("external_id").and_then(Value::as_str) {
                by_external_id.insert(external.to_owned(), id.clone());
            }

            let name = item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("<unnamed>")
                .to_owned();
            by_id.insert(id, name);
        }

        Ok(Self {
            by_id,
            by_external_id,
        })
    }

    /// How many zones the controller reported.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Whether the controller reported no zones at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Resolve one identifier taken from a staged body.
    fn resolve(&self, identifier: &str) -> ZoneLookup<'_> {
        if self.by_id.contains_key(identifier) {
            return ZoneLookup::Known;
        }
        if let Some(id) = self.by_external_id.get(identifier) {
            return ZoneLookup::ExternalId(id.as_str());
        }
        ZoneLookup::Absent
    }
}

/// The body fields a zone reference can appear under.
const ZONE_REFERENCE_FIELDS: &[&str] = &["source", "destination"];

/// The zone identifiers staged mutations reference, in staging order.
///
/// Empty means no staged body names a zone, so the caller can skip fetching
/// the zone list rather than making a change set that touches no firewall
/// depend on the firewall surface being reachable.
#[must_use]
pub fn referenced_zone_ids(mutations: &[StagedMutation]) -> Vec<String> {
    let mut referenced = Vec::new();

    for mutation in mutations {
        let body = match mutation {
            StagedMutation::Create { body, .. } | StagedMutation::Update { body, .. } => body,
            StagedMutation::Delete { .. } | StagedMutation::Restore { .. } => continue,
        };

        for field in ZONE_REFERENCE_FIELDS {
            if let Some(zone_id) = body
                .get(field)
                .and_then(|side| side.get("zone_id"))
                .and_then(Value::as_str)
                && !referenced.iter().any(|seen| seen == zone_id)
            {
                referenced.push(zone_id.to_owned());
            }
        }
    }

    referenced
}

/// The resource kind whose deletion removes a zone a policy could name.
const ZONE_KIND: &str = "firewall_zone";

/// The zones this change set deletes.
///
/// Apply is a sequence of independent REST calls in staging order, so a zone
/// deleted by the same set is gone by the time a later policy write lands even
/// though the live list still had it when validate read it. The projected state
/// is what a policy has to be checked against, not the pre-change one.
fn zones_deleted_by(mutations: &[StagedMutation]) -> Vec<&str> {
    mutations
        .iter()
        .filter_map(|mutation| match mutation {
            StagedMutation::Delete { kind, id } if kind == ZONE_KIND => Some(id.as_str()),
            _ => None,
        })
        .collect()
}

/// Check referential integrity for staged mutations against a zone index.
///
/// The zone must exist on the controller *and* survive the change set: a set
/// that deletes a zone and writes a policy naming it is internally
/// inconsistent, and validate is the last place to say so.
///
/// # Errors
///
/// Returns [`UnifiError::ReferenceNotFound`] if a staged body names a zone the
/// controller does not have, or one this change set removes. That variant
/// renders on its own, without the "unexpected response shape" prefix a parse
/// failure carries, so the two read differently in a tool result.
pub fn check_references(zones: &ZoneIndex, mutations: &[StagedMutation]) -> Result<(), UnifiError> {
    let deleted = zones_deleted_by(mutations);

    for mutation in mutations {
        let body = match mutation {
            StagedMutation::Create { body, .. } | StagedMutation::Update { body, .. } => body,
            StagedMutation::Delete { .. } | StagedMutation::Restore { .. } => continue,
        };

        for field in ZONE_REFERENCE_FIELDS {
            let Some(zone_id) = body
                .get(field)
                .and_then(|side| side.get("zone_id"))
                .and_then(Value::as_str)
            else {
                continue;
            };

            if deleted.contains(&zone_id) {
                return Err(UnifiError::ReferenceNotFound(format!(
                    "staged {} names {field}.zone_id '{zone_id}', which this change set also \
                     deletes",
                    mutation.preview()
                )));
            }

            match zones.resolve(zone_id) {
                ZoneLookup::Known => {}
                ZoneLookup::ExternalId(id) => {
                    return Err(UnifiError::ReferenceNotFound(format!(
                        "staged {} names {field}.zone_id '{zone_id}', which is that zone's \
                         external_id; the controller addresses it by `_id` '{id}'",
                        mutation.preview()
                    )));
                }
                ZoneLookup::Absent => {
                    return Err(UnifiError::ReferenceNotFound(format!(
                        "staged {} names {field}.zone_id '{zone_id}', which is not one of the \
                         {} firewall zones on this controller",
                        mutation.preview(),
                        zones.len()
                    )));
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ZoneIndex, check_references, referenced_zone_ids};
    use crate::changeset::StagedMutation;
    use serde_json::json;

    /// A zone list as the Private v2 surface returns it: a bare array.
    fn zone_list() -> serde_json::Value {
        json!([
            {
                "_id": "aaaaaaaaaaaaaaaaaaaaaaaa",
                "name": "Internal",
                "default_zone": true,
                "network_ids": ["bbbbbbbbbbbbbbbbbbbbbbbb"],
                "external_id": "11111111-1111-4111-8111-111111111111"
            },
            {
                "_id": "cccccccccccccccccccccccc",
                "name": "DMZ",
                "default_zone": false,
                "network_ids": [],
                "external_id": "22222222-2222-4222-8222-222222222222"
            }
        ])
    }

    fn policy_between(source: &str, destination: &str) -> StagedMutation {
        StagedMutation::create(
            "firewall_policy",
            json!({
                "name": "probe",
                "action": "ALLOW",
                "source": { "zone_id": source, "matching_target": "ZONE" },
                "destination": { "zone_id": destination, "matching_target": "ZONE" }
            }),
        )
    }

    /// Referential checks are local because no controller-side dry run exists.
    #[test]
    fn a_policy_referencing_an_absent_zone_is_refused() {
        let zones = ZoneIndex::from_zone_list(&zone_list()).expect("a well-formed zone list");
        let staged = policy_between("does-not-exist", "cccccccccccccccccccccccc");
        let error = check_references(&zones, &[staged]).expect_err("an absent zone must be caught");
        let rendered = error.to_string();
        assert!(rendered.contains("does-not-exist"), "{rendered}");
        assert!(
            rendered.contains('2'),
            "the count of known zones: {rendered}"
        );
    }

    /// The bug this replaces: a policy naming zones the controller listed
    /// moments earlier was refused, because the check ran against the
    /// pre-image, which is empty for a create.
    #[test]
    fn a_policy_referencing_listed_zones_passes() {
        let zones = ZoneIndex::from_zone_list(&zone_list()).expect("a well-formed zone list");
        let staged = policy_between("aaaaaaaaaaaaaaaaaaaaaaaa", "cccccccccccccccccccccccc");
        assert!(
            check_references(&zones, &[staged]).is_ok(),
            "both zones are in the list the controller returned"
        );
    }

    /// A zone list the caller can read hands out two identifiers. Naming the
    /// wrong one has to say so, not report the zone missing.
    #[test]
    fn an_external_id_reference_names_the_id_to_use_instead() {
        let zones = ZoneIndex::from_zone_list(&zone_list()).expect("a well-formed zone list");
        let staged = policy_between(
            "11111111-1111-4111-8111-111111111111",
            "cccccccccccccccccccccccc",
        );
        let error = check_references(&zones, &[staged]).expect_err("an external_id is not an _id");
        let rendered = error.to_string();
        assert!(rendered.contains("external_id"), "{rendered}");
        assert!(rendered.contains("aaaaaaaaaaaaaaaaaaaaaaaa"), "{rendered}");
    }

    /// "Could not read the zone list" and "the zone is not there" want
    /// different operator responses, so they must not render alike.
    #[test]
    fn an_unreadable_zone_list_does_not_read_as_a_missing_zone() {
        let error = ZoneIndex::from_zone_list(&serde_json::json!({ "data": [] }))
            .expect_err("an envelope is not the Private v2 shape");
        let rendered = error.to_string();
        assert!(rendered.contains("unexpected response shape"), "{rendered}");
        assert!(
            !rendered.contains("not one of the"),
            "a parse failure must not claim a zone is absent: {rendered}"
        );
    }

    /// A zone entry with no `_id` is drift, not an absent reference.
    #[test]
    fn a_zone_without_an_id_is_a_parse_failure() {
        let error = ZoneIndex::from_zone_list(&serde_json::json!([{ "name": "Internal" }]))
            .expect_err("a zone with no `_id` cannot be indexed");
        assert!(error.to_string().contains("position 0"), "{error}");
    }

    /// Both sides of a policy are checked. Only checking `source` let a
    /// destination naming a deleted zone through to apply.
    #[test]
    fn the_destination_zone_is_checked_too() {
        let zones = ZoneIndex::from_zone_list(&zone_list()).expect("a well-formed zone list");
        let staged = policy_between("aaaaaaaaaaaaaaaaaaaaaaaa", "does-not-exist");
        let error = check_references(&zones, &[staged]).expect_err("destination must be checked");
        assert!(error.to_string().contains("destination"), "{error}");
    }

    /// Apply runs staged mutations in order against live state, so a zone the
    /// same change set deletes is gone before a later policy write lands. The
    /// live list still has it, which is why the index alone is not enough.
    #[test]
    fn a_policy_naming_a_zone_the_same_set_deletes_is_refused() {
        let zones = ZoneIndex::from_zone_list(&zone_list()).expect("a well-formed zone list");
        let staged = vec![
            StagedMutation::delete("firewall_zone", "cccccccccccccccccccccccc"),
            policy_between("aaaaaaaaaaaaaaaaaaaaaaaa", "cccccccccccccccccccccccc"),
        ];
        let error =
            check_references(&zones, &staged).expect_err("the destination zone is being deleted");
        let rendered = error.to_string();
        assert!(rendered.contains("also"), "{rendered}");
        assert!(rendered.contains("deletes"), "{rendered}");
    }

    /// Staging order does not rescue it: the policy is checked against the
    /// state the whole set projects, not the prefix before it.
    #[test]
    fn the_delete_is_caught_even_when_staged_after_the_policy() {
        let zones = ZoneIndex::from_zone_list(&zone_list()).expect("a well-formed zone list");
        let staged = vec![
            policy_between("cccccccccccccccccccccccc", "aaaaaaaaaaaaaaaaaaaaaaaa"),
            StagedMutation::delete("firewall_zone", "cccccccccccccccccccccccc"),
        ];
        assert!(check_references(&zones, &staged).is_err());
    }

    /// Deleting some other resource that happens to share an id must not
    /// invalidate a zone reference.
    #[test]
    fn deleting_a_non_zone_resource_does_not_invalidate_a_zone_reference() {
        let zones = ZoneIndex::from_zone_list(&zone_list()).expect("a well-formed zone list");
        let staged = vec![
            StagedMutation::delete("firewall_policy", "cccccccccccccccccccccccc"),
            policy_between("aaaaaaaaaaaaaaaaaaaaaaaa", "cccccccccccccccccccccccc"),
        ];
        assert!(check_references(&zones, &staged).is_ok());
    }

    /// A change set that names no zone must not be made to depend on the
    /// firewall surface being reachable.
    #[test]
    fn a_change_set_naming_no_zone_needs_no_zone_list() {
        let staged = StagedMutation::update("network", "abc123", serde_json::json!({"name": "x"}));
        assert!(referenced_zone_ids(&[staged]).is_empty());
    }

    /// Deletes carry no body, so they contribute no reference to resolve.
    #[test]
    fn deletes_reference_no_zones() {
        let staged = StagedMutation::delete("firewall_policy", "abc123");
        assert!(referenced_zone_ids(&[staged]).is_empty());
    }

    #[test]
    fn both_sides_of_a_policy_are_collected_once_each() {
        let staged = policy_between("aaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(
            referenced_zone_ids(&[staged]),
            vec!["aaaaaaaaaaaaaaaaaaaaaaaa"]
        );
    }
}
