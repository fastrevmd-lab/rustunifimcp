//! UniFi firewall resource models.

use crate::error::UnifiError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A firewall address or port group.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct FirewallGroup {
    /// Group ID.
    #[serde(rename = "_id")]
    pub id: String,
    /// Group name.
    pub name: String,
    /// Group type (`"address-group"` or `"port-group"`).
    pub group_type: String,
    /// Group members (IPs/CIDRs for address groups, ports for port groups).
    pub group_members: Vec<String>,
    /// External ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

/// A firewall zone.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct FirewallZone {
    /// Zone ID.
    #[serde(rename = "_id")]
    pub id: String,
    /// Zone name.
    pub name: String,
    /// Whether this is a default zone.
    #[serde(default)]
    pub default_zone: bool,
    /// Network IDs assigned to this zone.
    #[serde(default)]
    pub network_ids: Vec<String>,
    /// External ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

/// A zone-based firewall policy.
///
/// The named fields are the ones the tool layer relies on. Everything else the
/// controller returns is carried in [`Self::rest`] rather than dropped, because
/// a policy that loses `source`, `destination`, `protocol` and its ports is not
/// a policy any more: reading a working one and adapting it is the safest way
/// to author a new one, and the trimmed projection made that impossible. Zones
/// were already returned whole; policies are the kind where completeness
/// matters most and were the one being trimmed.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct FirewallPolicy {
    /// Policy ID.
    #[serde(rename = "_id")]
    pub id: String,
    /// Policy name.
    pub name: String,
    /// Policy action (`"ALLOW"` or `"BLOCK"`).
    pub action: String,
    /// Whether the policy is enabled.
    pub enabled: bool,
    /// Policy index (for ordering).
    pub index: u32,
    /// Whether this is a predefined policy.
    #[serde(default)]
    pub predefined: bool,
    /// Number of hits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hits: Option<u64>,
    /// Every other field the controller returned, verbatim.
    ///
    /// `source`, `destination`, `protocol`, `schedule`,
    /// `connection_state_type` and the rest live here. Round-tripping a policy
    /// through this type is lossless, so `unifi_get_resource` output can be
    /// edited and handed back to `unifi_stage_change`.
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

/// A legacy (non-zone-based) firewall rule.
///
/// This is the pre-zone-based ruleset (`rest/firewallrule`), superseded on
/// newer controllers by [`FirewallPolicy`] but still the active enforcement
/// path on controllers that have not migrated. Unlike `FirewallPolicy` this
/// shape has no secret-bearing fields UniFi documents, so it is projected
/// through a plain allowlist rather than the denylist-and-shape scan.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct FirewallRule {
    /// Rule ID.
    #[serde(rename = "_id")]
    pub id: String,
    /// Rule name.
    pub name: String,
    /// Ruleset the rule belongs to (e.g., `"WAN_IN"`, `"LAN_IN"`).
    pub ruleset: String,
    /// Rule index (ordering within the ruleset).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_index: Option<String>,
    /// Whether the rule is enabled.
    pub enabled: bool,
    /// Action (`"accept"`, `"drop"`, `"reject"`).
    pub action: String,
    /// Protocol matched (e.g., `"tcp"`, `"udp"`, `"all"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Source address type (`"any"`, `"address"`, `"network"`, `"group"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_address: Option<String>,
    /// Destination address type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_address: Option<String>,
    /// Source port(s).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_port: Option<String>,
    /// Destination port(s).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<String>,
}

/// Parses legacy firewall rules from the Private v1 API response.
pub fn parse_firewall_rules(val: &serde_json::Value) -> Result<Vec<FirewallRule>, UnifiError> {
    let data = super::unwrap_enveloped_data(val)?;
    data.iter()
        .map(|item| {
            serde_json::from_value(item.clone())
                .map_err(|e| UnifiError::Malformed(format!("firewall rule parse failed: {e}")))
        })
        .collect()
}

/// Parses firewall groups from the Private v1 API response.
pub fn parse_firewall_groups(val: &serde_json::Value) -> Result<Vec<FirewallGroup>, UnifiError> {
    let data = super::unwrap_enveloped_data(val)?;
    data.iter()
        .map(|item| {
            serde_json::from_value(item.clone())
                .map_err(|e| UnifiError::Malformed(format!("firewall group parse failed: {e}")))
        })
        .collect()
}

/// Parses firewall zones from the Private v2 API response.
pub fn parse_firewall_zones(val: &serde_json::Value) -> Result<Vec<FirewallZone>, UnifiError> {
    let data = super::unwrap_private_v2_data(val)?;
    data.iter()
        .map(|item| {
            serde_json::from_value(item.clone())
                .map_err(|e| UnifiError::Malformed(format!("firewall zone parse failed: {e}")))
        })
        .collect()
}

/// Parses firewall policies from the Private v2 API response.
pub fn parse_firewall_policies(val: &serde_json::Value) -> Result<Vec<FirewallPolicy>, UnifiError> {
    let data = super::unwrap_private_v2_data(val)?;
    data.iter()
        .map(|item| {
            serde_json::from_value(item.clone())
                .map_err(|e| UnifiError::Malformed(format!("firewall policy parse failed: {e}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{parse_firewall_policies, parse_firewall_rules};
    use crate::testing::{DEFAULT_FIXTURE_VERSION, fixture};
    use serde_json::json;

    /// Legacy firewall rules must parse from the committed synthetic fixture.
    #[test]
    fn firewall_rules_parse_from_the_synthetic_fixture() {
        let raw = fixture(DEFAULT_FIXTURE_VERSION, "firewallrule");
        let rules = parse_firewall_rules(&raw).expect("firewall rule parse");
        assert!(
            !rules.is_empty(),
            "the synthetic fixture must carry at least one rule"
        );
        assert_eq!(rules[0].ruleset, "WAN_IN");
    }

    /// A policy the Private v2 surface returns, with the match fields that make
    /// it mean anything.
    fn recorded_policy() -> serde_json::Value {
        json!([{
            "_id": "aaaaaaaaaaaaaaaaaaaaaaaa",
            "name": "Phones to DMZ web (https)",
            "action": "ALLOW",
            "enabled": true,
            "index": 10000,
            "predefined": false,
            "hits": 42,
            "protocol": "tcp",
            "ip_version": "BOTH",
            "logging": false,
            "connection_state_type": "ALL",
            "connection_states": [],
            "schedule": { "mode": "ALWAYS" },
            "source": {
                "zone_id": "bbbbbbbbbbbbbbbbbbbbbbbb",
                "matching_target": "ANY",
                "port_matching_type": "ANY",
                "match_opposite_ports": false
            },
            "destination": {
                "zone_id": "cccccccccccccccccccccccc",
                "matching_target": "IP",
                "port_matching_type": "SPECIFIC",
                "match_opposite_ports": false
            }
        }])
    }

    /// The authoring loop is: read a policy that works, change one thing, stage
    /// it. A projection that drops `source` and `destination` breaks that, and
    /// leaves the caller guessing at the body `unifi_stage_change` wants.
    #[test]
    fn a_policy_keeps_the_fields_that_make_it_a_policy() {
        let parsed = parse_firewall_policies(&recorded_policy()).expect("policy parse");
        let rendered = serde_json::to_value(&parsed).expect("serialize");
        let policy = &rendered[0];

        for field in [
            "source",
            "destination",
            "protocol",
            "schedule",
            "connection_state_type",
        ] {
            assert!(
                policy.get(field).is_some(),
                "{field} is absent, so this policy cannot be used as a template: {policy}"
            );
        }
        assert_eq!(policy["source"]["zone_id"], "bbbbbbbbbbbbbbbbbbbbbbbb");
        assert_eq!(policy["destination"]["matching_target"], "IP");
    }

    /// Lossless in the strict sense: what came in comes back out, so a fetched
    /// policy can be edited and handed straight back to staging.
    #[test]
    fn a_policy_round_trips_without_losing_a_field() {
        let raw = recorded_policy();
        let parsed = parse_firewall_policies(&raw).expect("policy parse");
        let rendered = serde_json::to_value(&parsed).expect("serialize");
        assert_eq!(rendered, raw, "the projection dropped or renamed a field");
    }

    /// The named fields must not also appear in the overflow map, which is how
    /// a flattened struct silently starts emitting `_id` twice.
    #[test]
    fn named_fields_are_not_duplicated_into_the_overflow_map() {
        let parsed = parse_firewall_policies(&recorded_policy()).expect("policy parse");
        for field in ["_id", "name", "action", "enabled", "index", "predefined"] {
            assert!(
                !parsed[0].rest.contains_key(field),
                "{field} is both named and in `rest`"
            );
        }
    }
}
