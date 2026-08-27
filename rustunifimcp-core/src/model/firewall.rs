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
}

/// Parses firewall groups from the Private v1 API response.
pub fn parse_firewall_groups(val: &serde_json::Value) -> Result<Vec<FirewallGroup>, UnifiError> {
    let data = super::unwrap_private_v1_data(val)?;
    data.iter()
        .map(|item| serde_json::from_value(item.clone()).map_err(|e| {
            UnifiError::Malformed(format!("firewall group parse failed: {e}"))
        }))
        .collect()
}

/// Parses firewall zones from the Private v2 API response.
pub fn parse_firewall_zones(val: &serde_json::Value) -> Result<Vec<FirewallZone>, UnifiError> {
    let data = super::unwrap_private_v2_data(val)?;
    data.iter()
        .map(|item| serde_json::from_value(item.clone()).map_err(|e| {
            UnifiError::Malformed(format!("firewall zone parse failed: {e}"))
        }))
        .collect()
}

/// Parses firewall policies from the Private v2 API response.
pub fn parse_firewall_policies(val: &serde_json::Value) -> Result<Vec<FirewallPolicy>, UnifiError> {
    let data = super::unwrap_private_v2_data(val)?;
    data.iter()
        .map(|item| serde_json::from_value(item.clone()).map_err(|e| {
            UnifiError::Malformed(format!("firewall policy parse failed: {e}"))
        }))
        .collect()
}
