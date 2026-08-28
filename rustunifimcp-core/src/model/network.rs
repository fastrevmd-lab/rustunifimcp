//! UniFi network resource model.

use crate::error::UnifiError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A configured network / VLAN.
///
/// This includes WAN connections — entries with `purpose: "wan"` carry WAN DNS
/// fields (`wan_dns1`, `wan_dns2`, `wan_ipv6_dns1`, `wan_ipv6_dns2`).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Network {
    /// Network ID.
    #[serde(rename = "_id")]
    pub id: String,
    /// Network name.
    pub name: String,
    /// Network purpose (e.g., `"corporate"`, `"vlan-only"`, `"wan"`, `"remote-user-vpn"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// IP subnet in CIDR notation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_subnet: Option<String>,
    /// VLAN ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u16>,
    /// Whether DHCP is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcpd_enabled: Option<bool>,
    /// DHCP start address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcpd_start: Option<String>,
    /// DHCP stop address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcpd_stop: Option<String>,
    /// Primary WAN DNS server (for WAN networks).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wan_dns1: Option<String>,
    /// Secondary WAN DNS server (for WAN networks).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wan_dns2: Option<String>,
    /// Primary WAN IPv6 DNS server (for WAN networks).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wan_ipv6_dns1: Option<String>,
    /// Secondary WAN IPv6 DNS server (for WAN networks).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wan_ipv6_dns2: Option<String>,
}

/// A wireless network (WLAN).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Wlan {
    /// WLAN ID.
    #[serde(rename = "_id")]
    pub id: String,
    /// WLAN name / SSID.
    pub name: String,
    /// Whether the WLAN is enabled.
    pub enabled: bool,
    /// Security mode (e.g., `"wpapsk"`, `"open"`).
    pub security: String,
    /// WLAN band (e.g., `"5g"`, `"2.4g"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wlan_band: Option<String>,
    /// Whether this is a guest network.
    #[serde(default)]
    pub is_guest: bool,
}

/// A switch port profile.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct PortProfile {
    /// Port profile ID.
    #[serde(rename = "_id")]
    pub id: String,
    /// Profile name.
    pub name: String,
    /// Forwarding mode (e.g., `"customize"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forward: Option<String>,
    /// Native network ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_networkconf_id: Option<String>,
}

/// A static DHCP reservation (user).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct DhcpReservation {
    /// User/client ID.
    #[serde(rename = "_id")]
    pub id: String,
    /// Client MAC address.
    pub mac: String,
    /// Last seen IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_ip: Option<String>,
    /// Fixed IP address when `use_fixedip` is true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_ip: Option<String>,
    /// Hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

/// A RADIUS profile.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct RadiusProfile {
    /// RADIUS profile ID.
    #[serde(rename = "_id")]
    pub id: String,
    /// Profile name.
    pub name: String,
    /// External ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

/// Parses networks from the Private v1 API response.
pub fn parse_networks(val: &serde_json::Value) -> Result<Vec<Network>, UnifiError> {
    let data = super::unwrap_enveloped_data(val)?;
    data.iter()
        .map(|item| serde_json::from_value(item.clone()).map_err(|e| {
            UnifiError::Malformed(format!("network parse failed: {e}"))
        }))
        .collect()
}

/// Parses WLANs from the Private v1 API response.
pub fn parse_wlans(val: &serde_json::Value) -> Result<Vec<Wlan>, UnifiError> {
    let data = super::unwrap_enveloped_data(val)?;
    data.iter()
        .map(|item| serde_json::from_value(item.clone()).map_err(|e| {
            UnifiError::Malformed(format!("wlan parse failed: {e}"))
        }))
        .collect()
}

/// Parses port profiles from the Private v1 API response.
pub fn parse_port_profiles(val: &serde_json::Value) -> Result<Vec<PortProfile>, UnifiError> {
    let data = super::unwrap_enveloped_data(val)?;
    data.iter()
        .map(|item| serde_json::from_value(item.clone()).map_err(|e| {
            UnifiError::Malformed(format!("port profile parse failed: {e}"))
        }))
        .collect()
}

/// Parses DHCP reservations from the Private v1 API response.
///
/// The `/rest/user` endpoint returns every known client, not only those with
/// a fixed-IP assignment. A reservation is marked by `use_fixedip: true` in
/// the record; this function filters to only actual reservations.
pub fn parse_dhcp_reservations(val: &serde_json::Value) -> Result<Vec<DhcpReservation>, UnifiError> {
    let data = super::unwrap_enveloped_data(val)?;
    data.iter()
        .filter(|item| {
            item.get("use_fixedip")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        })
        .map(|item| serde_json::from_value(item.clone()).map_err(|e| {
            UnifiError::Malformed(format!("dhcp reservation parse failed: {e}"))
        }))
        .collect()
}

/// Parses RADIUS profiles from the Private v1 API response.
pub fn parse_radius_profiles(val: &serde_json::Value) -> Result<Vec<RadiusProfile>, UnifiError> {
    let data = super::unwrap_enveloped_data(val)?;
    data.iter()
        .map(|item| serde_json::from_value(item.clone()).map_err(|e| {
            UnifiError::Malformed(format!("radius profile parse failed: {e}"))
        }))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_dhcp_reservations;
    use crate::testing::{fixture, fixtures_available, DEFAULT_FIXTURE_VERSION};

    /// The `/rest/user` endpoint returns all known clients, not only those
    /// with a fixed-IP reservation. Verify that the parser filters to actual
    /// reservations (marked by `use_fixedip: true`).
    #[test]
    fn dhcp_reservations_are_filtered_from_all_users() {
        if !fixtures_available() {
            eprintln!("skipping: no fixtures");
            return;
        }

        let raw = fixture(DEFAULT_FIXTURE_VERSION, "user");
        let reservations = parse_dhcp_reservations(&raw).expect("parse");

        // The 10.5.67 fixture holds 257 total user records, of which 46 have
        // `use_fixedip: true`. Assert the parsed count is strictly less than
        // the total, proving the filter is active.
        let total_users = raw
            .get("data")
            .and_then(|d| d.as_array())
            .map(|arr| arr.len())
            .expect("envelope");

        assert!(
            reservations.len() < total_users,
            "parsed {}, total {}: filter did not reduce the set",
            reservations.len(),
            total_users
        );

        // The expected count for 10.5.67 specifically.
        assert_eq!(reservations.len(), 46, "10.5.67 fixture has 46 reservations");
    }
}
