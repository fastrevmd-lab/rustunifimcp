//! UniFi station (client) resource model.

use crate::error::UnifiError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A wireless or wired client associated with the site.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Station {
    /// Client UUID.
    pub id: String,
    /// Client type (`"WIRED"` or `"WIRELESS"`).
    #[serde(rename = "type")]
    pub client_type: String,
    /// Client name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Time the client connected (ISO 8601).
    #[serde(rename = "connectedAt", skip_serializing_if = "Option::is_none")]
    pub connected_at: Option<String>,
    /// Client IP address.
    #[serde(rename = "ipAddress", skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    /// Client MAC address.
    #[serde(rename = "macAddress")]
    pub mac_address: String,
    /// UUID of the uplink device.
    #[serde(rename = "uplinkDeviceId", skip_serializing_if = "Option::is_none")]
    pub uplink_device_id: Option<String>,
}

/// Parses stations from the Integration API response.
pub fn parse_stations(val: &serde_json::Value) -> Result<Vec<Station>, UnifiError> {
    let data = super::unwrap_enveloped_data(val)?;
    data.iter()
        .map(|item| serde_json::from_value(item.clone()).map_err(|e| {
            UnifiError::Malformed(format!("station parse failed: {e}"))
        }))
        .collect()
}
