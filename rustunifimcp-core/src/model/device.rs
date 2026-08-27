//! UniFi device resource model.

use crate::error::UnifiError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// An adopted UniFi device: AP, switch, or gateway.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Device {
    /// Device UUID.
    pub id: String,
    /// Device MAC address.
    #[serde(rename = "macAddress")]
    pub mac_address: String,
    /// Device IP address.
    #[serde(rename = "ipAddress", skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    /// Device name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Device model.
    pub model: String,
    /// Device state (e.g., `"ONLINE"`, `"OFFLINE"`).
    pub state: String,
    /// Whether the device is officially supported.
    pub supported: bool,
    /// Firmware version.
    #[serde(rename = "firmwareVersion")]
    pub firmware_version: String,
    /// Whether firmware is updatable.
    #[serde(rename = "firmwareUpdatable")]
    pub firmware_updatable: bool,
    /// Device features (e.g., `["switching", "accessPoint"]`).
    #[serde(default)]
    pub features: Vec<String>,
    /// Device interfaces (e.g., `["ports", "radios"]`).
    #[serde(default)]
    pub interfaces: Vec<String>,
}

/// Parses devices from the Integration API response.
pub fn parse_devices(val: &serde_json::Value) -> Result<Vec<Device>, UnifiError> {
    let data = super::unwrap_integration_data(val)?;
    data.iter()
        .map(|item| serde_json::from_value(item.clone()).map_err(|e| {
            UnifiError::Malformed(format!("device parse failed: {e}"))
        }))
        .collect()
}
