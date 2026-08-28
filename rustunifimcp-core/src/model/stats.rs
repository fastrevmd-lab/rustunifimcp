//! UniFi statistics resource models.

use crate::error::UnifiError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Device statistics.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct DeviceStats {
    /// Device MAC address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// Device name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Station (client) statistics.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct StationStats {
    /// Client MAC address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// Hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

/// Parses device statistics from the Private v1 API response.
pub fn parse_device_stats(val: &serde_json::Value) -> Result<Vec<DeviceStats>, UnifiError> {
    let data = super::unwrap_enveloped_data(val)?;
    data.iter()
        .map(|item| {
            serde_json::from_value(item.clone())
                .map_err(|e| UnifiError::Malformed(format!("device stats parse failed: {e}")))
        })
        .collect()
}

/// Parses station statistics from the Private v1 API response.
pub fn parse_station_stats(val: &serde_json::Value) -> Result<Vec<StationStats>, UnifiError> {
    let data = super::unwrap_enveloped_data(val)?;
    data.iter()
        .map(|item| {
            serde_json::from_value(item.clone())
                .map_err(|e| UnifiError::Malformed(format!("station stats parse failed: {e}")))
        })
        .collect()
}
