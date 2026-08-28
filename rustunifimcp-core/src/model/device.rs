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
    /// Device features.
    ///
    /// See [`DeviceCapability`] for why this is not simply a list of names.
    #[serde(default)]
    pub features: DeviceCapability,
    /// Device interfaces.
    ///
    /// See [`DeviceCapability`] for why this is not simply a list of names.
    #[serde(default)]
    pub interfaces: DeviceCapability,
}

/// A device capability set, in either shape the Integration API returns.
///
/// The collection endpoint answers with a list of names
/// (`["switching", "accessPoint"]`); the single-resource endpoint answers with
/// an object detailing each capability. Declaring `Vec<String>` parsed the
/// list and failed every single-device GET with "invalid type: map, expected a
/// sequence", which reads like a malformed controller response rather than one
/// endpoint of a pair answering differently from the other.
///
/// Both shapes are preserved as the controller sent them rather than
/// flattened, because the detail is the reason to fetch one device instead of
/// the list.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum DeviceCapability {
    /// Capability names, as the collection endpoint reports them.
    Names(Vec<String>),
    /// Per-capability detail, as the single-resource endpoint reports it.
    Detail(serde_json::Map<String, serde_json::Value>),
}

impl Default for DeviceCapability {
    fn default() -> Self {
        Self::Names(Vec::new())
    }
}

/// Parses devices from the Integration API response.
pub fn parse_devices(val: &serde_json::Value) -> Result<Vec<Device>, UnifiError> {
    let data = super::unwrap_enveloped_data(val)?;
    data.iter()
        .map(|item| {
            serde_json::from_value(item.clone())
                .map_err(|e| UnifiError::Malformed(format!("device parse failed: {e}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{DeviceCapability, parse_devices};

    /// Both Integration API shapes must parse.
    ///
    /// The collection and single-resource endpoints disagree about `features`
    /// and `interfaces`, and a model that only accepts one of them makes the
    /// other endpoint look broken.
    #[test]
    fn a_device_parses_from_either_integration_api_shape() {
        let collection = serde_json::json!({"data": [{
            "id": "d1", "macAddress": "00:00:00:00:00:01", "model": "US8",
            "state": "ONLINE", "supported": true,
            "firmwareVersion": "7.0.0", "firmwareUpdatable": false,
            "features": ["switching"], "interfaces": ["ports"]
        }]});
        let listed = parse_devices(&collection).expect("collection shape parses");
        assert!(matches!(listed[0].features, DeviceCapability::Names(_)));

        let single = serde_json::json!({"data": [{
            "id": "d1", "macAddress": "00:00:00:00:00:01", "model": "US8",
            "state": "ONLINE", "supported": true,
            "firmwareVersion": "7.0.0", "firmwareUpdatable": false,
            "features": {"switching": {"portCount": 8}},
            "interfaces": {"ports": [{"idx": 1}]}
        }]});
        let fetched = parse_devices(&single).expect("single-resource shape parses");
        assert!(
            matches!(fetched[0].features, DeviceCapability::Detail(_)),
            "per-capability detail must survive as detail, not collapse to names"
        );
    }
}
