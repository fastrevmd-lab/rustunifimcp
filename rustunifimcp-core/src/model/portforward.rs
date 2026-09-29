//! UniFi port forwarding resource model.

use crate::error::UnifiError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A port forwarding rule.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct PortForward {
    /// Rule ID.
    #[serde(rename = "_id")]
    pub id: String,
    /// Rule name.
    pub name: String,
    /// Whether the rule is enabled.
    pub enabled: bool,
    /// Source interface (e.g., `"wan"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pfwd_interface: Option<String>,
    /// External-side source address restriction (`"any"` or a CIDR).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src: Option<String>,
    /// External (WAN-side) destination port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<String>,
    /// Internal (LAN-side) forward-to address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fwd: Option<String>,
    /// Internal (LAN-side) forward-to port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fwd_port: Option<String>,
    /// Protocol (`"tcp"`, `"udp"`, `"tcp_udp"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proto: Option<String>,
    /// WAN destination IP this rule applies to, on a multi-WAN controller
    /// (as opposed to matching all WAN IPs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_ip: Option<String>,
    /// Whether matches against this rule are logged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<bool>,
}

/// Parses port forwards from the Private v1 API response.
pub fn parse_port_forwards(val: &serde_json::Value) -> Result<Vec<PortForward>, UnifiError> {
    let data = super::unwrap_enveloped_data(val)?;
    data.iter()
        .map(|item| {
            serde_json::from_value(item.clone())
                .map_err(|e| UnifiError::Malformed(format!("port forward parse failed: {e}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_port_forwards;
    use crate::testing::{DEFAULT_FIXTURE_VERSION, fixture};

    /// Port forwards must parse from the committed synthetic fixture.
    #[test]
    fn port_forwards_parse_from_the_synthetic_fixture() {
        let raw = fixture(DEFAULT_FIXTURE_VERSION, "portforward");
        let forwards = parse_port_forwards(&raw).expect("port forward parse");
        assert!(
            !forwards.is_empty(),
            "the synthetic fixture must carry at least one port forward"
        );
        assert_eq!(forwards[0].fwd_port.as_deref(), Some("22"));
        assert_eq!(forwards[0].destination_ip.as_deref(), Some("203.0.113.10"));
        assert_eq!(forwards[0].log, Some(false));
    }
}
