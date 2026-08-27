//! The resource model, and the enum that collapses the legacy surface.
//!
//! Roughly 130 of the legacy server's tools are `list_x` / `get_x` pairs that
//! differ only in the resource they address. They become variants here, behind
//! a shared, documented envelope, reached through `unifi_list_resources` and
//! `unifi_get_resource`.
//!
//! Each variant carries its API surface, which is what lets a supported-only
//! deployment refuse the undocumented ones structurally rather than by
//! convention.

use crate::ApiSurface;
use crate::error::UnifiError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub mod device;
pub mod firewall;
pub mod network;
pub mod routing;
pub mod site;
pub mod station;
pub mod stats;

/// Unwraps an enveloped response `{"data": [...], ...}`.
///
/// Both the Integration API and the Private v1 surface wrap their payload as
/// an object with a `data` array; this helper handles both.
fn unwrap_enveloped_data(val: &serde_json::Value) -> Result<&Vec<serde_json::Value>, UnifiError> {
    val.get("data")
        .and_then(|d| d.as_array())
        .ok_or_else(|| UnifiError::Malformed("expected an envelope object with a `data` array".to_string()))
}

/// Unwraps the Private v2 API response (plain array `[...]`).
///
/// Unlike the Integration API and Private v1, which wrap their payload in an
/// envelope with a `data` field, Private v2 returns a bare JSON array directly.
fn unwrap_private_v2_data(val: &serde_json::Value) -> Result<&Vec<serde_json::Value>, UnifiError> {
    val.as_array()
        .ok_or_else(|| UnifiError::Malformed("expected Private v2 plain array".to_string()))
}

/// A kind of UniFi resource addressable by the read primitives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ResourceKind {
    /// A wireless or wired client associated with the site.
    Station,
    /// An adopted UniFi device: AP, switch, or gateway.
    Device,
    /// A configured network / VLAN.
    Network,
    /// A wireless network.
    Wlan,
    /// A switch port profile.
    PortProfile,
    /// A static DHCP mapping.
    DhcpReservation,
    /// A zone-based firewall policy.
    FirewallPolicy,
    /// A firewall zone.
    FirewallZone,
    /// A firewall address or port group.
    FirewallGroup,
    /// A policy-based traffic route.
    TrafficRoute,
    /// A RADIUS profile.
    RadiusProfile,
}

impl ResourceKind {
    /// Every variant, for exhaustive tests and for `unifi_list_resources`'
    /// schema.
    pub const ALL: &'static [Self] = &[
        Self::Station,
        Self::Device,
        Self::Network,
        Self::Wlan,
        Self::PortProfile,
        Self::DhcpReservation,
        Self::FirewallPolicy,
        Self::FirewallZone,
        Self::FirewallGroup,
        Self::TrafficRoute,
        Self::RadiusProfile,
    ];

    /// Which API surface this kind is served from.
    #[must_use]
    pub const fn surface(self) -> ApiSurface {
        match self {
            Self::Station | Self::Device => ApiSurface::Supported,
            Self::Network
            | Self::Wlan
            | Self::PortProfile
            | Self::DhcpReservation
            | Self::FirewallGroup
            | Self::RadiusProfile => ApiSurface::PrivateV1,
            Self::FirewallPolicy | Self::FirewallZone | Self::TrafficRoute => {
                ApiSurface::PrivateV2
            }
        }
    }

    /// The path template, expanded by `mecmcp-openapi::expand_path`.
    #[must_use]
    pub const fn path_template(self) -> &'static str {
        match self {
            Self::Station => "/proxy/network/integration/v1/sites/{site}/clients",
            Self::Device => "/proxy/network/integration/v1/sites/{site}/devices",
            Self::Network => "/proxy/network/api/s/{site}/rest/networkconf",
            Self::Wlan => "/proxy/network/api/s/{site}/rest/wlanconf",
            Self::PortProfile => "/proxy/network/api/s/{site}/rest/portconf",
            Self::DhcpReservation => "/proxy/network/api/s/{site}/rest/user",
            Self::FirewallGroup => "/proxy/network/api/s/{site}/rest/firewallgroup",
            Self::RadiusProfile => "/proxy/network/api/s/{site}/rest/radiusprofile",
            Self::FirewallPolicy => "/proxy/network/v2/api/site/{site}/firewall-policies",
            Self::FirewallZone => "/proxy/network/v2/api/site/{site}/firewall/zone",
            Self::TrafficRoute => "/proxy/network/v2/api/site/{site}/trafficroutes",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ResourceKind;
    use crate::testing::{fixture, fixtures_available, DEFAULT_FIXTURE_VERSION};
    use crate::ApiSurface;

    /// Every kind must declare a surface. A kind whose surface is wrong is how
    /// an undocumented route gets reached by a supported-only deployment.
    #[test]
    fn every_kind_declares_its_surface_and_path() {
        for kind in ResourceKind::ALL {
            let template = kind.path_template();
            assert!(!template.is_empty(), "{kind:?} has no path template");
            assert!(
                template.starts_with('/'),
                "{kind:?} template is not absolute"
            );
            // A supported-surface kind must not point at a private route.
            if kind.surface() == ApiSurface::Supported {
                assert!(
                    !template.contains("/api/s/") && !template.contains("/v2/api/"),
                    "{kind:?} claims Supported but uses a private path: {template}"
                );
            }
        }
    }

    #[test]
    fn firewall_zones_are_tagged_private_v2() {
        assert_eq!(
            ResourceKind::FirewallZone.surface(),
            ApiSurface::PrivateV2
        );
    }

    #[test]
    fn sites_parse_from_the_recorded_response() {
        if !fixtures_available() {
            eprintln!("SKIPPED: no fixtures. Run scripts/capture-fixtures.sh against a controller.");
            return;
        }
        let raw = fixture(DEFAULT_FIXTURE_VERSION, "sites");
        let sites = crate::model::site::parse_sites(&raw).expect("sites parse");
        assert!(
            !sites.is_empty(),
            "the recorded controller has at least one site"
        );
    }

    #[test]
    fn networks_parse_from_the_recorded_response() {
        if !fixtures_available() {
            eprintln!("SKIPPED: no fixtures. Run scripts/capture-fixtures.sh against a controller.");
            return;
        }
        let raw = fixture(DEFAULT_FIXTURE_VERSION, "networkconf");
        let networks =
            crate::model::network::parse_networks(&raw).expect("networks parse");
        assert!(!networks.is_empty());
    }
}
