//! UniFi routing resource models.

use crate::error::UnifiError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A static route or policy-based route.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Route {
    /// Route ID.
    #[serde(rename = "_id")]
    pub id: String,
    /// Route name.
    pub name: String,
    /// Route type (e.g., `"static-route"`).
    #[serde(rename = "type")]
    pub route_type: String,
    /// Whether the route is enabled.
    pub enabled: bool,
    /// Static route sub-type (e.g., `"nexthop-route"`, `"blackhole-route"`,
    /// `"interface-route"`). Distinguishes a route with no next-hop (a
    /// blackhole) or one bound to an interface from an ordinary nexthop
    /// route -- three shapes that otherwise all carry the same top-level
    /// `type: "static-route"`.
    #[serde(rename = "static-route_type", skip_serializing_if = "Option::is_none")]
    pub static_route_type: Option<String>,
    /// Static route network (CIDR).
    #[serde(
        rename = "static-route_network",
        skip_serializing_if = "Option::is_none"
    )]
    pub static_route_network: Option<String>,
    /// Static route next-hop.
    #[serde(
        rename = "static-route_nexthop",
        skip_serializing_if = "Option::is_none"
    )]
    pub static_route_nexthop: Option<String>,
    /// Static route administrative distance.
    #[serde(
        rename = "static-route_distance",
        skip_serializing_if = "Option::is_none"
    )]
    pub static_route_distance: Option<u32>,
    /// Bound interface, for an `interface-route`.
    #[serde(
        rename = "static-route_interface",
        skip_serializing_if = "Option::is_none"
    )]
    pub static_route_interface: Option<String>,
}

/// A policy-based traffic route.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct TrafficRoute {
    /// Route ID.
    #[serde(rename = "_id")]
    pub id: String,
    /// Route name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Parses routes from the Private v1 API response.
pub fn parse_routes(val: &serde_json::Value) -> Result<Vec<Route>, UnifiError> {
    let data = super::unwrap_enveloped_data(val)?;
    data.iter()
        .map(|item| {
            serde_json::from_value(item.clone())
                .map_err(|e| UnifiError::Malformed(format!("route parse failed: {e}")))
        })
        .collect()
}

/// Parses traffic routes from the Private v2 API response.
pub fn parse_traffic_routes(val: &serde_json::Value) -> Result<Vec<TrafficRoute>, UnifiError> {
    let data = super::unwrap_private_v2_data(val)?;
    data.iter()
        .map(|item| {
            serde_json::from_value(item.clone())
                .map_err(|e| UnifiError::Malformed(format!("traffic route parse failed: {e}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_routes;
    use crate::testing::{DEFAULT_FIXTURE_VERSION, fixture};

    /// Static routes must parse from the committed synthetic fixture.
    #[test]
    fn static_routes_parse_from_the_synthetic_fixture() {
        let raw = fixture(DEFAULT_FIXTURE_VERSION, "routing");
        let routes = parse_routes(&raw).expect("route parse");
        assert!(
            !routes.is_empty(),
            "the synthetic fixture must carry at least one route"
        );
        let route = &routes[0];
        assert_eq!(route.static_route_type.as_deref(), Some("nexthop-route"));
        assert_eq!(
            route.static_route_network.as_deref(),
            Some("198.51.100.0/24")
        );
        assert_eq!(route.static_route_nexthop.as_deref(), Some("192.0.2.1"));
        assert_eq!(route.static_route_distance, Some(1));
    }
}
