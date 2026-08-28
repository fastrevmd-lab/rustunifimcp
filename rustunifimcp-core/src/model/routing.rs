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
