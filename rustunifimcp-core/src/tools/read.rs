//! The five read primitives.
//!
//! `unifi_list_resources` and `unifi_get_resource` are where the collapsed
//! surface lives: roughly 130 of the legacy server's tools were `list_x` /
//! `get_x` pairs differing only in the resource addressed, and they are variants
//! of `ResourceKind` here behind one documented envelope.

use crate::client::UnifiClient;
use crate::error::UnifiError;
use crate::model::ResourceKind;
use crate::ApiSurface;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Arguments to `unifi_list_resources`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListResourcesArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// Which kind of resource to list.
    pub kind: ResourceKind,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
    /// Maximum items to return.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Offset into the result set.
    #[serde(default)]
    pub offset: Option<u64>,
}

/// Arguments to `unifi_get_resource`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetResourceArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// Which kind of resource to fetch.
    pub kind: ResourceKind,
    /// The resource identifier.
    pub id: String,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
}

/// Subject for statistics queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StatsSubject {
    /// Site-wide statistics.
    Site,
    /// Per-device statistics.
    Device,
    /// Per-station (client) statistics.
    Station,
    /// Per-WLAN statistics.
    Wlan,
    /// Per-flow statistics.
    Flow,
}

/// Arguments to `unifi_query_stats`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryStatsArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// What to query statistics for.
    pub subject: StatsSubject,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
    /// Start of the time window (Unix timestamp in seconds).
    #[serde(default)]
    pub start: Option<i64>,
    /// End of the time window (Unix timestamp in seconds).
    #[serde(default)]
    pub end: Option<i64>,
}

/// Arguments to `unifi_search`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// Free text query.
    pub query: String,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
    /// Maximum items to return per resource type.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Arguments to `unifi_list_sites`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListSitesArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
}

/// List resources of one kind.
///
/// # Errors
///
/// Returns [`UnifiError::SurfaceRequiresConfig`] if the kind lives on a private
/// surface the controller has not opted into, or [`UnifiError::PrivateEndpointAbsent`]
/// if a private route has been removed by a controller upgrade.
pub async fn list_resources(
    client: &UnifiClient,
    args: &ListResourcesArgs,
) -> Result<serde_json::Value, UnifiError> {
    let page = mecmcp_openapi::page(
        args.offset.unwrap_or(0),
        u64::from(args.limit.unwrap_or(200)),
        mecmcp_openapi::PageLimits::default(),
    )
    .map_err(|error| UnifiError::Malformed(error.to_string()))?;

    let surface = args.kind.surface();
    let site = if let Some(ref s) = args.site {
        s.as_str()
    } else {
        &client.default_site_for(surface).await?
    };

    client
        .get(
            surface,
            args.kind.path_template(),
            &[("site", site)],
            &[
                ("offset", &page.from.to_string()),
                ("limit", &page.size.to_string()),
            ],
        )
        .await
}

/// Get a single resource by ID.
///
/// # Errors
///
/// Returns [`UnifiError::SurfaceRequiresConfig`] if the kind lives on a private
/// surface the controller has not opted into, or [`UnifiError::PrivateEndpointAbsent`]
/// if a private route has been removed by a controller upgrade.
pub async fn get_resource(
    client: &UnifiClient,
    args: &GetResourceArgs,
) -> Result<serde_json::Value, UnifiError> {
    let surface = args.kind.surface();
    let site = if let Some(ref s) = args.site {
        s.as_str()
    } else {
        &client.default_site_for(surface).await?
    };

    let template = format!("{}/{{}}", args.kind.path_template());

    client
        .get(
            surface,
            &template,
            &[("site", site), ("id", &args.id)],
            &[],
        )
        .await
}

/// Query statistics for a subject.
///
/// Statistics are served from the Private v1 API surface.
///
/// # Errors
///
/// Returns [`UnifiError::SurfaceRequiresConfig`] if the controller has not
/// opted into private API access.
pub async fn query_stats(
    client: &UnifiClient,
    args: &QueryStatsArgs,
) -> Result<serde_json::Value, UnifiError> {
    let site = if let Some(ref s) = args.site {
        s.as_str()
    } else {
        &client.default_site_for(ApiSurface::PrivateV1).await?
    };

    let endpoint = match args.subject {
        StatsSubject::Site => "/proxy/network/api/s/{site}/stat/sites",
        StatsSubject::Device => "/proxy/network/api/s/{site}/stat/device",
        StatsSubject::Station => "/proxy/network/api/s/{site}/stat/sta",
        StatsSubject::Wlan => "/proxy/network/api/s/{site}/stat/wlan",
        StatsSubject::Flow => "/proxy/network/api/s/{site}/stat/flow",
    };

    let mut query = Vec::new();
    if let Some(start) = args.start {
        query.push(("start", start.to_string()));
    }
    if let Some(end) = args.end {
        query.push(("end", end.to_string()));
    }

    let query_refs: Vec<(&str, &str)> = query
        .iter()
        .map(|(k, v)| (*k, v.as_str()))
        .collect();

    client
        .get(ApiSurface::PrivateV1, endpoint, &[("site", site)], &query_refs)
        .await
}

/// Search across stations, devices, and sites.
///
/// Merges results from the Integration API's client and device endpoints and
/// the Private v1 site endpoint.
///
/// # Errors
///
/// Returns [`UnifiError`] when any of the underlying searches fail.
pub async fn search(
    client: &UnifiClient,
    args: &SearchArgs,
) -> Result<serde_json::Value, UnifiError> {
    let limit = args.limit.unwrap_or(10);

    let site_uuid = client.default_site_for(ApiSurface::Supported).await?;
    let site_name = if let Some(ref s) = args.site {
        s.as_str()
    } else {
        client.default_site()
    };

    // Search stations (clients) via Integration API
    let stations = client
        .get(
            ApiSurface::Supported,
            "/proxy/network/integration/v1/sites/{site}/clients",
            &[("site", &site_uuid)],
            &[("limit", &limit.to_string())],
        )
        .await?;

    // Search devices via Integration API
    let devices = client
        .get(
            ApiSurface::Supported,
            "/proxy/network/integration/v1/sites/{site}/devices",
            &[("site", &site_uuid)],
            &[("limit", &limit.to_string())],
        )
        .await?;

    // Search sites via Private v1 API
    let sites = client
        .get(
            ApiSurface::PrivateV1,
            "/proxy/network/api/s/{site}/self",
            &[("site", site_name)],
            &[],
        )
        .await?;

    // Merge results
    let stations_data = crate::model::unwrap_enveloped_data(&stations)?;
    let devices_data = crate::model::unwrap_enveloped_data(&devices)?;

    let sites_data = if sites.is_array() {
        sites.as_array().ok_or_else(|| {
            UnifiError::Malformed("expected sites array".to_string())
        })?
    } else {
        crate::model::unwrap_enveloped_data(&sites)?
    };

    let results = serde_json::json!({
        "stations": filter_by_query(stations_data, &args.query, limit as usize),
        "devices": filter_by_query(devices_data, &args.query, limit as usize),
        "sites": filter_by_query(sites_data, &args.query, limit as usize),
    });

    Ok(results)
}

/// Filter results by a query string.
fn filter_by_query(
    items: &[serde_json::Value],
    query: &str,
    limit: usize,
) -> Vec<serde_json::Value> {
    let query_lower = query.to_lowercase();
    items
        .iter()
        .filter(|item| {
            let json_str = item.to_string().to_lowercase();
            json_str.contains(&query_lower)
        })
        .take(limit)
        .cloned()
        .collect()
}

/// List sites visible to this controller.
///
/// # Errors
///
/// Returns [`UnifiError`] when the sites endpoint cannot be reached or returns
/// an unexpected shape.
pub async fn list_sites(
    client: &UnifiClient,
    _args: &ListSitesArgs,
) -> Result<serde_json::Value, UnifiError> {
    client
        .get(
            ApiSurface::Supported,
            "/proxy/network/integration/v1/sites",
            &[],
            &[],
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::{GetResourceArgs, ListResourcesArgs};
    use crate::model::ResourceKind;

    /// Unknown fields must be refused, not dropped. rust-proxmoxmcp shipped
    /// this as a fix (its "refuse unknown fields instead of silently dropping
    /// them" commit): a caller who misspells a filter should be told, not
    /// silently given unfiltered results.
    #[test]
    fn unknown_arguments_are_refused_not_dropped() {
        let raw = r#"{"controller":"home","kind":"network","limitt":5}"#;
        let parsed: Result<ListResourcesArgs, _> = serde_json::from_str(raw);
        assert!(parsed.is_err(), "a misspelled argument must be an error");
    }

    #[test]
    fn every_resource_kind_round_trips_through_the_args_schema() {
        for kind in ResourceKind::ALL {
            let json = serde_json::to_string(kind).expect("serializes");
            let raw = format!(r#"{{"controller":"home","kind":{json}}}"#);
            let parsed: ListResourcesArgs =
                serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{kind:?}: {e}"));
            assert_eq!(parsed.kind, *kind);
        }
    }

    #[test]
    fn get_resource_requires_an_id() {
        let raw = r#"{"controller":"home","kind":"network"}"#;
        let parsed: Result<GetResourceArgs, _> = serde_json::from_str(raw);
        assert!(parsed.is_err(), "get_resource without an id must not parse");
    }
}
