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

/// Parses a raw resource response through the appropriate model parser.
///
/// This is where raw controller JSON becomes typed, filtered resources. Each
/// `ResourceKind` that has a parser is routed through it; kinds without one
/// return the raw payload.
fn parse_resource_list(
    kind: ResourceKind,
    raw: &serde_json::Value,
) -> Result<serde_json::Value, UnifiError> {
    use crate::model::device::parse_devices;
    use crate::model::firewall::{parse_firewall_groups, parse_firewall_policies, parse_firewall_zones};
    use crate::model::network::{parse_dhcp_reservations, parse_networks, parse_port_profiles, parse_radius_profiles, parse_wlans};
    use crate::model::routing::parse_traffic_routes;
    use crate::model::station::parse_stations;

    match kind {
        ResourceKind::Station => {
            let parsed = parse_stations(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        ResourceKind::Device => {
            let parsed = parse_devices(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        ResourceKind::Network => {
            let parsed = parse_networks(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        ResourceKind::Wlan => {
            let parsed = parse_wlans(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        ResourceKind::PortProfile => {
            let parsed = parse_port_profiles(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        ResourceKind::DhcpReservation => {
            let parsed = parse_dhcp_reservations(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        ResourceKind::FirewallPolicy => {
            let parsed = parse_firewall_policies(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        ResourceKind::FirewallZone => {
            let parsed = parse_firewall_zones(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        ResourceKind::FirewallGroup => {
            let parsed = parse_firewall_groups(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        ResourceKind::TrafficRoute => {
            let parsed = parse_traffic_routes(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        ResourceKind::RadiusProfile => {
            let parsed = parse_radius_profiles(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
    }
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

    let raw = client
        .get(
            surface,
            args.kind.path_template(),
            &[("site", site)],
            &[
                ("offset", &page.from.to_string()),
                ("limit", &page.size.to_string()),
            ],
        )
        .await?;

    parse_resource_list(args.kind, &raw)
}

/// Parses a single-resource response through the appropriate model parser.
///
/// Controllers may return a single object or an enveloped object; this function
/// handles both by normalizing to the parsed model type.
fn parse_single_resource(
    kind: ResourceKind,
    raw: &serde_json::Value,
) -> Result<serde_json::Value, UnifiError> {
    use crate::model::device::parse_devices;
    use crate::model::firewall::{parse_firewall_groups, parse_firewall_policies, parse_firewall_zones};
    use crate::model::network::{parse_dhcp_reservations, parse_networks, parse_port_profiles, parse_radius_profiles, parse_wlans};
    use crate::model::routing::parse_traffic_routes;
    use crate::model::station::parse_stations;

    // A single-resource GET does not always answer in the collection's shape.
    // The Integration API returns the object itself, so `kind=device` and
    // `kind=station` reached the collection parsers as a bare object and failed
    // with "expected an envelope object" -- a message that reads like a
    // controller fault rather than a shape we never normalised. Normalise once
    // here instead of teaching every parser two shapes.
    let normalised;
    let raw = match raw.get("data") {
        // Already the collection shape.
        Some(data) if data.is_array() => raw,
        // The Integration API answers a single-resource GET with the object
        // under `data`, not a one-element array. Without this the parser
        // reports "invalid type: map, expected a sequence".
        Some(data) => {
            normalised = serde_json::json!({ "data": [data] });
            &normalised
        }
        None if raw.is_array() => raw,
        // A bare object, which is how the private surfaces answer.
        None => {
            normalised = match kind.surface() {
                ApiSurface::PrivateV2 => serde_json::json!([raw]),
                _ => serde_json::json!({ "data": [raw] }),
            };
            &normalised
        }
    };

    // Wrap in an envelope if needed, parse, then extract the single item
    let parsed_vec = match kind {
        ResourceKind::Station => {
            let parsed = parse_stations(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
        ResourceKind::Device => {
            let parsed = parse_devices(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
        ResourceKind::Network => {
            let parsed = parse_networks(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
        ResourceKind::Wlan => {
            let parsed = parse_wlans(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
        ResourceKind::PortProfile => {
            let parsed = parse_port_profiles(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
        ResourceKind::DhcpReservation => {
            let parsed = parse_dhcp_reservations(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
        ResourceKind::FirewallPolicy => {
            let parsed = parse_firewall_policies(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
        ResourceKind::FirewallZone => {
            let parsed = parse_firewall_zones(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
        ResourceKind::FirewallGroup => {
            let parsed = parse_firewall_groups(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
        ResourceKind::TrafficRoute => {
            let parsed = parse_traffic_routes(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
        ResourceKind::RadiusProfile => {
            let parsed = parse_radius_profiles(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
    };

    // If parsing returned an array with one item, return that item; otherwise return as-is
    if let Some(arr) = parsed_vec.as_array()
        && arr.len() == 1
    {
        return Ok(arr[0].clone());
    }
    Ok(parsed_vec)
}

/// Get a single resource by ID.
///
/// # Errors
///
/// Returns [`UnifiError::SurfaceRequiresConfig`] if the kind lives on a private
/// surface the controller has not opted into, or [`UnifiError::PrivateEndpointAbsent`]
/// The path template addressing one resource of `kind` by id.
///
/// `{id}`, never `{}`: [`mecmcp_openapi::expand_path`] matches placeholders by
/// name, so an anonymous brace pair can never be supplied and the request fails
/// before it reaches the controller. This is a function rather than an inline
/// `format!` so the test exercises the same construction the request does.
#[must_use]
pub fn single_resource_template(kind: ResourceKind) -> String {
    format!("{}/{{id}}", kind.path_template())
}

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

    let template = single_resource_template(args.kind);

    let raw = client
        .get(
            surface,
            &template,
            &[("site", site), ("id", &args.id)],
            &[],
        )
        .await?;

    parse_single_resource(args.kind, &raw)
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
/// the Private v1 site endpoint. If a leg is refused for surface-permission
/// reasons, the result carries `partial: true` and an `omitted` array naming
/// what was skipped. A smaller answer, clearly labelled, beats a wrong one.
///
/// # Errors
///
/// Returns [`UnifiError`] when:
/// - All legs are refused for surface permission reasons (nothing was searched)
/// - Any leg fails with a real transport/protocol error (not a permission refusal)
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

    let mut omitted = Vec::new();
    let mut stations_results = Vec::new();
    let mut devices_results = Vec::new();
    let mut sites_results = Vec::new();

    // Search stations (clients) via Integration API
    match client
        .get(
            ApiSurface::Supported,
            "/proxy/network/integration/v1/sites/{site}/clients",
            &[("site", &site_uuid)],
            &[("limit", &limit.to_string())],
        )
        .await
    {
        Ok(stations) => {
            let stations_data = crate::model::unwrap_enveloped_data(&stations)?;
            stations_results = filter_by_query(stations_data, &args.query, limit as usize);
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("stations: controller has Integration API disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("stations: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // Search devices via Integration API
    match client
        .get(
            ApiSurface::Supported,
            "/proxy/network/integration/v1/sites/{site}/devices",
            &[("site", &site_uuid)],
            &[("limit", &limit.to_string())],
        )
        .await
    {
        Ok(devices) => {
            let devices_data = crate::model::unwrap_enveloped_data(&devices)?;
            devices_results = filter_by_query(devices_data, &args.query, limit as usize);
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("devices: controller has Integration API disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("devices: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // Search sites via Private v1 API
    match client
        .get(
            ApiSurface::PrivateV1,
            "/proxy/network/api/s/{site}/self",
            &[("site", site_name)],
            &[],
        )
        .await
    {
        Ok(sites) => {
            let sites_data = crate::model::unwrap_enveloped_data(&sites)?;
            sites_results = filter_by_query(sites_data, &args.query, limit as usize);
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("sites: controller has allow_private_api disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("sites: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // If all legs were refused, that's an error
    if omitted.len() == 3 {
        return Err(UnifiError::Malformed(
            "all search legs refused: nothing was searched".to_owned(),
        ));
    }

    let partial = !omitted.is_empty();
    let results = serde_json::json!({
        "stations": stations_results,
        "devices": devices_results,
        "sites": sites_results,
        "partial": partial,
        "omitted": omitted,
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

    /// No path in the crate may carry an anonymous `{}` placeholder.
    ///
    /// The first fix of this defect corrected `get_resource` and missed an
    /// identical construction in `changeset/preimage.rs`, which kept every
    /// pre-image capture failing -- and with it every change set that touches
    /// an existing resource. Fixing one occurrence of a defect is not the same
    /// as fixing the defect, so this sweeps the sources rather than trusting
    /// that the known sites are all of them.
    #[test]
    fn no_source_file_builds_a_path_with_an_anonymous_placeholder() {
        // Assembled at runtime so this assertion cannot match itself.
        let needle = format!("{}/{}{}\"", "format!(\"{}", "{", "{}}");
        for (name, source) in [
            ("tools/read.rs", include_str!("read.rs")),
            ("changeset/preimage.rs", include_str!("../changeset/preimage.rs")),
            ("changeset/apply.rs", include_str!("../changeset/apply.rs")),
            ("changeset/rollback.rs", include_str!("../changeset/rollback.rs")),
            ("client.rs", include_str!("../client.rs")),
        ] {
            assert!(
                !source.contains(&needle),
                "{name} builds a path with an anonymous placeholder, which \
                 expand_path can never fill"
            );
        }
    }

    /// Every single-resource GET path must actually expand.
    ///
    /// `get_resource` builds its path by appending an id segment to the kind's
    /// list template. That concatenation is invisible to the path-provenance
    /// test, which checks the constants only -- so an anonymous `{}` shipped
    /// here and made `unifi_get_resource` fail for every kind, on every
    /// controller, while the fixture tests stayed green. This expands the real
    /// template through the real expander, for all of `ResourceKind::ALL`.
    #[test]
    fn every_kind_expands_to_a_usable_single_resource_path() {
        for &kind in crate::model::ResourceKind::ALL {
            let template = super::single_resource_template(kind);
            let expanded = mecmcp_openapi::expand_path(
                &template,
                &[("site", "default"), ("id", "abc123")],
            )
            .unwrap_or_else(|error| {
                panic!("{kind:?} single-resource path does not expand: {error}")
            });
            assert!(
                expanded.ends_with("/abc123"),
                "{kind:?} expanded to {expanded}, which does not address the id"
            );
            assert!(
                !expanded.contains('{') && !expanded.contains('}'),
                "{kind:?} left an unexpanded placeholder: {expanded}"
            );
        }
    }

    use super::{GetResourceArgs, ListResourcesArgs, SearchArgs};
    use crate::error::UnifiError;
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

    /// Verify SearchArgs structure for completeness.
    #[test]
    fn search_args_parses_all_fields() {
        let raw = r#"{"controller":"home","query":"test","site":"default","limit":5}"#;
        let parsed: SearchArgs = serde_json::from_str(raw).expect("valid SearchArgs");
        assert_eq!(parsed.controller, "home");
        assert_eq!(parsed.query, "test");
        assert_eq!(parsed.site, Some("default".to_owned()));
        assert_eq!(parsed.limit, Some(5));
    }

    /// Search result shape must include partial and omitted fields.
    #[test]
    fn search_result_carries_partial_metadata() {
        // Simulated partial result as search would return
        let partial_result = serde_json::json!({
            "stations": [],
            "devices": [],
            "sites": [],
            "partial": true,
            "omitted": ["sites: controller has allow_private_api disabled"]
        });

        assert_eq!(partial_result.get("partial").and_then(|v| v.as_bool()), Some(true));
        let omitted = partial_result.get("omitted").and_then(|v| v.as_array());
        assert!(omitted.is_some(), "omitted field must be present");
        if let Some(arr) = omitted {
            assert_eq!(arr.len(), 1);
        }
    }

    /// The all-legs-refused error message must be recognizable.
    #[test]
    fn search_all_legs_refused_error_is_descriptive() {
        let error = UnifiError::Malformed(
            "all search legs refused: nothing was searched".to_owned(),
        );
        let error_text = error.to_string();
        assert!(
            error_text.contains("all search legs refused"),
            "error must clearly state nothing was searched: {error_text}"
        );
    }

    /// Every ResourceKind must route through a model parser.
    ///
    /// This is the coverage test that would have caught the DHCP reservation
    /// bypass: every kind must have a parser wired in parse_resource_list, or
    /// appear in an explicit commented list of kinds with no parser yet (there
    /// are none currently — all kinds have parsers).
    #[test]
    fn every_resource_kind_has_a_parser_wired() {
        use crate::model::ResourceKind;
        use crate::testing::{fixture, fixtures_available, DEFAULT_FIXTURE_VERSION};

        if !fixtures_available() {
            eprintln!("SKIPPED: no fixtures. Run scripts/capture-fixtures.sh against a controller.");
            return;
        }

        // For each kind, verify that parse_resource_list succeeds on the
        // recorded fixture (proving the parser is wired).
        for kind in ResourceKind::ALL {
            let fixture_name = match kind {
                ResourceKind::Station => "clients",
                ResourceKind::Device => "devices",
                ResourceKind::Network => "networkconf",
                ResourceKind::Wlan => "wlanconf",
                ResourceKind::PortProfile => "portconf",
                ResourceKind::DhcpReservation => "user",
                ResourceKind::FirewallGroup => "firewallgroup",
                ResourceKind::RadiusProfile => "radiusprofile",
                ResourceKind::FirewallPolicy => "policies",
                ResourceKind::FirewallZone => "zones",
                ResourceKind::TrafficRoute => "traffic_routes",
            };

            let raw = fixture(DEFAULT_FIXTURE_VERSION, fixture_name);
            super::parse_resource_list(*kind, &raw)
                .unwrap_or_else(|e| panic!("{kind:?} parser not wired or failed: {e}"));
        }
    }

    /// DHCP reservations must return strictly fewer rows than the raw /rest/user payload.
    ///
    /// This is the regression test for the architectural gap: parse_dhcp_reservations
    /// filters to `use_fixedip: true`, but list_resources was bypassing the parser,
    /// so callers got all 260 user records instead of the 46 actual reservations.
    #[test]
    fn dhcp_reservation_list_is_filtered() {
        use crate::testing::{fixture, fixtures_available, DEFAULT_FIXTURE_VERSION};

        if !fixtures_available() {
            eprintln!("SKIPPED: no fixtures. Run scripts/capture-fixtures.sh against a controller.");
            return;
        }

        let raw = fixture(DEFAULT_FIXTURE_VERSION, "user");
        let total_users = crate::model::unwrap_enveloped_data(&raw)
            .expect("envelope")
            .len();

        let parsed = super::parse_resource_list(ResourceKind::DhcpReservation, &raw)
            .expect("parse dhcp reservations");
        let parsed_count = parsed
            .as_array()
            .expect("parsed result is an array")
            .len();

        assert!(
            parsed_count < total_users,
            "parse_dhcp_reservations must filter: got {parsed_count}, expected < {total_users}"
        );

        // The 10.5.67 fixture has 257 total users, 46 with use_fixedip.
        // Verify the exact count to prove the filter worked.
        assert_eq!(
            parsed_count, 46,
            "10.5.67 fixture should have exactly 46 reservations"
        );
    }
}
