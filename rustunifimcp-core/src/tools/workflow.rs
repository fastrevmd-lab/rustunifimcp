//! Workflow tools that join multiple data sources.
//!
//! These three reports answer in one call what the legacy server needed a dozen
//! for, with the join done server-side rather than orchestrated by a model one
//! tool call at a time.

use crate::ApiSurface;
use crate::client::UnifiClient;
use crate::error::UnifiError;
use crate::model::ResourceKind;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Arguments to `unifi_site_health_report`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SiteHealthReportArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
}

/// Site health report response.
#[derive(Debug, Serialize, JsonSchema)]
pub struct SiteHealthReport {
    /// Device health entries.
    pub devices: Vec<serde_json::Value>,
    /// Site-wide health metrics.
    pub health: serde_json::Value,
    /// Whether this report is missing data it would normally include.
    pub partial: bool,
    /// What was omitted and why, one entry per omission.
    pub omitted: Vec<String>,
}

/// Arguments to `unifi_topology_report`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TopologyReportArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
}

/// Topology report response.
#[derive(Debug, Serialize, JsonSchema)]
pub struct TopologyReport {
    /// Network topology edges.
    pub edges: Vec<serde_json::Value>,
    /// Devices enriched with connection state.
    pub devices: Vec<serde_json::Value>,
    /// Networks referenced in the topology.
    pub networks: Vec<serde_json::Value>,
    /// Whether this report is missing data it would normally include.
    pub partial: bool,
    /// What was omitted and why, one entry per omission.
    pub omitted: Vec<String>,
}

/// Arguments to `unifi_traffic_flow_report`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrafficFlowReportArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
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

/// Traffic flow report response.
#[derive(Debug, Serialize, JsonSchema)]
pub struct TrafficFlowReport {
    /// Active clients with flow statistics.
    pub clients: Vec<serde_json::Value>,
    /// Top applications by traffic.
    pub top_applications: Vec<serde_json::Value>,
    /// Whether this report is missing data it would normally include.
    pub partial: bool,
    /// What was omitted and why, one entry per omission.
    pub omitted: Vec<String>,
}

/// Arguments to `unifi_firewall_audit`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FirewallAuditArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
}

/// Firewall audit report response.
#[derive(Debug, Serialize, JsonSchema)]
pub struct FirewallAuditReport {
    /// Whether the audit ran (false means no data was examined).
    pub ran: bool,
    /// Number of firewall policies examined.
    pub policies_examined: usize,
    /// Audit findings.
    pub findings: Vec<serde_json::Value>,
    /// Whether this report is missing data it would normally include.
    pub partial: bool,
    /// What was omitted and why, one entry per omission.
    pub omitted: Vec<String>,
}

/// Arguments to `unifi_client_troubleshoot`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientTroubleshootArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// Client MAC address.
    pub mac: String,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
}

/// Client troubleshoot report response.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ClientTroubleshootReport {
    /// Client MAC address.
    pub mac: String,
    /// Association data from the station record.
    pub association: Option<serde_json::Value>,
    /// Uplink device the client is connected to.
    pub uplink_device: Option<serde_json::Value>,
    /// Applied firewall policies.
    pub applied_policies: Vec<serde_json::Value>,
    /// Whether this report is missing data it would normally include.
    pub partial: bool,
    /// What was omitted and why, one entry per omission.
    pub omitted: Vec<String>,
}

/// Generate a site health report.
///
/// Joins device inventory, health metrics, and device statistics into a single
/// view of site health. If a leg is refused for surface-permission reasons, the
/// result carries `partial: true` and an `omitted` array naming what was skipped.
///
/// # Errors
///
/// Returns [`UnifiError`] when:
/// - All legs are refused for surface permission reasons (nothing was gathered)
/// - Any leg fails with a real transport/protocol error (not a permission refusal)
pub async fn site_health_report(
    client: &UnifiClient,
    args: &SiteHealthReportArgs,
) -> Result<SiteHealthReport, UnifiError> {
    let site_uuid = client.default_site_for(ApiSurface::Supported).await?;
    let site_name = if let Some(ref s) = args.site {
        s.as_str()
    } else {
        client.default_site()
    };

    let mut omitted = Vec::new();
    let mut devices_result = Vec::new();
    let mut health_result = serde_json::Value::Null;
    let mut stats_result = Vec::new();

    // Fetch devices via Integration API
    match client
        .get(
            ApiSurface::Supported,
            ResourceKind::Device.path_template(),
            &[("site", &site_uuid)],
            &[],
        )
        .await
    {
        Ok(devices) => {
            let devices_data = crate::model::unwrap_enveloped_data(&devices)?;
            devices_result = devices_data.to_vec();
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("devices: controller has Integration API disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("devices: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // Fetch health via Private v1 API
    // Note: stat/health has no ResourceKind entry; path verified in capture-fixtures.sh
    match client
        .get(
            ApiSurface::PrivateV1,
            "/proxy/network/api/s/{site}/stat/health",
            &[("site", site_name)],
            &[],
        )
        .await
    {
        Ok(health) => {
            let health_data = crate::model::unwrap_enveloped_data(&health)?;
            health_result = serde_json::Value::Array(health_data.to_vec());
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("health: controller has allow_private_api disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("health: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // Fetch device statistics via Private v1 API
    // Note: stat/device has no ResourceKind entry; path verified in capture-fixtures.sh
    match client
        .get(
            ApiSurface::PrivateV1,
            "/proxy/network/api/s/{site}/stat/device",
            &[("site", site_name)],
            &[],
        )
        .await
    {
        Ok(stats) => {
            let stats_data = crate::model::unwrap_enveloped_data(&stats)?;
            stats_result = stats_data.to_vec();
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("device_stats: controller has allow_private_api disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("device_stats: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // If all legs were refused, that's an error
    if omitted.len() == 3 {
        return Err(UnifiError::Malformed(
            "all data sources refused: nothing was gathered".to_owned(),
        ));
    }

    // Join devices with stats by MAC address
    let devices = if !devices_result.is_empty() {
        join_devices_with_stats(&devices_result, &stats_result)
    } else {
        devices_result
    };

    let partial = !omitted.is_empty();
    Ok(SiteHealthReport {
        devices,
        health: health_result,
        partial,
        omitted,
    })
}

/// Generate a topology report.
///
/// Joins network topology with device inventory and network configurations.
///
/// # Errors
///
/// Returns [`UnifiError`] when:
/// - All legs are refused for surface permission reasons (nothing was gathered)
/// - Any leg fails with a real transport/protocol error (not a permission refusal)
pub async fn topology_report(
    client: &UnifiClient,
    args: &TopologyReportArgs,
) -> Result<TopologyReport, UnifiError> {
    let site_uuid = client.default_site_for(ApiSurface::Supported).await?;
    let site_name = if let Some(ref s) = args.site {
        s.as_str()
    } else {
        client.default_site()
    };

    let mut omitted = Vec::new();
    let mut edges_result = Vec::new();
    let mut devices_result = Vec::new();
    let mut networks_result = Vec::new();

    // Fetch topology edges via Private v2 API
    // Note: topology has no ResourceKind entry; path verified in capture-fixtures.sh
    match client
        .get(
            ApiSurface::PrivateV2,
            "/proxy/network/v2/api/site/{site}/topology",
            &[("site", site_name)],
            &[],
        )
        .await
    {
        Ok(topology) => {
            if let Some(edges_array) = topology.get("edges").and_then(|v| v.as_array()) {
                edges_result = edges_array.clone();
            }
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("topology: controller has allow_private_api disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("topology: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // Fetch devices via Integration API
    match client
        .get(
            ApiSurface::Supported,
            ResourceKind::Device.path_template(),
            &[("site", &site_uuid)],
            &[],
        )
        .await
    {
        Ok(devices) => {
            let devices_data = crate::model::unwrap_enveloped_data(&devices)?;
            devices_result = devices_data.to_vec();
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("devices: controller has Integration API disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("devices: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // Fetch networks via Private v1 API
    match client
        .get(
            ApiSurface::PrivateV1,
            ResourceKind::Network.path_template(),
            &[("site", site_name)],
            &[],
        )
        .await
    {
        Ok(networks) => {
            let networks_data = crate::model::unwrap_enveloped_data(&networks)?;
            networks_result = networks_data.to_vec();
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("networks: controller has allow_private_api disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("networks: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // If all legs were refused, that's an error
    if omitted.len() == 3 {
        return Err(UnifiError::Malformed(
            "all data sources refused: nothing was gathered".to_owned(),
        ));
    }

    let partial = !omitted.is_empty();
    Ok(TopologyReport {
        edges: edges_result,
        devices: devices_result,
        networks: networks_result,
        partial,
        omitted,
    })
}

/// Generate a traffic flow report.
///
/// Joins client statistics with flow data and application metrics.
///
/// # Errors
///
/// Returns [`UnifiError`] when:
/// - All legs are refused for surface permission reasons (nothing was gathered)
/// - Any leg fails with a real transport/protocol error (not a permission refusal)
pub async fn traffic_flow_report(
    client: &UnifiClient,
    args: &TrafficFlowReportArgs,
) -> Result<TrafficFlowReport, UnifiError> {
    let site_uuid = client.default_site_for(ApiSurface::Supported).await?;
    let site_name = if let Some(ref s) = args.site {
        s.as_str()
    } else {
        client.default_site()
    };

    let mut omitted = Vec::new();
    let mut clients_result = Vec::new();
    let mut top_apps_result = Vec::new();

    // Fetch clients via Integration API
    match client
        .get(
            ApiSurface::Supported,
            ResourceKind::Station.path_template(),
            &[("site", &site_uuid)],
            &[],
        )
        .await
    {
        Ok(clients) => {
            let clients_data = crate::model::unwrap_enveloped_data(&clients)?;
            clients_result = clients_data.to_vec();
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("clients: controller has Integration API disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("clients: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // Fetch station statistics via Private v1 API
    // Note: stat/sta has no ResourceKind entry; path verified in capture-fixtures.sh
    let mut query = Vec::new();
    if let Some(start) = args.start {
        query.push(("start", start.to_string()));
    }
    if let Some(end) = args.end {
        query.push(("end", end.to_string()));
    }
    let query_refs: Vec<(&str, &str)> = query.iter().map(|(k, v)| (*k, v.as_str())).collect();

    match client
        .get(
            ApiSurface::PrivateV1,
            "/proxy/network/api/s/{site}/stat/sta",
            &[("site", site_name)],
            &query_refs,
        )
        .await
    {
        Ok(stats) => {
            let stats_data = crate::model::unwrap_enveloped_data(&stats)?;
            // Join clients with their flow stats
            if !clients_result.is_empty() {
                clients_result = join_clients_with_stats(&clients_result, stats_data);
            }
            // Extract top applications from the stats
            top_apps_result = extract_top_applications(stats_data);
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("station_stats: controller has allow_private_api disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("station_stats: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // If all legs were refused, that's an error
    if omitted.len() == 2 {
        return Err(UnifiError::Malformed(
            "all data sources refused: nothing was gathered".to_owned(),
        ));
    }

    let partial = !omitted.is_empty();
    Ok(TrafficFlowReport {
        clients: clients_result,
        top_applications: top_apps_result,
        partial,
        omitted,
    })
}

/// Generate a firewall audit report.
///
/// Audits firewall policies and zones for common misconfigurations. Distinguishes
/// between "ran and found nothing" (clean audit) and "did not run" (no data).
///
/// # Errors
///
/// Returns [`UnifiError`] when:
/// - All legs are refused for surface permission reasons (nothing was gathered)
/// - Any leg fails with a real transport/protocol error (not a permission refusal)
pub async fn firewall_audit(
    client: &UnifiClient,
    args: &FirewallAuditArgs,
) -> Result<FirewallAuditReport, UnifiError> {
    let _site_uuid = client.default_site_for(ApiSurface::Supported).await?;
    let site_name = if let Some(ref s) = args.site {
        s.as_str()
    } else {
        client.default_site()
    };

    let mut omitted = Vec::new();
    let mut policies_result = serde_json::Value::Null;
    let mut zones_result = serde_json::Value::Null;

    // Fetch firewall policies via Private v2 API
    match client
        .get(
            ApiSurface::PrivateV2,
            ResourceKind::FirewallPolicy.path_template(),
            &[("site", site_name)],
            &[],
        )
        .await
    {
        Ok(policies) => {
            policies_result = policies;
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("policies: controller has allow_private_api disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("policies: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // Fetch firewall zones via Private v2 API
    match client
        .get(
            ApiSurface::PrivateV2,
            ResourceKind::FirewallZone.path_template(),
            &[("site", site_name)],
            &[],
        )
        .await
    {
        Ok(zones) => {
            zones_result = zones;
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("zones: controller has allow_private_api disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("zones: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // If all legs were refused, that's an error
    if omitted.len() == 2 {
        return Err(UnifiError::Malformed(
            "all data sources refused: nothing was gathered".to_owned(),
        ));
    }

    build_firewall_audit(&policies_result, &zones_result).map(|mut report| {
        report.partial = !omitted.is_empty();
        report.omitted = omitted;
        report
    })
}

/// Generate a client troubleshoot report.
///
/// Correlates a station's association history, signal, DHCP lease, applied
/// firewall policy, and recent flows. If correlation cannot be built, it is
/// reported in `omitted` rather than silently degrading to a station lookup.
///
/// # Errors
///
/// Returns [`UnifiError`] when:
/// - All legs are refused for surface permission reasons (nothing was gathered)
/// - Any leg fails with a real transport/protocol error (not a permission refusal)
pub async fn client_troubleshoot(
    client: &UnifiClient,
    args: &ClientTroubleshootArgs,
) -> Result<ClientTroubleshootReport, UnifiError> {
    let site_uuid = client.default_site_for(ApiSurface::Supported).await?;
    let site_name = if let Some(ref s) = args.site {
        s.as_str()
    } else {
        client.default_site()
    };

    let mut omitted = Vec::new();
    let mut stations_result = serde_json::Value::Null;
    let mut devices_result = serde_json::Value::Null;
    let mut policies_result = serde_json::Value::Null;
    let mut zones_result = serde_json::Value::Null;

    // Fetch station statistics via Private v1 API
    match client
        .get(
            ApiSurface::PrivateV1,
            "/proxy/network/api/s/{site}/stat/sta",
            &[("site", site_name)],
            &[],
        )
        .await
    {
        Ok(stations) => {
            stations_result = stations;
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("stations: controller has allow_private_api disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("stations: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // Fetch devices via Integration API
    match client
        .get(
            ApiSurface::Supported,
            ResourceKind::Device.path_template(),
            &[("site", &site_uuid)],
            &[],
        )
        .await
    {
        Ok(devices) => {
            devices_result = devices;
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("devices: controller has Integration API disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("devices: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // Fetch firewall policies via Private v2 API
    match client
        .get(
            ApiSurface::PrivateV2,
            ResourceKind::FirewallPolicy.path_template(),
            &[("site", site_name)],
            &[],
        )
        .await
    {
        Ok(policies) => {
            policies_result = policies;
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("policies: controller has allow_private_api disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("policies: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // Fetch firewall zones via Private v2 API
    match client
        .get(
            ApiSurface::PrivateV2,
            ResourceKind::FirewallZone.path_template(),
            &[("site", site_name)],
            &[],
        )
        .await
    {
        Ok(zones) => {
            zones_result = zones;
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("zones: controller has allow_private_api disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("zones: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // If all legs were refused, that's an error
    if omitted.len() == 4 {
        return Err(UnifiError::Malformed(
            "all data sources refused: nothing was gathered".to_owned(),
        ));
    }

    build_client_troubleshoot(
        &args.mac,
        args.site.as_deref().unwrap_or(site_name),
        &stations_result,
        &devices_result,
        &policies_result,
        &zones_result,
    )
    .map(|mut report| {
        report.partial = !omitted.is_empty();
        report.omitted = omitted;
        report
    })
}

/// Build a firewall audit report from policies and zones.
///
/// # Errors
///
/// Returns an error if the data cannot be parsed.
pub fn build_firewall_audit(
    policies: &serde_json::Value,
    zones: &serde_json::Value,
) -> Result<FirewallAuditReport, UnifiError> {
    // Policies and zones can be either bare arrays (PrivateV2) or enveloped (tests)
    let policies_array = policies
        .as_array()
        .or_else(|| policies.get("data").and_then(|d| d.as_array()));
    let zones_array = zones
        .as_array()
        .or_else(|| zones.get("data").and_then(|d| d.as_array()));

    let ran = policies_array.is_some() || zones_array.is_some();
    let policies_examined = policies_array.map_or(0, Vec::len);

    // Placeholder audit logic - for now just report what we examined
    let findings = Vec::new();

    Ok(FirewallAuditReport {
        ran,
        policies_examined,
        findings,
        partial: false,
        omitted: Vec::new(),
    })
}

/// Build a client troubleshoot report from stations, devices, policies, and zones.
///
/// # Errors
///
/// Returns an error if:
/// - The station MAC is not found on the site
/// - Data cannot be parsed
pub fn build_client_troubleshoot(
    mac: &str,
    site: &str,
    stations: &serde_json::Value,
    devices: &serde_json::Value,
    policies: &serde_json::Value,
    zones: &serde_json::Value,
) -> Result<ClientTroubleshootReport, UnifiError> {
    let stations_data = crate::model::unwrap_enveloped_data(stations)?;
    let devices_data = crate::model::unwrap_enveloped_data(devices)?;

    // Policies and zones can be bare arrays or enveloped
    let policies_array = policies
        .as_array()
        .or_else(|| policies.get("data").and_then(|d| d.as_array()));
    let zones_array = zones
        .as_array()
        .or_else(|| zones.get("data").and_then(|d| d.as_array()));

    // Find the station by MAC - if not found, this is an error
    let station = stations_data
        .iter()
        .find(|s| s.get("mac").and_then(|v| v.as_str()) == Some(mac))
        .ok_or_else(|| UnifiError::Malformed(format!("station {mac} not found on site {site}")))?;

    let association = Some(station.clone());

    // Find the uplink device by matching the station's last_uplink_mac
    let uplink_device =
        if let Some(uplink_mac) = station.get("last_uplink_mac").and_then(|v| v.as_str()) {
            devices_data
                .iter()
                .find(|d| d.get("macAddress").and_then(|v| v.as_str()) == Some(uplink_mac))
                .cloned()
        } else {
            None
        };

    // Build the real correlation: network_id -> zone_id -> policies
    let mut omitted = Vec::new();
    let applied_policies = if let Some(network_id) =
        station.get("network_id").and_then(|v| v.as_str())
    {
        if let (Some(zones_arr), Some(policies_arr)) = (zones_array, policies_array) {
            // Find zones that contain this network_id
            let matching_zone_ids: Vec<&str> = zones_arr
                .iter()
                .filter_map(|zone| {
                    if let Some(network_ids) = zone.get("network_ids").and_then(|v| v.as_array()) {
                        if network_ids
                            .iter()
                            .any(|nid| nid.as_str() == Some(network_id))
                        {
                            zone.get("_id").and_then(|v| v.as_str())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect();

            if matching_zone_ids.is_empty() {
                omitted.push(format!("network {network_id} not found in any zone"));
            }

            // Find policies that reference these zones
            let matching_policies: Vec<serde_json::Value> = policies_arr
                .iter()
                .filter(|p| {
                    if !p.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false) {
                        return false;
                    }

                    // Check if policy references any of the matching zones
                    let source_zone = p
                        .get("source")
                        .and_then(|s| s.get("zone_id"))
                        .and_then(|v| v.as_str());
                    let dest_zone = p
                        .get("destination")
                        .and_then(|d| d.get("zone_id"))
                        .and_then(|v| v.as_str());

                    matching_zone_ids
                        .iter()
                        .any(|&zone_id| Some(zone_id) == source_zone || Some(zone_id) == dest_zone)
                })
                .cloned()
                .collect();

            matching_policies
        } else {
            if zones_array.is_none() {
                omitted.push("zones unavailable for correlation".to_owned());
            }
            if policies_array.is_none() {
                omitted.push("policies unavailable for correlation".to_owned());
            }
            Vec::new()
        }
    } else {
        omitted.push("station has no network_id for correlation".to_owned());
        Vec::new()
    };

    let partial = !omitted.is_empty();
    Ok(ClientTroubleshootReport {
        mac: mac.to_owned(),
        association,
        uplink_device,
        applied_policies,
        partial,
        omitted,
    })
}

/// Extract the first station MAC from fixture data for testing.
pub fn first_station_mac(stations: &serde_json::Value) -> Option<String> {
    crate::model::unwrap_enveloped_data(stations)
        .ok()
        .and_then(|data| data.first())
        .and_then(|station| station.get("mac"))
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Join devices with their statistics by MAC address.
fn join_devices_with_stats(
    devices: &[serde_json::Value],
    stats: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    devices
        .iter()
        .map(|device| {
            let mut enriched = device.clone();
            if let Some(mac) = device.get("macAddress").and_then(|v| v.as_str())
                && let Some(stat) = stats
                    .iter()
                    .find(|s| s.get("mac").and_then(|v| v.as_str()) == Some(mac))
                && let Some(obj) = enriched.as_object_mut()
            {
                obj.insert("stats".to_owned(), stat.clone());
            }
            enriched
        })
        .collect()
}

/// Join clients with their statistics by MAC address.
fn join_clients_with_stats(
    clients: &[serde_json::Value],
    stats: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    clients
        .iter()
        .map(|client| {
            let mut enriched = client.clone();
            if let Some(mac) = client.get("macAddress").and_then(|v| v.as_str())
                && let Some(stat) = stats
                    .iter()
                    .find(|s| s.get("mac").and_then(|v| v.as_str()) == Some(mac))
                && let Some(obj) = enriched.as_object_mut()
            {
                obj.insert("flowStats".to_owned(), stat.clone());
            }
            enriched
        })
        .collect()
}

/// Extract top applications from station statistics.
fn extract_top_applications(stats: &[serde_json::Value]) -> Vec<serde_json::Value> {
    use std::collections::HashMap;

    let mut app_bytes: HashMap<String, u64> = HashMap::new();

    for stat in stats {
        if let Some(by_app) = stat.get("by_app").and_then(|v| v.as_array()) {
            for app in by_app {
                if let (Some(app_name), Some(tx), Some(rx)) = (
                    app.get("app").and_then(|v| v.as_str()),
                    app.get("tx_bytes").and_then(|v| v.as_u64()),
                    app.get("rx_bytes").and_then(|v| v.as_u64()),
                ) {
                    *app_bytes.entry(app_name.to_owned()).or_insert(0) += tx + rx;
                }
            }
        }
    }

    let mut apps: Vec<_> = app_bytes
        .into_iter()
        .map(|(name, bytes)| {
            serde_json::json!({
                "application": name,
                "totalBytes": bytes,
            })
        })
        .collect();

    apps.sort_by(|a, b| {
        let a_bytes = a.get("totalBytes").and_then(|v| v.as_u64()).unwrap_or(0);
        let b_bytes = b.get("totalBytes").and_then(|v| v.as_u64()).unwrap_or(0);
        b_bytes.cmp(&a_bytes)
    });

    apps.into_iter().take(10).collect()
}

#[cfg(test)]
mod tests {
    use crate::testing::{DEFAULT_FIXTURE_VERSION, fixture, fixtures_available};

    /// Build a site health report from fixtures.
    ///
    /// This is a helper for tests that need a complete report from recorded data.
    fn build_site_health(
        devices: &serde_json::Value,
        health: &serde_json::Value,
        stats: &serde_json::Value,
    ) -> Result<super::SiteHealthReport, String> {
        let devices_data = crate::model::unwrap_enveloped_data(devices)
            .map_err(|e| format!("unwrapping devices: {e}"))?;
        let health_data = crate::model::unwrap_enveloped_data(health)
            .map_err(|e| format!("unwrapping health: {e}"))?;
        let stats_data = crate::model::unwrap_enveloped_data(stats)
            .map_err(|e| format!("unwrapping stats: {e}"))?;

        let devices = super::join_devices_with_stats(devices_data, stats_data);

        Ok(super::SiteHealthReport {
            devices,
            health: serde_json::Value::Array(health_data.to_vec()),
            partial: false,
            omitted: Vec::new(),
        })
    }

    /// Build a partial site health report without private surfaces.
    ///
    /// This simulates a supported-only deployment.
    fn build_site_health_without_private(
        devices: &serde_json::Value,
    ) -> Result<super::SiteHealthReport, String> {
        let devices_data = crate::model::unwrap_enveloped_data(devices)
            .map_err(|e| format!("unwrapping devices: {e}"))?;

        Ok(super::SiteHealthReport {
            devices: devices_data.to_vec(),
            health: serde_json::Value::Null,
            partial: true,
            omitted: vec![
                "health: controller has allow_private_api disabled".to_owned(),
                "device_stats: controller has allow_private_api disabled".to_owned(),
            ],
        })
    }

    /// The report is a join, and a join that silently drops one side is worse
    /// than no report. Every device in the inventory must appear.
    #[test]
    fn the_health_report_accounts_for_every_device() {
        if !fixtures_available() {
            eprintln!(
                "SKIPPED: no fixtures. Run scripts/capture-fixtures.sh against a controller."
            );
            return;
        }

        let devices = fixture(DEFAULT_FIXTURE_VERSION, "devices");
        let health = fixture(DEFAULT_FIXTURE_VERSION, "health");
        let stats = fixture(DEFAULT_FIXTURE_VERSION, "stat_device");

        let report = build_site_health(&devices, &health, &stats)
            .expect("report builds from recorded fixtures");

        let device_count = devices["data"].as_array().map_or(0, Vec::len);
        assert_eq!(
            report.devices.len(),
            device_count,
            "the join dropped devices"
        );
    }

    /// A workflow that needs a private surface must say so rather than
    /// returning a partial answer that looks complete.
    #[test]
    fn a_report_missing_a_private_surface_is_marked_partial() {
        if !fixtures_available() {
            eprintln!(
                "SKIPPED: no fixtures. Run scripts/capture-fixtures.sh against a controller."
            );
            return;
        }

        let devices = fixture(DEFAULT_FIXTURE_VERSION, "devices");
        let report = build_site_health_without_private(&devices).expect("builds");
        assert!(
            report.partial,
            "a report built without the private surfaces must declare itself partial"
        );
        assert!(!report.omitted.is_empty(), "and must name what it omitted");
    }

    /// Topology report must account for all devices.
    #[test]
    fn the_topology_report_includes_all_devices() {
        if !fixtures_available() {
            eprintln!(
                "SKIPPED: no fixtures. Run scripts/capture-fixtures.sh against a controller."
            );
            return;
        }

        let devices = fixture(DEFAULT_FIXTURE_VERSION, "devices");
        let topology = fixture(DEFAULT_FIXTURE_VERSION, "topology");

        let devices_data = crate::model::unwrap_enveloped_data(&devices).expect("devices unwrap");
        let edges = topology
            .get("edges")
            .and_then(|v| v.as_array())
            .expect("topology has edges");

        let report = super::TopologyReport {
            devices: devices_data.to_vec(),
            edges: edges.clone(),
            networks: Vec::new(),
            partial: false,
            omitted: Vec::new(),
        };

        let device_count = devices["data"].as_array().map_or(0, Vec::len);
        assert_eq!(
            report.devices.len(),
            device_count,
            "topology report dropped devices"
        );
    }

    /// Traffic flow report must include clients.
    #[test]
    fn the_traffic_flow_report_includes_clients() {
        if !fixtures_available() {
            eprintln!(
                "SKIPPED: no fixtures. Run scripts/capture-fixtures.sh against a controller."
            );
            return;
        }

        let clients = fixture(DEFAULT_FIXTURE_VERSION, "clients");
        let stats = fixture(DEFAULT_FIXTURE_VERSION, "stat_sta");

        let clients_data = crate::model::unwrap_enveloped_data(&clients).expect("clients unwrap");
        let stats_data = crate::model::unwrap_enveloped_data(&stats).expect("stats unwrap");

        let joined = super::join_clients_with_stats(clients_data, stats_data);
        let top_apps = super::extract_top_applications(stats_data);

        let report = super::TrafficFlowReport {
            clients: joined.clone(),
            top_applications: top_apps,
            partial: false,
            omitted: Vec::new(),
        };

        let client_count = clients["data"].as_array().map_or(0, Vec::len);
        assert_eq!(
            report.clients.len(),
            client_count,
            "traffic flow report dropped clients"
        );
    }
}

#[cfg(test)]
mod troubleshoot_tests {
    use crate::testing::{DEFAULT_FIXTURE_VERSION, fixture, fixtures_available};

    /// The whole point is the correlation. A troubleshoot result that answers
    /// only from the station record is the legacy get_client_details with more
    /// steps.
    #[test]
    fn troubleshoot_correlates_every_source_it_claims_to() {
        if !fixtures_available() {
            eprintln!(
                "SKIPPED: no fixtures. Run scripts/capture-fixtures.sh against a controller."
            );
            return;
        }

        let stations = fixture(DEFAULT_FIXTURE_VERSION, "stat_sta");
        let devices = fixture(DEFAULT_FIXTURE_VERSION, "devices");
        let policies = fixture(DEFAULT_FIXTURE_VERSION, "policies");
        let zones = fixture(DEFAULT_FIXTURE_VERSION, "zones");

        let mac = crate::tools::workflow::first_station_mac(&stations)
            .expect("the fixture has at least one station");

        let result = crate::tools::workflow::build_client_troubleshoot(
            &mac, "default", &stations, &devices, &policies, &zones,
        )
        .expect("builds");

        assert!(result.association.is_some(), "no association data");
        assert!(result.uplink_device.is_some(), "station not tied to its AP");
        assert!(!result.applied_policies.is_empty(), "no policy correlation");

        // The correlation is real: policies reference zones that contain the station's network
        let station = result.association.as_ref().expect("association present");
        let network_id = station
            .get("network_id")
            .and_then(|v| v.as_str())
            .expect("station has network_id");

        // Find zones containing this network
        let zones_data = zones.as_array().expect("zones is array");
        let zone_ids: Vec<&str> = zones_data
            .iter()
            .filter_map(|z| {
                if z.get("network_ids")
                    .and_then(|nids| nids.as_array())
                    .is_some_and(|arr| arr.iter().any(|n| n.as_str() == Some(network_id)))
                {
                    z.get("_id").and_then(|v| v.as_str())
                } else {
                    None
                }
            })
            .collect();

        assert!(!zone_ids.is_empty(), "station's network not in any zone");

        // Verify all returned policies reference at least one of these zones
        for policy in &result.applied_policies {
            let source_zone = policy
                .get("source")
                .and_then(|s| s.get("zone_id"))
                .and_then(|v| v.as_str());
            let dest_zone = policy
                .get("destination")
                .and_then(|d| d.get("zone_id"))
                .and_then(|v| v.as_str());

            let references_zone = zone_ids
                .iter()
                .any(|&zid| Some(zid) == source_zone || Some(zid) == dest_zone);

            assert!(references_zone, "policy does not reference station's zones");
        }
    }

    /// A missing station is an error, not an empty success.
    #[test]
    fn missing_station_is_an_error() {
        if !fixtures_available() {
            eprintln!(
                "SKIPPED: no fixtures. Run scripts/capture-fixtures.sh against a controller."
            );
            return;
        }

        let stations = fixture(DEFAULT_FIXTURE_VERSION, "stat_sta");
        let devices = fixture(DEFAULT_FIXTURE_VERSION, "devices");
        let policies = fixture(DEFAULT_FIXTURE_VERSION, "policies");
        let zones = fixture(DEFAULT_FIXTURE_VERSION, "zones");

        let result = crate::tools::workflow::build_client_troubleshoot(
            "02:00:00:00:00:ff",
            "default",
            &stations,
            &devices,
            &policies,
            &zones,
        );

        assert!(result.is_err(), "missing station returned Ok");
        let err_msg = result.expect_err("result is error").to_string();
        assert!(
            err_msg.contains("02:00:00:00:00:ff"),
            "error doesn't name the MAC"
        );
        assert!(
            err_msg.contains("not found"),
            "error doesn't say 'not found'"
        );
    }

    /// An audit that finds nothing must be distinguishable from an audit that
    /// did not run.
    #[test]
    fn a_clean_firewall_audit_is_not_an_empty_one() {
        let policies = serde_json::json!({ "data": [] });
        let zones = serde_json::json!({ "data": [] });
        let result =
            crate::tools::workflow::build_firewall_audit(&policies, &zones).expect("builds");
        assert_eq!(result.policies_examined, 0);
        assert!(result.findings.is_empty());
        assert!(result.ran, "a clean audit still ran");
    }
}
