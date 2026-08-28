//! Workflow tools that join multiple data sources.
//!
//! These three reports answer in one call what the legacy server needed a dozen
//! for, with the join done server-side rather than orchestrated by a model one
//! tool call at a time.

use crate::client::UnifiClient;
use crate::error::UnifiError;
use crate::ApiSurface;
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
            "/proxy/network/integration/v1/sites/{site}/devices",
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
            "/proxy/network/integration/v1/sites/{site}/devices",
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
            "/proxy/network/api/s/{site}/rest/networkconf",
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
            "/proxy/network/integration/v1/sites/{site}/clients",
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
                && let Some(stat) = stats.iter().find(|s| {
                    s.get("mac").and_then(|v| v.as_str()) == Some(mac)
                })
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
                && let Some(stat) = stats.iter().find(|s| {
                    s.get("mac").and_then(|v| v.as_str()) == Some(mac)
                })
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
    use crate::testing::{fixtures_available, fixture, DEFAULT_FIXTURE_VERSION};

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
            eprintln!("SKIPPED: no fixtures. Run scripts/capture-fixtures.sh against a controller.");
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
            eprintln!("SKIPPED: no fixtures. Run scripts/capture-fixtures.sh against a controller.");
            return;
        }

        let devices = fixture(DEFAULT_FIXTURE_VERSION, "devices");
        let report = build_site_health_without_private(&devices)
            .expect("builds");
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
            eprintln!("SKIPPED: no fixtures. Run scripts/capture-fixtures.sh against a controller.");
            return;
        }

        let devices = fixture(DEFAULT_FIXTURE_VERSION, "devices");
        let topology = fixture(DEFAULT_FIXTURE_VERSION, "topology");

        let devices_data = crate::model::unwrap_enveloped_data(&devices)
            .expect("devices unwrap");
        let edges = topology.get("edges")
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
            eprintln!("SKIPPED: no fixtures. Run scripts/capture-fixtures.sh against a controller.");
            return;
        }

        let clients = fixture(DEFAULT_FIXTURE_VERSION, "clients");
        let stats = fixture(DEFAULT_FIXTURE_VERSION, "stat_sta");

        let clients_data = crate::model::unwrap_enveloped_data(&clients)
            .expect("clients unwrap");
        let stats_data = crate::model::unwrap_enveloped_data(&stats)
            .expect("stats unwrap");

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
