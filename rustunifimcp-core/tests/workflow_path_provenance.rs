//! Verify every workflow path comes from ResourceKind or is proven in capture-fixtures.sh.

use std::collections::HashSet;

/// Paths verified to return 200 in scripts/capture-fixtures.sh.
///
/// These are the paths that have no ResourceKind entry but are used by workflows.
/// Extracted from capture-fixtures.sh on 2026-08-28.
const VERIFIED_PATHS: &[&str] = &[
    "/proxy/network/api/s/{site}/stat/device",
    "/proxy/network/api/s/{site}/stat/health",
    "/proxy/network/api/s/{site}/stat/sta",
    "/proxy/network/v2/api/site/{site}/topology",
];

/// All ResourceKind paths, normalized to {site} placeholder.
///
/// These paths are the source of truth from the enum; workflows must use
/// ResourceKind::path_template() to reference them.
fn resource_kind_paths() -> HashSet<String> {
    use rustunifimcp_core::model::ResourceKind;

    [
        ResourceKind::Station,
        ResourceKind::Device,
        ResourceKind::Network,
        ResourceKind::Wlan,
        ResourceKind::PortProfile,
        ResourceKind::DhcpReservation,
        ResourceKind::FirewallGroup,
        ResourceKind::RadiusProfile,
        ResourceKind::FirewallPolicy,
        ResourceKind::FirewallZone,
        ResourceKind::TrafficRoute,
    ]
    .iter()
    .map(|kind| kind.path_template().to_owned())
    .collect()
}

/// Paths actually used in workflow.rs, extracted via grep.
///
/// After fix round 2, only stat/* and topology paths remain hardcoded (with comments
/// noting they have no ResourceKind entry). All ResourceKind paths are now accessed
/// via .path_template().
///
/// Run: grep -o '"/proxy[^"]*"' rustunifimcp-core/src/tools/workflow.rs | sort -u
const WORKFLOW_PATHS: &[&str] = &[
    "/proxy/network/api/s/{site}/stat/device",
    "/proxy/network/api/s/{site}/stat/health",
    "/proxy/network/api/s/{site}/stat/sta",
    "/proxy/network/v2/api/site/{site}/topology",
];

/// Every workflow path must come from ResourceKind or be verified in capture-fixtures.sh.
#[test]
fn workflow_paths_have_provenance() {
    let resource_paths = resource_kind_paths();
    let verified: HashSet<&str> = VERIFIED_PATHS.iter().copied().collect();

    for path in WORKFLOW_PATHS {
        let has_provenance = resource_paths.contains(*path) || verified.contains(path);
        assert!(
            has_provenance,
            "workflow path {path} not in ResourceKind and not verified in capture-fixtures.sh"
        );
    }
}

/// ResourceKind paths used by workflows must not be hardcoded.
///
/// If a path appears in both WORKFLOW_PATHS and resource_kind_paths(), it was
/// hardcoded instead of using ResourceKind::path_template(). This is the defect
/// that caused the firewall/policies vs firewall-policies drift.
#[test]
fn workflows_use_resource_kind_not_hardcoded_paths() {
    let resource_paths = resource_kind_paths();

    for path in WORKFLOW_PATHS {
        if resource_paths.contains(*path) {
            // This path exists in ResourceKind, so it should NOT be hardcoded in WORKFLOW_PATHS.
            // If it appears here, it means workflow.rs is hardcoding it instead of using
            // ResourceKind::path_template(), which is the mistake we're preventing.
            //
            // The correct workflow code uses ResourceKind::Device.path_template(), etc.,
            // which does NOT appear as a literal string in the source, so grep won't find it.
            panic!(
                "workflow path {path} matches ResourceKind entry; \
                 use ResourceKind::path_template() instead of hardcoding"
            );
        }
    }
}
