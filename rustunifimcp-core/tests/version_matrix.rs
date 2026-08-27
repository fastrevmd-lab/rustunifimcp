//! Which endpoints exist on which controller version.
//!
//! This is where private-API drift is caught, and it is the reason every
//! endpoint carries a surface tag. A private route that disappears in a
//! controller upgrade should fail here, in CI, rather than in a tool call at
//! 03:00.

use rustunifimcp_core::model::ResourceKind;
use rustunifimcp_core::testing::{fixtures_available, is_absent};
use rustunifimcp_core::version::{endpoint_availability, Availability};

/// Every version directory under tests/fixtures/.
fn recorded_versions() -> Vec<String> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
    std::fs::read_dir(dir)
        .expect("fixtures directory exists")
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect()
}

#[test]
#[ignore = "Phase 1 exit criterion: needs a second controller version captured. Only 10.5.67 exists; capture the next UniFi OS upgrade with scripts/capture-fixtures.sh and remove this attribute."]
fn at_least_two_controller_versions_are_recorded() {
    let versions = recorded_versions();
    assert!(
        versions.len() >= 2,
        "the matrix cannot distinguish versions with only {versions:?}; \
         Phase 1's exit criterion is two"
    );
}

#[test]
fn the_matrix_agrees_with_what_was_recorded() {
    if !fixtures_available() {
        eprintln!("SKIPPED: no fixtures. Run scripts/capture-fixtures.sh against a controller.");
        return;
    }
    for version in recorded_versions() {
        for kind in ResourceKind::ALL {
            let fixture_name = kind_fixture_name(*kind);
            let recorded_absent = is_absent(&version, fixture_name);
            let availability = endpoint_availability(&version, *kind);

            let expected = if recorded_absent {
                Availability::Absent
            } else {
                Availability::Present
            };

            assert_eq!(
                availability, expected,
                "matrix and fixtures disagree for {kind:?} on {version}: \
                 recorded_absent={recorded_absent}, matrix={availability:?}"
            );
        }
    }
}

#[test]
fn unrecorded_versions_return_unrecorded_for_private_endpoints() {
    let unrecorded_version = "99.9.9";

    // Supported API endpoints are always Present
    for kind in ResourceKind::ALL {
        if kind.surface() == rustunifimcp_core::ApiSurface::Supported {
            assert_eq!(
                endpoint_availability(unrecorded_version, *kind),
                Availability::Present,
                "Supported endpoint {kind:?} should be Present even on unrecorded version"
            );
        } else {
            assert_eq!(
                endpoint_availability(unrecorded_version, *kind),
                Availability::Unrecorded,
                "Private endpoint {kind:?} should be Unrecorded on unrecorded version"
            );
        }
    }
}

/// Map a kind to the fixture basename `capture-fixtures.sh` wrote.
fn kind_fixture_name(kind: ResourceKind) -> &'static str {
    match kind {
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
        _ => unreachable!("all known ResourceKind variants are covered"),
    }
}
