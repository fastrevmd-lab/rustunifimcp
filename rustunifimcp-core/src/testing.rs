//! Test helpers for loading recorded controller responses.
//!
//! Fixtures are recorded per controller version by `scripts/capture-fixtures.sh`
//! and committed scrubbed. Tests read them instead of reaching the network, so
//! the model and client layers are exercised with no controller present.

use std::path::PathBuf;

/// The controller version whose fixtures the unit tests default to.
///
/// The version matrix in `tests/version_matrix.rs` deliberately reads others.
pub const DEFAULT_FIXTURE_VERSION: &str = "10.5.67";

/// Whether any recorded fixtures are present in this checkout.
///
/// Fixtures are captured from a live controller and are deliberately not
/// committed, so a fresh clone has none. Tests that need them skip rather than
/// fail — a missing fixture is an un-run test, never a passing one.
#[must_use]
pub fn fixtures_available() -> bool {
    let fixtures_dir: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "fixtures"]
        .iter()
        .collect();

    std::fs::read_dir(fixtures_dir)
        .ok()
        .and_then(|entries| {
            entries
                .filter_map(Result::ok)
                .any(|entry| entry.path().is_dir())
                .then_some(())
        })
        .is_some()
}

/// Load a recorded controller response.
///
/// # Panics
///
/// Panics if the fixture is absent or is not valid JSON. Both are test-authoring
/// errors, and a panic naming the path is the fastest way to fix them.
#[must_use]
pub fn fixture(version: &str, name: &str) -> serde_json::Value {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "fixtures",
        version,
        &format!("{name}.json"),
    ]
    .iter()
    .collect();

    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("no fixture at {}: {error}", path.display()));

    serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("fixture {} is not JSON: {error}", path.display()))
}

/// Whether an endpoint was recorded as absent on this controller version.
///
/// `capture-fixtures.sh` writes a `.absent` marker when a route 404s, so the
/// version matrix can assert absence as a fact rather than inferring it from a
/// missing file.
#[must_use]
pub fn is_absent(version: &str, name: &str) -> bool {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "fixtures",
        version,
        &format!("{name}.absent"),
    ]
    .iter()
    .collect();
    path.exists()
}

#[cfg(test)]
mod tests {
    use super::{fixture, fixtures_available};

    #[test]
    fn loads_a_recorded_sites_response() {
        if !fixtures_available() {
            eprintln!(
                "SKIPPED: no fixtures. Run scripts/capture-fixtures.sh against a controller."
            );
            return;
        }
        let value = fixture(super::DEFAULT_FIXTURE_VERSION, "sites");
        assert!(value.is_object() || value.is_array());
    }

    #[test]
    #[should_panic(expected = "no fixture")]
    fn a_missing_fixture_panics_with_the_path_it_looked_for() {
        let _ = fixture(super::DEFAULT_FIXTURE_VERSION, "no_such_endpoint");
    }
}
