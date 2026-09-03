//! Tests for the fixture scrubbing verification gate.
//!
//! Ensures the scrub gate passes on verified-clean fixtures and fails on each
//! category of sensitive data that has leaked in the past.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use rustunifimcp_core::testing::{
    SYNTHETIC_FIXTURE_VERSION, recorded_fixtures_available, recorded_versions,
};

/// Path to the verification script relative to workspace root.
const GATE_SCRIPT: &str = "scripts/verify-fixtures-scrubbed.sh";

/// The fixture directory for one recorded or synthetic version.
fn fixture_dir(version: &str) -> String {
    format!("rustunifimcp-core/tests/fixtures/{version}")
}

/// Get workspace root by walking up from the test binary location.
fn workspace_root() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // rustunifimcp-core -> rustunifimcp
    path
}

/// Run the scrub gate on a directory.
///
/// Returns (exit_code, stdout, stderr).
fn run_gate(fixture_dir: &str) -> (i32, String, String) {
    let root = workspace_root();
    let script = root.join(GATE_SCRIPT);
    let dir = root.join(fixture_dir);

    let output = Command::new(&script)
        .arg(dir)
        .env("ALLOW_MISSING_DENYLIST", "1") // Tests use synthetic data, no denylist needed
        .output()
        .expect("failed to execute gate script");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);

    (code, stdout, stderr)
}

#[test]
fn gate_passes_on_verified_clean_fixtures() {
    // Self-contained test: create a small known-clean fixture set
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");

    // Create a minimal clean fixture
    let clean_fixture = r#"{
        "_id": "507f1f77bcf86cd799439011deadbeef",
        "site_id": "1234567890abcdef1234567890abcdef",
        "name": "test-site",
        "ip": "192.0.2.1",
        "ipv6": "2001:db8::1",
        "dns": "8.8.8.8",
        "mac": "02:00:00:11:22:33",
        "lat": 0.0,
        "lng": 0.0
    }"#;

    fs::write(temp_dir.path().join("test.json"), clean_fixture)
        .expect("failed to write clean fixture");

    let (code, stdout, stderr) = run_gate(
        temp_dir
            .path()
            .to_str()
            .expect("temp dir path is valid UTF-8"),
    );

    assert_eq!(
        code, 0,
        "Gate should pass on verified-clean fixtures.\nstdout: {}\nstderr: {}",
        stdout, stderr
    );

    // Success output should report files and values checked
    assert!(
        stdout.contains("files") && stdout.contains("values checked"),
        "Success output should report scan summary: {}",
        stdout
    );
}

#[test]
fn gate_passes_on_live_fixtures_when_available() {
    // Optional test: verify against the real fixture sets if present.
    if !recorded_fixtures_available() {
        eprintln!(
            "SKIPPED: no live fixtures. Run scripts/capture-fixtures.sh against a controller."
        );
        return;
    }

    for version in recorded_versions() {
        let (code, stdout, stderr) = run_gate(&fixture_dir(&version));

        assert_eq!(
            code, 0,
            "Gate should pass on live verified-clean fixtures for {version}.\n\
             stdout: {stdout}\nstderr: {stderr}"
        );
    }
}

/// The synthetic set is committed to a public repo, so the gate has to hold on
/// it in every run -- not only when a developer happens to have a live capture.
/// This is the check that makes committing fixtures safe rather than hopeful.
#[test]
fn gate_passes_on_the_committed_synthetic_fixtures() {
    let (code, stdout, stderr) = run_gate(&fixture_dir(SYNTHETIC_FIXTURE_VERSION));

    assert_eq!(
        code, 0,
        "the committed synthetic fixtures must satisfy the scrub gate.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn gate_fails_on_credential_shaped_field() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let fixture_path = temp_dir.path().join("test.json");

    // WireGuard-shaped private key (44-char base64) — the round 4 failure
    let bad_fixture = r#"{
        "wg_private_key": "cGFzc3dvcmQxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="
    }"#;

    fs::write(&fixture_path, bad_fixture).expect("failed to write fixture");

    let (code, _stdout, stderr) = run_gate(
        temp_dir
            .path()
            .to_str()
            .expect("temp dir path is valid UTF-8"),
    );

    assert_ne!(
        code, 0,
        "Gate should fail on credential-shaped field.\nstderr: {}",
        stderr
    );
    assert!(
        stderr.contains("credential-shaped field"),
        "Error should mention credential-shaped field: {}",
        stderr
    );
    // Ensure the value itself is not echoed
    assert!(
        !stderr.contains("cGFzc3dvcmQx"),
        "Diagnostic should not echo the credential value: {}",
        stderr
    );
}

#[test]
fn gate_fails_on_high_entropy_value() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let fixture_path = temp_dir.path().join("test.json");

    // High-entropy value in a field that is NOT a structural identifier
    let bad_fixture = r#"{
        "guest_token": "aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkaGVsbG93b3JsZA=="
    }"#;

    fs::write(&fixture_path, bad_fixture).expect("failed to write fixture");

    let (code, _stdout, stderr) = run_gate(
        temp_dir
            .path()
            .to_str()
            .expect("temp dir path is valid UTF-8"),
    );

    assert_ne!(
        code, 0,
        "Gate should fail on high-entropy value.\nstderr: {}",
        stderr
    );
    assert!(
        stderr.contains("high-entropy value"),
        "Error should mention high-entropy value: {}",
        stderr
    );
}

#[test]
fn gate_fails_on_public_ipv4_in_cidr() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let fixture_path = temp_dir.path().join("test.json");

    // Public IPv4 in CIDR form — the round 2 failure that regex missed
    // Using 203.0.114.x which is outside the 203.0.113.0/24 documentation range
    let bad_fixture = r#"{
        "wan_ip": "203.0.114.212/23"
    }"#;

    fs::write(&fixture_path, bad_fixture).expect("failed to write fixture");

    let (code, _stdout, stderr) = run_gate(
        temp_dir
            .path()
            .to_str()
            .expect("temp dir path is valid UTF-8"),
    );

    assert_ne!(
        code, 0,
        "Gate should fail on public IPv4 in CIDR.\nstderr: {}",
        stderr
    );
    assert!(
        stderr.contains("public IP"),
        "Error should mention public IP: {}",
        stderr
    );
    // Ensure the value itself is not echoed
    assert!(
        !stderr.contains("203.0.114.212"),
        "Diagnostic should not echo the IP address: {}",
        stderr
    );
}

#[test]
fn gate_fails_on_public_ipv6_cidr() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let fixture_path = temp_dir.path().join("test.json");

    // Public IPv6 CIDR
    let bad_fixture = r#"{
        "wan6_subnet": "2001:470:1234:5678::/64"
    }"#;

    fs::write(&fixture_path, bad_fixture).expect("failed to write fixture");

    let (code, _stdout, stderr) = run_gate(
        temp_dir
            .path()
            .to_str()
            .expect("temp dir path is valid UTF-8"),
    );

    assert_ne!(
        code, 0,
        "Gate should fail on public IPv6 CIDR.\nstderr: {}",
        stderr
    );
    assert!(
        stderr.contains("public IP"),
        "Error should mention public IP: {}",
        stderr
    );
}

#[test]
fn gate_fails_on_global_ipv6() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let fixture_path = temp_dir.path().join("test.json");

    // Global IPv6 address (bare, not CIDR).
    // Not 2001:db8:: because that's the documentation prefix the gate must ACCEPT.
    let bad_fixture = r#"{
        "wan6_ip": "2001:470:1234:5678::1"
    }"#;

    fs::write(&fixture_path, bad_fixture).expect("failed to write fixture");

    let (code, _stdout, stderr) = run_gate(
        temp_dir
            .path()
            .to_str()
            .expect("temp dir path is valid UTF-8"),
    );

    assert_ne!(
        code, 0,
        "Gate should fail on global IPv6.\nstderr: {}",
        stderr
    );
    assert!(
        stderr.contains("public IP"),
        "Error should mention public IPv6: {}",
        stderr
    );
}

#[test]
fn gate_fails_on_non_zero_latitude() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let fixture_path = temp_dir.path().join("test.json");

    // Non-zero GPS coordinates — the round 3 failure
    let bad_fixture = r#"{
        "lat": 37.7749,
        "lng": -122.4194
    }"#;

    fs::write(&fixture_path, bad_fixture).expect("failed to write fixture");

    let (code, _stdout, stderr) = run_gate(
        temp_dir
            .path()
            .to_str()
            .expect("temp dir path is valid UTF-8"),
    );

    assert_ne!(
        code, 0,
        "Gate should fail on non-zero coordinates.\nstderr: {}",
        stderr
    );
    assert!(
        stderr.contains("non-zero coordinate"),
        "Error should mention coordinate: {}",
        stderr
    );
}

#[test]
fn gate_fails_on_real_mac_address() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let fixture_path = temp_dir.path().join("test.json");

    // Real-looking MAC address (not in synthetic ranges)
    let bad_fixture = r#"{
        "client_mac": "aa:bb:cc:dd:ee:ff"
    }"#;

    fs::write(&fixture_path, bad_fixture).expect("failed to write fixture");

    let (code, _stdout, stderr) = run_gate(
        temp_dir
            .path()
            .to_str()
            .expect("temp dir path is valid UTF-8"),
    );

    assert_ne!(
        code, 0,
        "Gate should fail on real MAC address.\nstderr: {}",
        stderr
    );
    assert!(
        stderr.contains("MAC address"),
        "Error should mention MAC address: {}",
        stderr
    );
}

#[test]
fn gate_fails_on_denylist_hit() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let fixture_path = temp_dir.path().join("test.json");

    // Synthetic identifiers for testing (not the real "mechub-office" or "harman.admin")
    let bad_fixture = r#"{
        "site_name": "example-office",
        "user_name": "testuser.admin"
    }"#;

    fs::write(&fixture_path, bad_fixture).expect("failed to write fixture");

    // Create a temporary denylist for this test
    let denylist_path = workspace_root().join("scripts/fixture-denylist.txt");
    let denylist_existed = denylist_path.exists();
    let original_content = if denylist_existed {
        fs::read_to_string(&denylist_path).ok()
    } else {
        None
    };

    // Write test denylist
    fs::write(&denylist_path, "example-office\ntestuser\n").expect("failed to write test denylist");

    // Run WITHOUT ALLOW_MISSING_DENYLIST so it actually checks
    let root = workspace_root();
    let script = root.join(GATE_SCRIPT);
    let dir = temp_dir.path();

    let output = Command::new(&script)
        .arg(dir)
        .output()
        .expect("failed to execute gate script");

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);

    // Restore original denylist state
    if let Some(content) = original_content {
        fs::write(&denylist_path, content).expect("failed to restore denylist");
    } else {
        let _ = fs::remove_file(&denylist_path);
    }

    assert_ne!(
        code, 0,
        "Gate should fail on denylist match.\nstderr: {}",
        stderr
    );
    assert!(
        stderr.contains("denylist match"),
        "Error should mention denylist: {}",
        stderr
    );
}

#[test]
fn gate_allows_documentation_ips() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let fixture_path = temp_dir.path().join("test.json");

    // Documentation range IPs should be allowed
    let good_fixture = r#"{
        "example_ipv4": "192.0.2.1",
        "example_ipv6": "2001:db8::1",
        "resolver": "8.8.8.8"
    }"#;

    fs::write(&fixture_path, good_fixture).expect("failed to write fixture");

    let (code, stdout, stderr) = run_gate(
        temp_dir
            .path()
            .to_str()
            .expect("temp dir path is valid UTF-8"),
    );

    assert_eq!(
        code, 0,
        "Gate should allow documentation IPs.\nstdout: {}\nstderr: {}",
        stdout, stderr
    );
}

#[test]
fn gate_allows_synthetic_mac_addresses() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let fixture_path = temp_dir.path().join("test.json");

    // Synthetic MAC addresses should be allowed
    let good_fixture = r#"{
        "mac1": "02:00:00:11:22:33",
        "mac2": "00:00:5e:00:53:01"
    }"#;

    fs::write(&fixture_path, good_fixture).expect("failed to write fixture");

    let (code, stdout, stderr) = run_gate(
        temp_dir
            .path()
            .to_str()
            .expect("temp dir path is valid UTF-8"),
    );

    assert_eq!(
        code, 0,
        "Gate should allow synthetic MACs.\nstdout: {}\nstderr: {}",
        stdout, stderr
    );
}

#[test]
fn gate_allows_structural_high_entropy_ids() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let fixture_path = temp_dir.path().join("test.json");

    // Structural identifiers should be allowed even if high-entropy
    let good_fixture = r#"{
        "_id": "507f1f77bcf86cd799439011deadbeef",
        "site_id": "1234567890abcdef1234567890abcdef",
        "device_id": "aabbccdd11223344556677889900aabb"
    }"#;

    fs::write(&fixture_path, good_fixture).expect("failed to write fixture");

    let (code, stdout, stderr) = run_gate(
        temp_dir
            .path()
            .to_str()
            .expect("temp dir path is valid UTF-8"),
    );

    assert_eq!(
        code, 0,
        "Gate should allow structural IDs.\nstdout: {}\nstderr: {}",
        stdout, stderr
    );
}

#[test]
fn gate_fails_on_empty_fixture_directory() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");

    let (code, _stdout, stderr) = run_gate(
        temp_dir
            .path()
            .to_str()
            .expect("temp dir path is valid UTF-8"),
    );

    assert_ne!(
        code, 0,
        "Gate should fail on empty directory.\nstderr: {}",
        stderr
    );
    assert!(
        stderr.contains("no fixture files found"),
        "Error should mention no files found: {}",
        stderr
    );
}

#[test]
fn gate_fails_on_real_mac_colon_format() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let fixture_path = temp_dir.path().join("test.json");

    // Real MAC in colon format
    let bad_fixture = r#"{
        "mac": "de:ad:be:ef:12:34"
    }"#;

    fs::write(&fixture_path, bad_fixture).expect("failed to write fixture");

    let (code, _stdout, stderr) = run_gate(
        temp_dir
            .path()
            .to_str()
            .expect("temp dir path is valid UTF-8"),
    );

    assert_ne!(
        code, 0,
        "Gate should fail on real MAC (colon format).\nstderr: {}",
        stderr
    );
    assert!(
        stderr.contains("MAC address"),
        "Error should mention MAC address: {}",
        stderr
    );
}

#[test]
fn gate_fails_on_real_mac_dash_format() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let fixture_path = temp_dir.path().join("test.json");

    // Real MAC in dash format
    let bad_fixture = r#"{
        "mac": "DE-AD-BE-EF-12-34"
    }"#;

    fs::write(&fixture_path, bad_fixture).expect("failed to write fixture");

    let (code, _stdout, stderr) = run_gate(
        temp_dir
            .path()
            .to_str()
            .expect("temp dir path is valid UTF-8"),
    );

    assert_ne!(
        code, 0,
        "Gate should fail on real MAC (dash format).\nstderr: {}",
        stderr
    );
    assert!(
        stderr.contains("MAC address"),
        "Error should mention MAC address: {}",
        stderr
    );
}

#[test]
fn gate_fails_on_real_mac_bare_format() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let fixture_path = temp_dir.path().join("test.json");

    // Real MAC in bare 12-hex format (as returned by UniFi API)
    let bad_fixture = r#"{
        "mac": "deadbeef1234"
    }"#;

    fs::write(&fixture_path, bad_fixture).expect("failed to write fixture");

    let (code, _stdout, stderr) = run_gate(
        temp_dir
            .path()
            .to_str()
            .expect("temp dir path is valid UTF-8"),
    );

    assert_ne!(
        code, 0,
        "Gate should fail on real MAC (bare format).\nstderr: {}",
        stderr
    );
    assert!(
        stderr.contains("MAC address"),
        "Error should mention MAC address: {}",
        stderr
    );
}

#[test]
fn gate_allows_synthetic_mac_in_mac_field() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let fixture_path = temp_dir.path().join("test.json");

    // Synthetic MAC in the 'mac' field itself should be allowed
    let good_fixture = r#"{
        "mac": "02:00:00:00:01:00"
    }"#;

    fs::write(&fixture_path, good_fixture).expect("failed to write fixture");

    let (code, stdout, stderr) = run_gate(
        temp_dir
            .path()
            .to_str()
            .expect("temp dir path is valid UTF-8"),
    );

    assert_eq!(
        code, 0,
        "Gate should allow synthetic MAC in 'mac' field.\nstdout: {}\nstderr: {}",
        stdout, stderr
    );
}
