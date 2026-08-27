//! Tests for the fixture scrubbing verification gate.
//!
//! Ensures the scrub gate passes on verified-clean fixtures and fails on each
//! category of sensitive data that has leaked in the past.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Path to the verification script relative to workspace root.
const GATE_SCRIPT: &str = "scripts/verify-fixtures-scrubbed.sh";

/// Path to existing verified-clean fixtures.
const CLEAN_FIXTURE_DIR: &str = "rustunifimcp-core/tests/fixtures/10.5.67";

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
        .output()
        .expect("failed to execute gate script");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);

    (code, stdout, stderr)
}

#[test]
fn gate_passes_on_verified_clean_fixtures() {
    let (code, stdout, stderr) = run_gate(CLEAN_FIXTURE_DIR);

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
fn gate_fails_on_credential_shaped_field() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let fixture_path = temp_dir.path().join("test.json");

    // WireGuard-shaped private key (44-char base64) — the round 4 failure
    let bad_fixture = r#"{
        "wg_private_key": "cGFzc3dvcmQxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="
    }"#;

    fs::write(&fixture_path, bad_fixture).expect("failed to write fixture");

    let (code, _stdout, stderr) = run_gate(temp_dir.path().to_str().expect("temp dir path is valid UTF-8"));

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

    let (code, _stdout, stderr) = run_gate(temp_dir.path().to_str().expect("temp dir path is valid UTF-8"));

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
    let bad_fixture = r#"{
        "wan_ip": "198.51.100.212/23"
    }"#;

    fs::write(&fixture_path, bad_fixture).expect("failed to write fixture");

    let (code, _stdout, stderr) = run_gate(temp_dir.path().to_str().expect("temp dir path is valid UTF-8"));

    assert_ne!(
        code, 0,
        "Gate should fail on public IPv4 in CIDR.\nstderr: {}",
        stderr
    );
    assert!(
        stderr.contains("public IP") && stderr.contains("198.51.100.212"),
        "Error should mention public IP address: {}",
        stderr
    );
}

#[test]
fn gate_fails_on_global_ipv6() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let fixture_path = temp_dir.path().join("test.json");

    // Global IPv6 address — the round 3 failure (Comcast prefix)
    let bad_fixture = r#"{
        "wan6_ip": "2601:1234:5678:90ab::1"
    }"#;

    fs::write(&fixture_path, bad_fixture).expect("failed to write fixture");

    let (code, _stdout, stderr) = run_gate(temp_dir.path().to_str().expect("temp dir path is valid UTF-8"));

    assert_ne!(
        code, 0,
        "Gate should fail on global IPv6.\nstderr: {}",
        stderr
    );
    assert!(
        stderr.contains("public IP") && stderr.contains("2601:1234:5678:90ab::1"),
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

    let (code, _stdout, stderr) = run_gate(temp_dir.path().to_str().expect("temp dir path is valid UTF-8"));

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
fn gate_fails_on_denylist_hit() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let fixture_path = temp_dir.path().join("test.json");

    // Identifier from the denylist — the round 2 and 3 failures
    let bad_fixture = r#"{
        "site_name": "mechub-office",
        "user_name": "harman.admin"
    }"#;

    fs::write(&fixture_path, bad_fixture).expect("failed to write fixture");

    let (code, _stdout, stderr) = run_gate(temp_dir.path().to_str().expect("temp dir path is valid UTF-8"));

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

    let (code, stdout, stderr) = run_gate(temp_dir.path().to_str().expect("temp dir path is valid UTF-8"));

    assert_eq!(
        code, 0,
        "Gate should allow documentation IPs.\nstdout: {}\nstderr: {}",
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

    let (code, stdout, stderr) = run_gate(temp_dir.path().to_str().expect("temp dir path is valid UTF-8"));

    assert_eq!(
        code, 0,
        "Gate should allow structural IDs.\nstdout: {}\nstderr: {}",
        stdout, stderr
    );
}

#[test]
fn gate_fails_on_empty_fixture_directory() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");

    let (code, _stdout, stderr) = run_gate(temp_dir.path().to_str().expect("temp dir path is valid UTF-8"));

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
