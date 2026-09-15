//! Pins the operator-visible text of the startup refusals, and their ordering
//! against config errors.
//!
//! This binary used to skip `mecmcp_runtime::cli_validate` entirely. The
//! listener still refused an unsafe bind — `mecmcp_transport::serve_router`
//! owns that check — but the refusal surfaced as `Fatal: failed to serve HTTP
//! router`, with the reason discarded, so an operator had no path from the
//! message to the flag. See mecmcp#358.
//!
//! These assertions run the real binary. The posture was never the problem:
//! the bind was refused correctly throughout. What was wrong was what reached
//! stderr, and what order the checks ran in — neither is observable from
//! inside the process.

use std::io::Write;
use std::process::{Command, Output};

/// A controllers file that parses and is mode 0600, so a run reaches CLI
/// validation rather than stopping on the inventory first.
fn controllers_file() -> tempfile::NamedTempFile {
    let mut key = tempfile::NamedTempFile::new().expect("create api key file");
    key.write_all(b"dummy-api-key\n").expect("write api key");
    key.flush().expect("flush api key");
    secure(key.path());
    // Leak the key file so it outlives this call; the registry only needs the
    // path to exist while the binary starts.
    let key_path = key.into_temp_path();
    let key_path = key_path.keep().expect("persist api key file");

    let mut file = tempfile::NamedTempFile::new().expect("create controllers file");
    let body = format!(
        r#"{{"version":1,"devices":{{"home":{{"endpoint":"https://unifi.example.org","site":"default","api_key_file":"{}","allow_private_api":true}}}}}}"#,
        key_path.display()
    );
    file.write_all(body.as_bytes())
        .expect("write controllers file");
    file.flush().expect("flush controllers file");
    secure(file.path());
    file
}

fn tokens_file() -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("create tokens file");
    file.write_all(br#"{"tokens":[]}"#)
        .expect("write tokens file");
    file.flush().expect("flush tokens file");
    secure(file.path());
    file
}

fn secure(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rustunifimcp"))
        .args(args)
        .output()
        .expect("spawn rustunifimcp")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn off_loopback_without_allowed_origin_names_the_flag() {
    let controllers = controllers_file();
    let tokens = tokens_file();
    let output = run(&[
        "--controllers-file",
        controllers.path().to_str().expect("utf-8 path"),
        "--transport",
        "streamable-http",
        "--host",
        "0.0.0.0",
        "--port",
        "30033",
        "--tokens-file",
        tokens.path().to_str().expect("utf-8 path"),
        "--allow-insecure-bind",
        "--allowed-host",
        "10.0.0.1:30033",
    ]);
    let stderr = stderr_of(&output);

    assert!(
        stderr.contains("requires at least one --allowed-origin"),
        "the refusal must name the flag, got:\n{stderr}"
    );
    // The regression guard. This is the string the binary printed before the
    // shared validator was called, and it is what a reintroduced skip looks
    // like: the bind is still refused, but the reason is gone.
    assert!(
        !stderr.contains("failed to serve HTTP router"),
        "the reason was swallowed by the generic serve error:\n{stderr}"
    );
    assert!(!output.status.success(), "a refused CLI must exit non-zero");
}

#[test]
fn off_loopback_without_allowed_host_names_the_flag() {
    let controllers = controllers_file();
    let tokens = tokens_file();
    let output = run(&[
        "--controllers-file",
        controllers.path().to_str().expect("utf-8 path"),
        "--transport",
        "streamable-http",
        "--host",
        "0.0.0.0",
        "--port",
        "30033",
        "--tokens-file",
        tokens.path().to_str().expect("utf-8 path"),
        "--allow-insecure-bind",
    ]);
    let stderr = stderr_of(&output);

    assert!(
        stderr.contains("requires at least one --allowed-host"),
        "the refusal must name the flag, got:\n{stderr}"
    );
    assert!(!output.status.success(), "a refused CLI must exit non-zero");
}

/// Ordering, not just wording.
///
/// Validation must run before any file is read, so an argument mistake is
/// reported as an argument mistake. Before this was fixed, the controllers
/// file was parsed first and a wrong file mode masked the CLI error entirely —
/// the opposite order from every other server in the family.
#[test]
fn argument_errors_are_not_masked_by_config_errors() {
    let controllers = controllers_file();
    let tokens = tokens_file();

    // Deliberately make the inventory unreadable-by-policy as well.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(controllers.path(), std::fs::Permissions::from_mode(0o644))
            .expect("chmod 644");
    }

    let output = run(&[
        "--controllers-file",
        controllers.path().to_str().expect("utf-8 path"),
        "--transport",
        "streamable-http",
        "--host",
        "0.0.0.0",
        "--port",
        "30033",
        "--tokens-file",
        tokens.path().to_str().expect("utf-8 path"),
        "--allow-insecure-bind",
        "--allowed-host",
        "10.0.0.1:30033",
    ]);
    let stderr = stderr_of(&output);

    assert!(
        stderr.contains("requires at least one --allowed-origin"),
        "the argument error must win over the inventory error, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("group- or world-accessible"),
        "the inventory error masked the argument error:\n{stderr}"
    );
}
