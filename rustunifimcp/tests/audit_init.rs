//! Pins that the audit flags actually wire an audit subscriber and file.
//!
//! `main.rs` used to parse `--audit-format` / `--audit-log-file` /
//! `--audit-journald` (`UnifiCli` flattens `mecmcp_runtime::cli::Cli`, which
//! declares them) and never call `mecmcp_audit::init_tracing`. The systemd
//! unit passes all three unconditionally, so every deployment ran with no
//! audit trail and no indication that was happening. These assertions run the
//! real binary, because the wiring lives in `main`'s own startup sequence and
//! is not observable from inside a unit test.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

/// A controllers file that parses and is mode 0600, so the run reaches audit
/// init and then serving rather than stopping on the inventory first. Empty
/// is enough: nothing here touches a controller.
fn controllers_file() -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("create controllers file");
    file.write_all(b"{}").expect("write controllers file");
    file.flush().expect("flush controllers file");
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

/// Run the binary over stdio with a closed stdin, so the MCP transport sees
/// EOF immediately and `service.waiting()` returns instead of blocking
/// forever. Startup — audit init, lab-mode warning, registry load — all
/// happens before that point, so a closed stdin does not race any of it.
fn run(args: &[&str]) -> std::process::Output {
    let child = Command::new(env!("CARGO_BIN_EXE_rustunifimcp"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rustunifimcp");

    // Bounded wait: a wiring regression that makes the process hang (rather
    // than exit) must fail the test loudly instead of stalling CI.
    wait_with_timeout(child, Duration::from_secs(10))
}

fn wait_with_timeout(mut child: std::process::Child, timeout: Duration) -> std::process::Output {
    let start = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            if let Some(mut out) = child.stdout.take() {
                use std::io::Read as _;
                let _ = out.read_to_end(&mut stdout);
            }
            if let Some(mut err) = child.stderr.take() {
                use std::io::Read as _;
                let _ = err.read_to_end(&mut stderr);
            }
            return std::process::Output {
                status,
                stdout,
                stderr,
            };
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            panic!("rustunifimcp did not exit within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn stderr_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Starting with the audit flags set must create the audit file, and an
/// audited action — here, `--lab-mode`, which unconditionally logs
/// `target: "audit"` before serving begins — must write a record to it.
#[test]
fn audit_flags_create_the_file_and_an_action_writes_a_record() {
    let controllers = controllers_file();
    let audit_dir = tempfile::tempdir().expect("audit dir");
    let audit_path = audit_dir.path().join("audit.jsonl");

    let output = run(&[
        "--controllers-file",
        controllers.path().to_str().expect("utf-8 path"),
        "--lab-mode",
        "--audit-format",
        "json",
        "--audit-log-file",
        audit_path.to_str().expect("utf-8 path"),
    ]);

    assert!(
        audit_path.exists(),
        "the audit file must be created when --audit-log-file is set; stderr:\n{}",
        stderr_of(&output)
    );

    let body = std::fs::read_to_string(&audit_path).expect("read audit file");
    assert!(
        !body.is_empty(),
        "lab mode must write an audit record before serving begins"
    );

    let line = body
        .lines()
        .next()
        .expect("at least one audit line was written");
    let record: serde_json::Value = serde_json::from_str(line).expect("audit line is JSON");
    let rendered = record.to_string();
    assert!(
        rendered.contains("lab mode"),
        "the record must be the lab-mode audit event, got: {rendered}"
    );
}

/// A configured audit path that cannot be opened (parent directory absent)
/// must make startup fail rather than run unaudited. `mecmcp_audit::init_tracing`
/// already refuses via `?`; this pins that the refusal reaches the process
/// exit code and is not swallowed anywhere in `main`'s call chain.
#[test]
fn an_unwritable_audit_path_fails_startup() {
    let controllers = controllers_file();
    let audit_dir = tempfile::tempdir().expect("audit dir");
    let unwritable = audit_dir
        .path()
        .join("no-such-directory")
        .join("audit.jsonl");

    let output = run(&[
        "--controllers-file",
        controllers.path().to_str().expect("utf-8 path"),
        "--audit-format",
        "json",
        "--audit-log-file",
        unwritable.to_str().expect("utf-8 path"),
    ]);

    assert!(
        !output.status.success(),
        "startup must fail when the audit file cannot be opened"
    );
    assert!(
        !unwritable.exists(),
        "no file must be left behind by the failed open"
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("Fatal:"),
        "the refusal must reach the operator on stderr, got:\n{stderr}"
    );
}
