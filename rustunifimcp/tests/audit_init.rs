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
///
/// `run()` always closes stdin, so a build that starts serving over stdio
/// with no audit failure at all *also* exits non-zero here: `service.waiting()`
/// sees immediate EOF and returns `Fatal: connection closed`, which alone
/// satisfies "fails" and "prints Fatal:" with no audit refusal in sight. That
/// is exactly the false pass this test had against the pre-M10 `main.rs`,
/// which never called `init_audit` at all. So beyond "it failed", this
/// asserts the failure names audit specifically, and that stderr never shows
/// `serve_stdio`'s "Starting MCP stdio service" line -- proving the process
/// never got past `init_audit` to reach serving.
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
    assert!(
        stderr.contains("audit"),
        "the refusal must name audit, not just fail for some other reason, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("Starting MCP stdio service"),
        "startup must fail before serving begins, not on the closed-stdin \
         `connection closed` a build with no audit wiring at all would also \
         hit; got:\n{stderr}"
    );
}

/// SIGHUP must reopen the audit file in place so a `rename`-mode logrotate
/// (see `packaging/logrotate/rustunifimcp-audit`) is lossless: the record
/// logrotate's `postrotate` script provokes must land in the new inode at the
/// original path, not the renamed one the old descriptor still points at.
///
/// This drives the real binary rather than calling `perform_sighup_reload`
/// directly, because an `AuditFileSink` can only be constructed through
/// `mecmcp_audit::init_tracing`'s process-global subscriber, and that isn't
/// something a unit test can fabricate without a test-only constructor this
/// crate does not own.
#[cfg(unix)]
#[test]
fn sighup_reopens_the_audit_file_for_lossless_rotation() {
    let controllers = controllers_file();
    let audit_dir = tempfile::tempdir().expect("audit dir");
    let audit_path = audit_dir.path().join("audit.jsonl");
    let rotated_path = audit_dir.path().join("audit.jsonl.1");

    let mut child = Command::new(env!("CARGO_BIN_EXE_rustunifimcp"))
        .args([
            "--controllers-file",
            controllers.path().to_str().expect("utf-8 path"),
            "--lab-mode",
            "--audit-format",
            "json",
            "--audit-log-file",
            audit_path.to_str().expect("utf-8 path"),
        ])
        // Left open (not `Stdio::null()`) so the stdio transport keeps
        // waiting instead of seeing immediate EOF and exiting before the
        // signal can be delivered.
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rustunifimcp");

    poll_until(Duration::from_secs(10), || {
        std::fs::read_to_string(&audit_path).is_ok_and(|body| !body.is_empty())
    });

    let pre_rotation = std::fs::read_to_string(&audit_path).expect("read audit file");
    assert!(
        pre_rotation.contains("lab mode"),
        "expected the startup lab-mode record before rotation, got: {pre_rotation}"
    );

    // Simulate logrotate's rename step: move the live file aside.
    std::fs::rename(&audit_path, &rotated_path).expect("rename audit file");

    // Simulate logrotate's postrotate step: signal the server.
    let status = Command::new("kill")
        .args(["-HUP", &child.id().to_string()])
        .status()
        .expect("send SIGHUP");
    assert!(status.success(), "kill -HUP must succeed");

    poll_until(Duration::from_secs(10), || audit_path.exists());
    poll_until(Duration::from_secs(10), || {
        std::fs::read_to_string(&audit_path).is_ok_and(|body| body.contains("audit file reopened"))
    });

    let post_rotation = std::fs::read_to_string(&audit_path).expect("read reopened audit file");
    assert!(
        post_rotation.contains("audit file reopened"),
        "the reopened file must carry the record written after reopen, got: {post_rotation}"
    );

    let rotated_final = std::fs::read_to_string(&rotated_path).expect("read rotated audit file");
    assert!(
        rotated_final.contains("lab mode"),
        "the rotated file must keep the pre-rotation record intact"
    );
    assert!(
        !rotated_final.contains("audit file reopened"),
        "a post-rotation record must not land in the renamed file -- that is \
         exactly the data loss this SIGHUP wiring exists to prevent, got: {rotated_final}"
    );

    // Let the process exit cleanly: close stdin so the stdio transport sees
    // EOF, then reap it (bounded, as `run()` above does).
    drop(child.stdin.take());
    let _ = wait_with_timeout(child, Duration::from_secs(10));
}

fn poll_until(timeout: Duration, mut condition: impl FnMut() -> bool) {
    let start = std::time::Instant::now();
    loop {
        if condition() {
            return;
        }
        assert!(
            start.elapsed() <= timeout,
            "condition did not become true within {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
