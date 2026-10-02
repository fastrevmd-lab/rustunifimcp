//! MEC-504: `/healthz`, `/readyz`, and the default per-IP rate limit that
//! comes with mecmcp 0.24.1.
//!
//! `/healthz` and `/readyz` are mounted unconditionally by
//! `mecmcp-transport`'s router assembly -- this server wires in no readiness
//! checks of its own (matching the sibling servers' MEC-449/MEC-408 scope),
//! so `/readyz` degrades to "200 when nothing is configured to fail."
//!
//! Rate limiting is enforced by whatever `LimitsConfig` this server passes to
//! `build_http_router`; `serve_http` now builds that from `UnifiCli::limits`
//! (see `rustunifimcp/src/cli.rs`), whose defaults mirror
//! `LimitsConfig::default()` -- which, as of mecmcp 0.24.1, is no longer
//! unmetered. This test drives the real assembled router, not a mock, so a
//! regression in the wiring between the CLI flags and the transport's
//! middleware fails here.

use mecmcp_transport::LimitsConfig;
use mecmcp_transport::test_harness::serve_on_loopback;
use reqwest::StatusCode;
use rustunifimcp::http_transport::build_http_router;
use rustunifimcp::server::UnifiServer;
use std::io::Write as _;
use tokio_util::sync::CancellationToken;

/// Build an unauthenticated router over an empty controller inventory. No
/// controller is needed: `/healthz`, `/readyz`, and the per-IP limiter never
/// touch the inventory.
async fn start_server() -> (String, tokio_util::sync::CancellationToken) {
    let mut controllers_file = tempfile::NamedTempFile::new().expect("tempfile");
    writeln!(controllers_file, "{{}}").expect("write");
    controllers_file.flush().expect("flush");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(controllers_file.path())
            .expect("metadata")
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(controllers_file.path(), perms).expect("chmod");
    }

    let registry = std::sync::Arc::new(
        rustunifimcp_core::inventory::ControllerRegistry::load(controllers_file.path())
            .expect("load empty inventory"),
    );
    let coordinator = rustunifimcp::changeset_state::build_coordinator(
        None,
        std::time::Duration::from_secs(300),
        false,
        None,
        None,
    )
    .expect("build coordinator");
    let handler = UnifiServer::new(
        registry,
        false,
        coordinator,
        None,
        mecmcp_audit::DirectCommitPolicy::new(false),
    )
    .expect("build server");

    let shutdown = CancellationToken::new();
    let plan = build_http_router(
        handler,
        None, // unauthenticated: no bearer boundary to configure for this test
        Vec::new(),
        Vec::new(),
        LimitsConfig::default(),
        false, // metrics
        true,  // allow_insecure_bind: loopback test, no TLS material to hand it
        shutdown.clone(),
    )
    .expect("build router");

    let served = serve_on_loopback(plan).await;
    std::mem::forget(served.serving);
    (format!("http://{}", served.address), shutdown)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthz_responds_ok_without_auth() {
    let (url, shutdown) = start_server().await;
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{url}/healthz"))
        .header(reqwest::header::HOST, "localhost")
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    shutdown.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readyz_responds_ok_without_auth() {
    let (url, shutdown) = start_server().await;
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{url}/readyz"))
        .header(reqwest::header::HOST, "localhost")
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    shutdown.cancel();
}

/// mecmcp 0.24.1 makes `LimitsConfig::default()` rate-limit by default (50
/// requests/second and a burst of 100 per IP). `serve_http` now passes
/// `UnifiCli::limits`, whose defaults are that same `LimitsConfig::default()`,
/// straight through -- so a burst of requests from one IP must eventually see
/// 429, proving the limiter is live and actually reachable through this
/// server's CLI-to-transport wiring, not merely configured and ignored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_flood_from_one_ip_is_rate_limited() {
    let (url, shutdown) = start_server().await;
    let client = reqwest::Client::new();

    // The default burst is 100/ip, refilling at 50/s. Fire all 200 requests
    // concurrently rather than sequentially awaiting each one: on a loaded
    // CI runner, a sequential loop can take long enough between requests that
    // the bucket refills as fast as it drains, and the flood never exceeds
    // the burst.
    let mut handles = Vec::with_capacity(200);
    for _ in 0..200 {
        let client = client.clone();
        let url = format!("{url}/healthz");
        handles.push(tokio::spawn(async move {
            client
                .get(url)
                .header(reqwest::header::HOST, "localhost")
                .send()
                .await
                .expect("request")
                .status()
        }));
    }

    let mut saw_too_many_requests = false;
    for handle in handles {
        if handle.await.expect("task") == StatusCode::TOO_MANY_REQUESTS {
            saw_too_many_requests = true;
        }
    }

    shutdown.cancel();

    assert!(
        saw_too_many_requests,
        "a flood of 200 concurrent requests from one IP must be rate-limited (429); \
         LimitsConfig::default() is supposed to be metered as of mecmcp 0.24.1, and \
         serve_http is supposed to pass that default through from UnifiCli::limits"
    );
}
