//! MEC-504: `Controller::ca_pem_path` must be honored for outbound TLS to a
//! UniFi controller, and mecmcp 0.24.1's `extra_root_certificates` semantics
//! (replace the public root store, not add to it) must actually be in effect
//! by the time this server talks to a controller.
//!
//! Two independent self-signed certificates stand in for "the operator's
//! private CA" and "some other certificate the controller does not use".
//! `UnifiClient` is configured to trust only the first; a controller
//! presenting the second must be refused, not merely "also accepted"
//! alongside the public root store -- that regression (`add` instead of
//! `replace`) would keep the positive case below passing for the wrong
//! reason.

use rustunifimcp_core::client::UnifiClient;
use rustunifimcp_core::inventory::Controller;
use std::io::Write as _;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Generate a self-signed `localhost` certificate and a matching rustls
/// server config. ALPN is pinned to `http/1.1` so the canned byte-level
/// response below is what the client actually negotiates.
fn tls_material() -> (String, rustls::ServerConfig) {
    let key_pair = rcgen::KeyPair::generate().expect("keypair");
    let params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("params");
    let cert = params.self_signed(&key_pair).expect("self-signed cert");

    let cert_pem = cert.pem();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();

    // Named explicitly rather than left to auto-detection: under
    // `cargo test --workspace`, feature unification can enable more than one
    // rustls crypto provider, and auto-detection cannot choose between them.
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key_der)
        .expect("server config");
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    (cert_pem, server_config)
}

/// Install the crypto provider once for the whole test binary.
fn ensure_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

async fn bind_local() -> (tokio::net::TcpListener, u16) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local addr").port();
    (listener, port)
}

/// Serve one TLS connection, replying with a canned `applicationVersion` body
/// once a request's headers have been read.
fn serve_one(listener: tokio::net::TcpListener, server_config: rustls::ServerConfig) {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut tls) = acceptor.accept(stream).await else {
            return;
        };
        let mut seen = Vec::new();
        let mut byte = [0u8; 1];
        while tls.read_exact(&mut byte).await.is_ok() {
            seen.push(byte[0]);
            if seen.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let body = r#"{"applicationVersion":"9.0.0"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = tls.write_all(response.as_bytes()).await;
        let _ = tls.flush().await;
    });
}

/// Write `pem` to a fresh temp file and return the guard alongside its path.
fn write_pem(pem: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    file.write_all(pem.as_bytes()).expect("write pem");
    file.flush().expect("flush");
    file
}

/// Write a throwaway API key to a fresh 0600 temp file and return the guard
/// alongside its path.
///
/// `api_key_file` rather than `api_key_env`: the loader hardens file reads
/// (mode 0600, single owner), and a file needs no process-wide mutable state,
/// so concurrent tests in this binary cannot race each other over one env var.
fn write_api_key() -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    file.write_all(b"test-key").expect("write key");
    file.flush().expect("flush");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(file.path())
            .expect("metadata")
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(file.path(), perms).expect("chmod");
    }
    file
}

fn controller_for(
    port: u16,
    ca_pem_path: &std::path::Path,
    api_key_file: &std::path::Path,
) -> Controller {
    serde_json::from_value(serde_json::json!({
        "endpoint": format!("https://localhost:{port}"),
        "site": "default",
        "api_key_file": api_key_file,
        "ca_pem_path": ca_pem_path,
    }))
    .expect("controller parses")
}

/// A controller cert signed by the operator's configured private CA must be
/// trusted.
#[tokio::test]
async fn a_controller_cert_signed_by_the_configured_private_ca_is_trusted() {
    ensure_crypto_provider();

    let (cert_pem, server_config) = tls_material();
    let (listener, port) = bind_local().await;
    serve_one(listener, server_config);

    let ca_file = write_pem(&cert_pem);
    let api_key_file = write_api_key();
    let controller = controller_for(port, ca_file.path(), api_key_file.path());
    let client = UnifiClient::new(controller).expect("client builds");

    let version = client
        .controller_version()
        .await
        .expect("a cert signed by the configured private CA must be trusted");
    assert_eq!(version, "9.0.0");
}

/// A cert the configured private CA did not issue must be refused -- proving
/// `extra_root_certificates` *replaces* the trust store rather than adding to
/// it. Before mecmcp 0.24.1 this same setup would have connected successfully
/// alongside the public root store.
#[tokio::test]
async fn a_cert_the_configured_private_ca_did_not_issue_is_refused() {
    ensure_crypto_provider();

    let (configured_ca_pem, _unused_server_config) = tls_material();
    let (_unrelated_cert_pem, servers_actual_config) = tls_material();

    let (listener, port) = bind_local().await;
    serve_one(listener, servers_actual_config);

    // Client trusts only its own, unrelated CA -- not the one the server used.
    let ca_file = write_pem(&configured_ca_pem);
    let api_key_file = write_api_key();
    let controller = controller_for(port, ca_file.path(), api_key_file.path());
    let client = UnifiClient::new(controller).expect("client builds");

    let result = client.controller_version().await;
    assert!(
        result.is_err(),
        "a cert not signed by the configured private CA must be refused, got {result:?}"
    );
}
