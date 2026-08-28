//! `rustunifimcp` — enterprise MCP server for UniFi Network.

use rustunifimcp::cli::UnifiCli;
use rustunifimcp::server::UnifiServer;
use rustunifimcp::http_transport::build_http_router;
use anyhow::{Context as _, Result, bail};
use clap::Parser;
use mecmcp_transport::{LimitsConfig, serve_router};
use rmcp::ServiceExt;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("Fatal: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    run_inner().await.map_err(Into::into)
}

async fn run_inner() -> Result<()> {
    // Install crypto provider.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = UnifiCli::parse();

    if cli.lab_mode() {
        tracing::warn!(
            target: "audit",
            "Running in lab mode — two-person control disabled"
        );
    }

    // Load registry.
    let registry = Arc::new(
        rustunifimcp_core::inventory::ControllerRegistry::load(&cli.controllers_file)?
    );

    // Build server.
    let server = UnifiServer::new(registry, cli.lab_mode())?;

    // Determine transport.
    match cli.common.transport {
        mecmcp_runtime::cli::Transport::Stdio => {
            serve_stdio(server).await
        }
        mecmcp_runtime::cli::Transport::StreamableHttp => {
            serve_http(server, &cli).await
        }
    }
}

/// Load TLS configuration for the listener.
///
/// # Errors
///
/// Returns an error when:
/// - Only one of cert or key is provided (both or neither required)
/// - Certificate or key file cannot be read
/// - Certificate or key PEM is malformed
/// - Certificate and key are not a matching pair
fn load_listener_tls(args: &mecmcp_runtime::cli::Cli) -> Result<Option<Arc<rustls::ServerConfig>>> {
    // Validate that both or neither are provided.
    match (&args.tls_cert, &args.tls_key) {
        (Some(_), None) => bail!("--tls-cert provided without --tls-key"),
        (None, Some(_)) => bail!("--tls-key provided without --tls-cert"),
        (None, None) => Ok(None),
        (Some(cert), Some(key)) => {
            // The process-global provider is installed in `main`; do not install again —
            // `install_default` returns Err when one is already set, and treating that
            // as fatal would break every TLS start.
            let provider = rustls::crypto::aws_lc_rs::default_provider();
            mecmcp_transport::load_tls(cert, key, Arc::new(provider))
                .context("loading listener TLS")
                .map(Some)
        }
    }
}

async fn serve_stdio(
    handler: UnifiServer,
) -> Result<()> {
    tracing::info!("Starting MCP stdio service");

    let service = handler
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await?;

    service.waiting().await?;
    Ok(())
}

async fn serve_http(
    handler: UnifiServer,
    cli: &UnifiCli,
) -> Result<()> {

    // Load token store if provided.
    let token_store = if let Some(ref path) = cli.common.tokens_file {
        Some(Arc::new(
            mecmcp_auth::TokenStoreFile::load(path)?
        ))
    } else {
        None
    };

    let shutdown = CancellationToken::new();
    let router = build_http_router(
        handler,
        token_store,
        cli.common.allowed_host.clone(),
        cli.common.allowed_origin.clone(),
        LimitsConfig::default(),
        false, // metrics
        cli.common.allow_insecure_bind,
        shutdown.clone(),
    )?;

    let bind_addr = format!("{}:{}", cli.common.host, cli.common.port)
        .parse()?;

    // Load TLS config if provided.
    let tls_config = load_listener_tls(&cli.common)?;

    // Log the serving mode for audit purposes.
    if tls_config.is_some() {
        tracing::info!(
            target: "audit",
            "serving HTTPS on {bind_addr}"
        );
    } else {
        tracing::info!(
            target: "audit",
            "serving plain HTTP on {bind_addr}"
        );
    }

    serve_router(
        router,
        bind_addr,
        tls_config,
        std::time::Duration::from_secs(30),
    )
    .await?;

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use mecmcp_runtime::cli::Cli;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

    /// Helper to generate a self-signed cert and key for testing.
    fn generate_test_cert() -> (String, String) {
        use rcgen::{CertificateParams, KeyPair};
        let key_pair = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }

    /// Helper to write content to a temporary file and return its path.
    fn write_temp_file(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    /// Helper to create a minimal Cli with optional TLS paths.
    fn make_cli(tls_cert: Option<PathBuf>, tls_key: Option<PathBuf>) -> Cli {
        use clap::Parser;

        let mut args: Vec<String> = vec![
            "rustunifimcp".to_string(),
            "--transport".to_string(),
            "streamable-http".to_string(),
            "--host".to_string(),
            "127.0.0.1".to_string(),
            "--port".to_string(),
            "0".to_string(),
        ];

        if let Some(cert) = tls_cert {
            args.push("--tls-cert".to_string());
            args.push(cert.to_string_lossy().to_string());
        }
        if let Some(key) = tls_key {
            args.push("--tls-key".to_string());
            args.push(key.to_string_lossy().to_string());
        }

        Cli::try_parse_from(args).unwrap()
    }

    #[test]
    fn tls_cert_without_key_fails() {
        let (cert_pem, _) = generate_test_cert();
        let cert_file = write_temp_file(&cert_pem);

        let cli = make_cli(Some(cert_file.path().to_path_buf()), None);

        let result = load_listener_tls(&cli);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("--tls-cert provided without --tls-key"));
    }

    #[test]
    fn tls_key_without_cert_fails() {
        let (_, key_pem) = generate_test_cert();
        let key_file = write_temp_file(&key_pem);

        let cli = make_cli(None, Some(key_file.path().to_path_buf()));

        let result = load_listener_tls(&cli);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("--tls-key provided without --tls-cert"));
    }

    #[test]
    fn no_tls_args_returns_none() {
        let cli = make_cli(None, None);
        let result = load_listener_tls(&cli).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn valid_tls_cert_and_key_succeed() {
        let (cert_pem, key_pem) = generate_test_cert();
        let cert_file = write_temp_file(&cert_pem);
        let key_file = write_temp_file(&key_pem);

        let cli = make_cli(
            Some(cert_file.path().to_path_buf()),
            Some(key_file.path().to_path_buf()),
        );

        let result = load_listener_tls(&cli);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn malformed_cert_fails() {
        let key_pem = generate_test_cert().1;
        let cert_file = write_temp_file("not a valid PEM");
        let key_file = write_temp_file(&key_pem);

        let cli = make_cli(
            Some(cert_file.path().to_path_buf()),
            Some(key_file.path().to_path_buf()),
        );

        let result = load_listener_tls(&cli);
        assert!(result.is_err());
    }

    #[test]
    fn malformed_key_fails() {
        let cert_pem = generate_test_cert().0;
        let cert_file = write_temp_file(&cert_pem);
        let key_file = write_temp_file("not a valid PEM");

        let cli = make_cli(
            Some(cert_file.path().to_path_buf()),
            Some(key_file.path().to_path_buf()),
        );

        let result = load_listener_tls(&cli);
        assert!(result.is_err());
    }

    #[test]
    fn mismatched_cert_and_key_fail() {
        let (cert_pem1, _) = generate_test_cert();
        let (_, key_pem2) = generate_test_cert();
        let cert_file = write_temp_file(&cert_pem1);
        let key_file = write_temp_file(&key_pem2);

        let cli = make_cli(
            Some(cert_file.path().to_path_buf()),
            Some(key_file.path().to_path_buf()),
        );

        let result = load_listener_tls(&cli);
        assert!(result.is_err());
    }
}
