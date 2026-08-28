//! `rustunifimcp` — enterprise MCP server for UniFi Network.

use rustunifimcp::cli::UnifiCli;
use rustunifimcp::server::UnifiServer;
use rustunifimcp::http_transport::build_http_router;
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

async fn serve_stdio(
    handler: UnifiServer,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("Starting MCP stdio service");

    let service = handler
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await?;

    service
        .waiting()
        .await
        .map(|_| ())?;

    Ok(())
}

async fn serve_http(
    handler: UnifiServer,
    cli: &UnifiCli,
) -> Result<(), Box<dyn std::error::Error>> {

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

    tracing::info!("Serving on {bind_addr}");

    // Load TLS config if provided.
    let tls_config = if let (Some(_cert), Some(_key)) = (&cli.common.tls_cert, &cli.common.tls_key) {
        None // TODO: Add TLS support
    } else {
        None
    };

    serve_router(
        router,
        bind_addr,
        tls_config,
        std::time::Duration::from_secs(30),
    )
    .await?;

    Ok(())
}
