//! `rustunifimcp` — enterprise MCP server for UniFi Network.

use rustunifimcp::cli::{UnifiCli, TokenCli, TokenCommand};
use rustunifimcp::server::UnifiServer;
use rustunifimcp::http_transport::build_http_router;
use anyhow::{Context as _, Result, bail};
use clap::Parser;
use mecmcp_auth::NoGrant;
use mecmcp_runtime::cli::{Command, TokenAction};
use mecmcp_transport::{LimitsConfig, serve_router};
use rmcp::ServiceExt;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Convert `TokenCommand` to `TokenAction`.
///
/// UniFi uses `NoGrant`, so no vendor grant is built.
fn token_command_to_action(command: TokenCommand) -> (TokenAction, Option<NoGrant>) {
    match command {
        TokenCommand::Add {
            tokens_file,
            name,
            devices,
            tools,
            provider,
            provider_tier,
            on_behalf_of,
            actor_type,
            server_pid,
        } => (
            TokenAction::Add {
                tokens_file,
                name,
                devices,
                tools,
                provider,
                provider_tier,
                on_behalf_of,
                actor_type,
                server_pid,
            },
            None,
        ),
        TokenCommand::Revoke {
            tokens_file,
            name,
            server_pid,
        } => (
            TokenAction::Revoke {
                tokens_file,
                name,
                server_pid,
            },
            None,
        ),
        TokenCommand::List { tokens_file } => (TokenAction::List { tokens_file }, None),
        TokenCommand::Rotate {
            tokens_file,
            name,
            server_pid,
        } => (
            TokenAction::Rotate {
                tokens_file,
                name,
                server_pid,
            },
            None,
        ),
        TokenCommand::SetScope {
            tokens_file,
            name,
            devices,
            tools,
            yes,
            server_pid,
        } => (
            TokenAction::SetScopes {
                tokens_file,
                name,
                devices,
                tools,
                yes,
                server_pid,
            },
            None,
        ),
    }
}

/// Install a minimal audit subscriber for token operations.
///
/// Token commands are dispatched before the server's full `init_audit`, so
/// without a subscriber every token mutation — a mint, a revoke, a privilege
/// widening — is written to disk having left no record. A pre-existing
/// subscriber already installed is not an error worth refusing a token
/// operation over.
fn init_token_audit() {
    use tracing_subscriber::Layer as _;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    use tracing_subscriber::{EnvFilter, filter::filter_fn, fmt};

    // Two layers, each with its own filter, because the audit record must not
    // be reachable by RUST_LOG at all.
    //
    // Adding `audit=info` to the env filter is not enough: `EnvFilter` picks
    // the most specific matching directive, so a field-specific value such as
    // `audit[{tool}]=off` still wins over a target-only one. Measured — the
    // widening applied and stderr stayed empty:
    //
    //     RUST_LOG=audit=off            audit lines: 1
    //     RUST_LOG=audit[{tool}]=off    audit lines: 0   <- silent widening
    //
    // So the audit layer carries a plain predicate instead, which no
    // environment variable participates in.
    let audit_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(filter_fn(|metadata| metadata.target() == "audit"));

    // Everything else follows RUST_LOG as usual, minus the audit target so a
    // permissive filter cannot print the record twice.
    let general_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_filter(filter_fn(|metadata| metadata.target() != "audit"));

    let _ = tracing_subscriber::registry()
        .with(audit_layer)
        .with(general_layer)
        .try_init();
}

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

    // Dispatch token commands before parsing UnifiCli.
    //
    // This keeps grant-specific flags (--devices, --tools) off the server's help
    // and allows them to appear after the subcommand where they belong. The
    // flattened Cli still declares its own `token` subcommand, but TokenCli owns
    // the complete token surface including --help when argv names `token`.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("token") {
        // Build args for TokenCli: [program_name, add/revoke/list/rotate, ...]
        // Skip "token" at index 1 since TokenCli expects the subcommand directly.
        let token_args = std::iter::once(args[0].clone())
            .chain(args.iter().skip(2).cloned())
            .collect::<Vec<_>>();
        let token_cli = TokenCli::parse_from(token_args);

        // Install a subscriber before dispatching. `run_with_grant` emits the
        // scope change as a `target: "audit"` event, and this path returns
        // long before the server's normal tracing init, so without one every token
        // mutation — a mint, a revoke, a privilege widening — is written to
        // disk having left no record that it happened.
        //
        // Deliberately minimal: the token CLI carries no audit flags, so there
        // is no log file, journald sink, or redaction policy to honour. The
        // operator running the command is the audience, and stderr is where
        // they are looking.
        init_token_audit();

        let (action, grant) = token_command_to_action(token_cli.command);

        // Emit audit record for token mutations before executing them.
        // The record contains the operation and scope, never the secret.
        match &action {
            TokenAction::Add { name, devices, tools, .. } => {
                tracing::info!(
                    target: "audit",
                    operation = "token_add",
                    token_name = name,
                    devices = ?devices,
                    tools = ?tools,
                    "token minted"
                );
            }
            TokenAction::Revoke { name, .. } => {
                tracing::info!(
                    target: "audit",
                    operation = "token_revoke",
                    token_name = name,
                    "token revoked"
                );
            }
            TokenAction::Rotate { name, .. } => {
                tracing::info!(
                    target: "audit",
                    operation = "token_rotate",
                    token_name = name,
                    "token secret rotated"
                );
            }
            TokenAction::SetScopes { name, devices, tools, .. } => {
                tracing::info!(
                    target: "audit",
                    operation = "token_set_scope",
                    token_name = name,
                    devices = ?devices,
                    tools = ?tools,
                    "token scope modified"
                );
            }
            TokenAction::SetProvenance { name, provider, provider_tier, on_behalf_of, actor_type, .. } => {
                tracing::info!(
                    target: "audit",
                    operation = "token_set_provenance",
                    token_name = name,
                    provider = ?provider,
                    provider_tier = ?provider_tier,
                    on_behalf_of = ?on_behalf_of,
                    actor_type = ?actor_type,
                    "token provenance modified"
                );
            }
            TokenAction::List { .. } => {
                // List is read-only and does not need audit logging.
            }
        }

        return mecmcp_runtime::token_cmd::run_with_grant::<NoGrant>(
            action,
            &[],
            rustunifimcp_core::tools::TOOL_NAMES,
            grant,
        )
        .map_err(|error| anyhow::anyhow!("{error}"));
    }

    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let mut cli = UnifiCli::parse();

    if let Some(Command::Token { .. }) = cli.common.command.take() {
        // This path fires when a server flag precedes the subcommand
        // (e.g., `--controllers-file X token add ...`). The early dispatch at argv[1]
        // does not intercept it, so TokenCli's grant-specific flags (--devices,
        // --tools) are unavailable. Refuse rather than silently minting a
        // grantless token.
        bail!(
            "token subcommand must appear before server flags; use: \
             rustunifimcp token add [options]"
        );
    }

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
    let tls_config = load_listener_tls(&cli.common)
        .context("TLS configuration failed")?;

    // Remember whether TLS is enabled before moving tls_config.
    let is_tls = tls_config.is_some();

    // Attempt to bind and serve. Log intent first, then outcome after successful bind.
    if is_tls {
        tracing::info!(
            target: "audit",
            "attempting to bind HTTPS listener on {bind_addr}"
        );
    } else {
        tracing::info!(
            target: "audit",
            "attempting to bind plain HTTP listener on {bind_addr}"
        );
    }

    serve_router(
        router,
        bind_addr,
        tls_config,
        std::time::Duration::from_secs(30),
    )
    .await
    .context("failed to serve HTTP router")?;

    // This is reached only on graceful shutdown.
    if is_tls {
        tracing::info!(
            target: "audit",
            "HTTPS listener on {bind_addr} shut down"
        );
    } else {
        tracing::info!(
            target: "audit",
            "plain HTTP listener on {bind_addr} shut down"
        );
    }

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

    #[test]
    fn token_command_to_action_add() {
        use std::path::PathBuf;
        let command = TokenCommand::Add {
            tokens_file: PathBuf::from("/tmp/tokens.json"),
            name: "test".to_string(),
            devices: vec!["*".to_string()],
            tools: vec!["*".to_string()],
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: None,
            server_pid: None,
        };

        let (action, grant) = token_command_to_action(command);
        assert!(grant.is_none());
        match action {
            TokenAction::Add { name, .. } => assert_eq!(name, "test"),
            _ => panic!("expected TokenAction::Add"),
        }
    }

    #[test]
    fn token_command_to_action_revoke() {
        use std::path::PathBuf;
        let command = TokenCommand::Revoke {
            tokens_file: PathBuf::from("/tmp/tokens.json"),
            name: "test".to_string(),
            server_pid: None,
        };

        let (action, grant) = token_command_to_action(command);
        assert!(grant.is_none());
        match action {
            TokenAction::Revoke { name, .. } => assert_eq!(name, "test"),
            _ => panic!("expected TokenAction::Revoke"),
        }
    }

    #[test]
    fn token_command_to_action_list() {
        use std::path::PathBuf;
        let command = TokenCommand::List {
            tokens_file: PathBuf::from("/tmp/tokens.json"),
        };

        let (action, grant) = token_command_to_action(command);
        assert!(grant.is_none());
        assert!(matches!(action, TokenAction::List { .. }));
    }

    #[test]
    fn token_command_to_action_rotate() {
        use std::path::PathBuf;
        let command = TokenCommand::Rotate {
            tokens_file: PathBuf::from("/tmp/tokens.json"),
            name: "test".to_string(),
            server_pid: None,
        };

        let (action, grant) = token_command_to_action(command);
        assert!(grant.is_none());
        match action {
            TokenAction::Rotate { name, .. } => assert_eq!(name, "test"),
            _ => panic!("expected TokenAction::Rotate"),
        }
    }

    #[test]
    fn token_command_to_action_set_scope() {
        use std::path::PathBuf;
        let command = TokenCommand::SetScope {
            tokens_file: PathBuf::from("/tmp/tokens.json"),
            name: "test".to_string(),
            devices: Some(vec!["*".to_string()]),
            tools: Some(vec!["*".to_string()]),
            yes: false,
            server_pid: None,
        };

        let (action, grant) = token_command_to_action(command);
        assert!(grant.is_none());
        match action {
            TokenAction::SetScopes { name, .. } => assert_eq!(name, "test"),
            _ => panic!("expected TokenAction::SetScopes"),
        }
    }
}
