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

/// A token-mutation audit record, built before the mutation and emitted after.
///
/// The scope has to be captured up front because [`TokenAction`] is consumed by
/// the runtime call, but the record must not be written until the outcome is
/// known. Emitting on the way in produced audit lines asserting a credential
/// had been minted when the store write had in fact failed.
struct PendingTokenAudit {
    /// Stable operation identifier, e.g. `token_add`.
    operation: &'static str,
    /// Audit name of the token acted on.
    token_name: String,
    /// Requested controller scope, where the action carries one.
    devices: Option<Vec<String>>,
    /// Requested tool scope, where the action carries one.
    tools: Option<Vec<String>>,
    /// Whether the named token was in the store beforehand.
    ///
    /// `None` where the question does not apply (a mint). For the operations
    /// that address an existing token, this is what separates a real change
    /// from a no-op: the runtime returns `Ok(())` either way and reports the
    /// no-op only on stderr, so without this the audit trail would record a
    /// revocation of a token that was never there.
    target_existed: Option<bool>,
}

/// The outcome word for a token mutation that returned `Ok`.
///
/// `Ok` alone does not mean the store changed: revoking a name that is not
/// present succeeds and reports the no-op only on stderr. `target_existed` is
/// `None` where presence is not the question (a mint) or could not be read, and
/// those are reported as succeeded rather than silently downgraded.
fn success_outcome_word(target_existed: Option<bool>) -> &'static str {
    match target_existed {
        Some(false) => "no_op",
        _ => "succeeded",
    }
}

/// Whether `name` is present in the token store at `path`.
///
/// Reads only the `name` field of each entry; digests and secrets are never
/// touched. Returns `None` when the store cannot be read or parsed, so an
/// unreadable store is reported as unknown rather than as absence.
fn token_name_present(path: &std::path::Path, name: &str) -> Option<bool> {
    let raw = std::fs::read_to_string(path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let entries = parsed.get("tokens")?.as_array()?;
    Some(entries.iter().any(|entry| {
        entry.get("name").and_then(serde_json::Value::as_str) == Some(name)
    }))
}

impl PendingTokenAudit {
    /// Describe a mutating token action, or `None` for read-only ones.
    fn describe(action: &TokenAction) -> Option<Self> {
        match action {
            TokenAction::Add { name, devices, tools, .. } => Some(Self {
                operation: "token_add",
                token_name: name.clone(),
                devices: Some(devices.clone()),
                tools: Some(tools.clone()),
                target_existed: None,
            }),
            TokenAction::Revoke { name, tokens_file, .. } => Some(Self {
                operation: "token_revoke",
                token_name: name.clone(),
                devices: None,
                tools: None,
                target_existed: token_name_present(tokens_file, name),
            }),
            TokenAction::Rotate { name, tokens_file, .. } => Some(Self {
                operation: "token_rotate",
                token_name: name.clone(),
                devices: None,
                tools: None,
                target_existed: token_name_present(tokens_file, name),
            }),
            TokenAction::SetScopes { name, devices, tools, tokens_file, .. } => Some(Self {
                operation: "token_set_scope",
                token_name: name.clone(),
                devices: devices.clone(),
                tools: tools.clone(),
                target_existed: token_name_present(tokens_file, name),
            }),
            TokenAction::SetProvenance { name, tokens_file, .. } => Some(Self {
                operation: "token_set_provenance",
                token_name: name.clone(),
                devices: None,
                tools: None,
                target_existed: token_name_present(tokens_file, name),
            }),
            // Read-only: nothing changes, so there is nothing to attest to.
            TokenAction::List { .. } => None,
        }
    }

    /// Emit the record, carrying whether the mutation actually took effect.
    ///
    /// The failure branch records the error text so an auditor can tell a
    /// rejected mint from one that never reached the store. Scope fields are
    /// emitted only for the operations that carry scope, so a revoke does not
    /// render an empty device list that reads like a scope of nothing.
    fn emit<T, E: std::fmt::Display>(&self, outcome: Result<&T, &E>) {
        let (operation, token_name) = (self.operation, self.token_name.as_str());
        let applied = success_outcome_word(self.target_existed);
        let message = if applied == "no_op" {
            "token mutation matched no token"
        } else {
            "token mutation applied"
        };
        match (outcome, self.devices.as_deref(), self.tools.as_deref()) {
            (Ok(_), Some(devices), Some(tools)) => tracing::info!(
                target: "audit",
                operation,
                token_name,
                devices = ?devices,
                tools = ?tools,
                outcome = applied,
                message
            ),
            (Ok(_), _, _) => tracing::info!(
                target: "audit",
                operation,
                token_name,
                outcome = applied,
                message
            ),
            (Err(error), Some(devices), Some(tools)) => tracing::warn!(
                target: "audit",
                operation,
                token_name,
                devices = ?devices,
                tools = ?tools,
                outcome = "failed",
                error = %error,
                "token mutation failed"
            ),
            (Err(error), _, _) => tracing::warn!(
                target: "audit",
                operation,
                token_name,
                outcome = "failed",
                error = %error,
                "token mutation failed"
            ),
        }
    }
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

        // Describe the mutation now, emit the record after it runs.
        //
        // These records are the forensic trail for credential issuance. Emitting
        // them before execution logged "token minted" in the past tense for
        // mints that then failed -- an observed case wrote that line while the
        // store write returned ENOENT, leaving the audit trail asserting a
        // credential that does not exist. The scope is captured up front
        // because the action is consumed by the call; the outcome is attached
        // afterwards.
        let pending = PendingTokenAudit::describe(&action);

        let outcome = mecmcp_runtime::token_cmd::run_with_grant::<NoGrant>(
            action,
            &[],
            rustunifimcp_core::tools::TOOL_NAMES,
            grant,
        )
        .map_err(|error| anyhow::anyhow!("{error}"));

        if let Some(pending) = pending {
            pending.emit(outcome.as_ref());
        }

        return outcome;

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

    // Warn if --state-file is not provided.
    if cli.state_file.is_none() {
        tracing::warn!(
            target: "audit",
            "No --state-file provided; change sets will live in memory only. \
             Every approval, preview, and in-flight apply will be lost on restart. \
             Pass --state-file to persist change-set state across restarts."
        );
    }

    // Load registry.
    let registry = Arc::new(
        rustunifimcp_core::inventory::ControllerRegistry::load(&cli.controllers_file)?
    );

    // Build changeset store.
    let changeset_store = rustunifimcp::changeset_store::ChangeSetStore::new(cli.state_file.clone())
        .map_err(|e| anyhow::anyhow!("failed to initialize changeset store: {e}"))?;

    // Build server.
    let server = UnifiServer::new(Arc::clone(&registry), cli.lab_mode(), changeset_store)?;

    // Determine transport.
    match cli.common.transport {
        mecmcp_runtime::cli::Transport::Stdio => {
            // SIGHUP reloads the inventory and rebuilds clients.
            // Clone the server for the reload handler; serve_stdio consumes the original.
            install_sighup_reload(registry, Some(server.clone()), None)?;
            serve_stdio(server).await
        }
        mecmcp_runtime::cli::Transport::StreamableHttp => {
            serve_http(server, &cli, registry).await
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

/// Install a SIGHUP handler that reloads configuration.
///
/// On SIGHUP:
/// - Controller inventory is reloaded from disk
/// - HTTP clients are rebuilt from the new inventory
/// - Token store is reloaded (HTTP mode only)
///
/// A reload failure logs at `warn` and retains the previous configuration rather
/// than terminating the running server.
///
/// # Errors
///
/// Returns error if the signal handler could not be registered.
fn install_sighup_reload(
    registry: Arc<rustunifimcp_core::inventory::ControllerRegistry>,
    server: Option<UnifiServer>,
    token_store: Option<Arc<mecmcp_auth::TokenStoreFile<mecmcp_auth::NoGrant>>>,
) -> std::io::Result<()> {
    mecmcp_runtime::signals::install_hup_handler(move || {
        // Reload controller inventory.
        let registry_reloaded = match registry.reload() {
            Ok(count) => {
                tracing::info!(
                    target: "audit",
                    controllers = count,
                    "controller inventory reloaded"
                );
                true
            }
            Err(error) => {
                tracing::warn!(
                    target: "audit",
                    %error,
                    "controller inventory reload failed; retaining previous snapshot"
                );
                false
            }
        };

        // Rebuild clients if inventory reload succeeded.
        if registry_reloaded && let Some(ref srv) = server {
            match srv.rebuild_clients() {
                Ok(count) => {
                    tracing::info!(
                        target: "audit",
                        clients = count,
                        "HTTP clients rebuilt from reloaded inventory"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        target: "audit",
                        %error,
                        "client rebuild failed; retaining previous clients"
                    );
                }
            }
        }

        // Reload token store if present (HTTP mode only).
        if let Some(ref store) = token_store {
            match store.reload() {
                Ok(()) => {
                    let count = store.store().len();
                    tracing::info!(
                        target: "audit",
                        tokens = count,
                        "token store reloaded"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        target: "audit",
                        %error,
                        "token store reload failed; retaining previous snapshot"
                    );
                }
            }
        }
    })
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
    registry: Arc<rustunifimcp_core::inventory::ControllerRegistry>,
) -> Result<()> {

    // Load token store if provided.
    let token_store = if let Some(ref path) = cli.common.tokens_file {
        Some(Arc::new(
            mecmcp_auth::TokenStoreFile::load(path)?
        ))
    } else {
        None
    };

    // Install SIGHUP handler that reloads inventory, rebuilds clients, and reloads token store.
    // Clone the handler for the reload callback; build_http_router consumes the original.
    install_sighup_reload(registry, Some(handler.clone()), token_store.clone())?;

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

    #[tokio::test]
    async fn sighup_handler_installs_without_token_store() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create a minimal valid controllers.json
        let mut controllers_file = NamedTempFile::new().unwrap();
        writeln!(controllers_file, "{{}}").unwrap();
        controllers_file.flush().unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(controllers_file.path())
                .unwrap()
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(controllers_file.path(), perms).unwrap();
        }

        let registry = Arc::new(
            rustunifimcp_core::inventory::ControllerRegistry::load(controllers_file.path())
                .unwrap()
        );

        let changeset_store = rustunifimcp::changeset_store::ChangeSetStore::new(None).unwrap();

        // Build a server for the reload handler.
        let server = UnifiServer::new(Arc::clone(&registry), false, changeset_store).unwrap();

        // Should install successfully without a token store.
        let result = install_sighup_reload(registry, Some(server), None);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn sighup_handler_installs_with_token_store() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create a minimal valid controllers.json
        let mut controllers_file = NamedTempFile::new().unwrap();
        writeln!(controllers_file, "{{}}").unwrap();
        controllers_file.flush().unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(controllers_file.path())
                .unwrap()
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(controllers_file.path(), perms).unwrap();
        }

        // Create a minimal valid tokens.json
        let mut tokens_file = NamedTempFile::new().unwrap();
        writeln!(tokens_file, r#"{{"version": 1, "tokens": []}}"#).unwrap();
        tokens_file.flush().unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(tokens_file.path())
                .unwrap()
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(tokens_file.path(), perms).unwrap();
        }

        let registry = Arc::new(
            rustunifimcp_core::inventory::ControllerRegistry::load(controllers_file.path())
                .unwrap()
        );

        let changeset_store = rustunifimcp::changeset_store::ChangeSetStore::new(None).unwrap();
        let server = UnifiServer::new(Arc::clone(&registry), false, changeset_store).unwrap();

        let token_store = Arc::new(
            mecmcp_auth::TokenStoreFile::load(tokens_file.path()).unwrap()
        );

        // Should install successfully with a token store.
        let result = install_sighup_reload(registry, Some(server), Some(token_store));
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn malformed_inventory_reload_retains_previous_config() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create initial valid controllers.json
        let mut controllers_file = NamedTempFile::new().unwrap();
        writeln!(controllers_file, "{{}}").unwrap();
        controllers_file.flush().unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(controllers_file.path())
                .unwrap()
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(controllers_file.path(), perms).unwrap();
        }

        let registry = Arc::new(
            rustunifimcp_core::inventory::ControllerRegistry::load(controllers_file.path())
                .unwrap()
        );

        // Verify initial load worked
        assert_eq!(registry.names().len(), 0);

        // Now corrupt the file
        std::fs::write(controllers_file.path(), "not valid json").unwrap();

        // Reload should fail but not panic
        let result = registry.reload();
        assert!(result.is_err());

        // The registry should still be usable with the previous config
        assert_eq!(registry.names().len(), 0);
    }

    #[tokio::test]
    async fn client_rebuild_after_reload() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create initial valid controllers.json with no controllers
        let mut controllers_file = NamedTempFile::new().unwrap();
        writeln!(controllers_file, "{{}}").unwrap();
        controllers_file.flush().unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(controllers_file.path())
                .unwrap()
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(controllers_file.path(), perms).unwrap();
        }

        let registry = Arc::new(
            rustunifimcp_core::inventory::ControllerRegistry::load(controllers_file.path())
                .unwrap()
        );

        let changeset_store = rustunifimcp::changeset_store::ChangeSetStore::new(None).unwrap();
        let server = UnifiServer::new(Arc::clone(&registry), false, changeset_store).unwrap();

        // Initial state: no controllers, no clients
        assert_eq!(registry.names().len(), 0);

        // Reload should succeed with empty config
        let result = registry.reload();
        assert!(result.is_ok());

        // Rebuild clients should succeed
        let rebuild_result = server.rebuild_clients();
        assert!(rebuild_result.is_ok());
        assert_eq!(rebuild_result.unwrap(), 0);
    }

}

#[cfg(test)]
mod audit_tests {
    use super::*;
    use std::io::Write;

    fn store_with(names: &[&str]) -> tempfile::NamedTempFile {
        let entries: Vec<_> = names
            .iter()
            .map(|name| serde_json::json!({ "name": name, "digest": "x", "devices": [], "tools": [] }))
            .collect();
        let body = serde_json::json!({ "version": 1, "tokens": entries });
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        write!(file, "{body}").expect("write store");
        file
    }

    #[test]
    fn a_revoke_that_matches_nothing_is_not_reported_as_a_change() {
        // The runtime returns Ok whether or not the name was there, so this is
        // the only thing standing between the audit trail and a recorded
        // revocation of a token that never existed.
        assert_eq!(success_outcome_word(Some(false)), "no_op");
        assert_eq!(success_outcome_word(Some(true)), "succeeded");
    }

    #[test]
    fn an_unreadable_store_does_not_masquerade_as_an_absent_token() {
        // Unknown must not collapse into "absent" -- that would report a real
        // revocation as a no-op and hide it from the trail.
        assert_eq!(success_outcome_word(None), "succeeded");
    }

    #[test]
    fn presence_is_read_from_the_store_by_name() {
        let store = store_with(&["alpha", "beta"]);
        assert_eq!(token_name_present(store.path(), "alpha"), Some(true));
        assert_eq!(token_name_present(store.path(), "gamma"), Some(false));
    }

    #[test]
    fn a_missing_or_malformed_store_reads_as_unknown_not_absent() {
        assert_eq!(token_name_present(std::path::Path::new("/nonexistent/t.json"), "a"), None);
        let mut bad = tempfile::NamedTempFile::new().expect("temp file");
        write!(bad, "not json").expect("write");
        assert_eq!(token_name_present(bad.path(), "a"), None);
    }

    #[test]
    fn describing_a_revoke_records_whether_the_target_was_there() {
        let store = store_with(&["present"]);
        let describe = |name: &str| {
            PendingTokenAudit::describe(&TokenAction::Revoke {
                tokens_file: store.path().to_path_buf(),
                name: name.to_owned(),
                server_pid: None,
            })
            .expect("revoke is a mutating action")
            .target_existed
        };
        assert_eq!(describe("present"), Some(true));
        assert_eq!(describe("absent"), Some(false));
    }

    #[test]
    fn listing_tokens_produces_no_audit_record() {
        let store = store_with(&["a"]);
        assert!(
            PendingTokenAudit::describe(&TokenAction::List {
                tokens_file: store.path().to_path_buf(),
            })
            .is_none(),
            "a read-only list must not write a mutation record"
        );
    }
}
