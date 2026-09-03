//! Command-line surface.
//!
//! `mecmcp_runtime::cli::Cli` is flattened rather than reimplemented, so every
//! shared flag — transport, bind, TLS, allowed hosts, audit — behaves exactly as
//! it does on the sibling servers.
//!
//! Token management is intercepted before parsing to prevent grant flags
//! (`--sites`, `--actions`) from appearing in the server's help. See
//! [`TokenCli`] and the dispatch logic in `main.rs`.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// `rustunifimcp` command line.
#[derive(Debug, Parser)]
#[command(name = "rustunifimcp", version)]
pub struct UnifiCli {
    /// Flags shared with the rest of the mechub MCP family.
    ///
    /// Carries the SSDF evidence flag group (`--ssdf-audit-*`), which this
    /// server advertised and never consumed: `mecmcp-audit` was a declared
    /// dependency imported nowhere, so the flags parsed and did nothing.
    #[command(flatten)]
    pub common: mecmcp_runtime::cli::Cli,

    /// Controller inventory. Must be mode 0600 and owned by the service user.
    #[arg(long, default_value = "/etc/unifimcp/controllers.json")]
    pub controllers_file: PathBuf,

    /// Run without two-person control for destructive operations.
    ///
    /// For a single-operator lab. No approver is invented: a waived change set
    /// records `approver: null` with a lab-mode waiver, so it stays
    /// distinguishable from one a second person reviewed.
    ///
    /// Spelled identically on every mecmcp server.
    #[arg(long = "lab-mode")]
    pub lab_mode: bool,

    /// Absolute path to the change-set and operation state file.
    ///
    /// Spelled `--state-file` on every mecmcp server, per
    /// `mecmcp/docs/PACKAGING.md`. **Without it the coordinator keeps change
    /// sets in memory only**: every approval, preview and in-flight apply is
    /// lost on restart.
    ///
    /// Left optional rather than defaulted so an existing deployment does not
    /// silently start writing a file its unit never provisioned; the packaged
    /// unit passes `$STATE_DIRECTORY/changeset-state.json`, and startup warns
    /// loudly when it is unset.
    #[arg(long = "state-file")]
    pub state_file: Option<PathBuf>,

    /// How long a change set stays usable, in seconds.
    ///
    /// Spelled `--approval-timeout-secs` on every mecmcp server, and it
    /// configures the change-set coordinator's approval TTL -- which is what
    /// actually expires an approval, rather than a window this server measured
    /// itself.
    ///
    /// The window runs from the moment something is **staged**, not from
    /// approval. So the default 300 seconds bounds the review-and-apply round,
    /// and it bounds the age of the pre-image the plan was built against, which
    /// is the point: a pre-image captured half an hour ago is not evidence
    /// about the controller now. Raise it if a review takes longer than the
    /// round it gates.
    #[arg(long = "approval-timeout-secs", default_value = "300")]
    pub approval_timeout_secs: u64,
}

impl UnifiCli {
    /// Whether lab mode is enabled.
    #[must_use]
    pub fn lab_mode(&self) -> bool {
        self.lab_mode
    }
}

/// Token management CLI, parsed only when argv starts with `token`.
///
/// This is dispatched before `UnifiCli` to keep grant-specific flags
/// (`--sites`, `--actions`) off the server's help text.
#[derive(Debug, Parser)]
#[command(name = "rustunifimcp", version)]
pub struct TokenCli {
    /// Token subcommand (add, revoke, list, rotate, set-scope).
    #[command(subcommand)]
    pub command: TokenCommand,
}

/// Token subcommands.
#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// Mint a new token and append to the file.
    Add {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Stable audit name for the token.
        #[arg(long)]
        name: String,
        /// Comma-separated controller names, or '*' for all.
        #[arg(long, value_delimiter = ',')]
        devices: Vec<String>,
        /// Comma-separated tool names, or '*' for read-only tools only.
        #[arg(long, value_delimiter = ',')]
        tools: Vec<String>,
        /// Provider name (e.g., "anthropic", "ollama"). Optional.
        #[arg(long)]
        provider: Option<String>,
        /// Provider tier: "public" or "private". Required if provider is set.
        #[arg(long)]
        provider_tier: Option<String>,
        /// The human on whose behalf this credential acts. Optional.
        #[arg(long)]
        on_behalf_of: Option<String>,
        /// Actor type: "human", "agent", or "unknown". Optional.
        #[arg(long)]
        actor_type: Option<String>,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// Revoke a token by name.
    Revoke {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token name to revoke.
        #[arg(long)]
        name: String,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// List all tokens in the store.
    List {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
    },
    /// Rotate a token's secret, preserving its grant.
    Rotate {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token name to rotate.
        #[arg(long)]
        name: String,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// Change an existing token's scopes without reissuing its secret.
    SetScope {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token audit name.
        #[arg(long)]
        name: String,
        /// Replacement device scope. Omit to leave unchanged.
        #[arg(long, value_delimiter = ',')]
        devices: Option<Vec<String>>,
        /// Replacement tool scope. Omit to leave unchanged.
        #[arg(long, value_delimiter = ',')]
        tools: Option<Vec<String>>,
        /// Apply a widening without the interactive confirmation.
        #[arg(long)]
        yes: bool,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
}

/// Validate configuration without starting the server.
#[derive(Debug, Parser)]
#[command(name = "rustunifimcp", version)]
pub struct ValidateConfigCli {
    /// Controller inventory to validate.
    #[arg(long)]
    pub controllers_file: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// --lab-mode is CLI-only and must never be readable from a config file.
    /// mecmcp#267 decided this: a relaxed security control should be visible
    /// where someone will see it, and a boolean in a product config file is
    /// strictly less visible than a flag in a unit file, not more.
    #[test]
    fn lab_mode_is_a_flag_and_defaults_off() {
        let cli = UnifiCli::try_parse_from([
            "rustunifimcp",
            "--controllers-file",
            "/etc/unifimcp/controllers.json",
        ])
        .expect("parses");
        assert!(!cli.lab_mode());

        let cli = UnifiCli::try_parse_from([
            "rustunifimcp",
            "--controllers-file",
            "/etc/unifimcp/controllers.json",
            "--lab-mode",
        ])
        .expect("parses");
        assert!(cli.lab_mode());
    }

    /// There must be no way to ask for unverified TLS. If this test ever needs
    /// changing, the deployment is wrong, not the test.
    #[test]
    fn there_is_no_insecure_tls_flag() {
        for flag in [
            "--insecure",
            "--no-verify-tls",
            "--insecure-skip-verify",
            "--tls-no-verify",
        ] {
            let parsed = UnifiCli::try_parse_from([
                "rustunifimcp",
                "--controllers-file",
                "/etc/unifimcp/controllers.json",
                flag,
            ]);
            assert!(parsed.is_err(), "{flag} must not be accepted");
        }
    }
}
