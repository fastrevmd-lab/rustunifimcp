//! Transport assembly.
//!
//! The bearer boundary and per-IP rate limiting are both applied inside
//! `build_streamable_http_router` as of mecmcp-transport 0.8.8, so the consumer
//! builds the configuration and passes it in.

use crate::server::UnifiServer;
use mecmcp_auth::{BearerSyntax, CallerCtx, NoGrant, TokenStoreFile};
use mecmcp_transport::{
    BearerAuthenticator, BearerBoundary, BearerResponseProfile, HostOriginPolicy,
    HttpTransportBuildError, HttpTransportConfig, InsecureBindAcknowledgement, LimitsConfig,
    MalformedArgumentsPolicy, NoAuthAcknowledgement, ServePlan, TargetField, ToolScopePreflight,
    TransportIdentity, build_streamable_http_router,
};
use rustunifimcp_core::tools::WRITE_TOOLS;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Build the stage-1 preflight: tool scope and controller scope, with no I/O.
#[must_use]
pub fn build_preflight() -> ToolScopePreflight {
    ToolScopePreflight::new(
        WRITE_TOOLS,
        [TargetField::scalar("controller")],
        MalformedArgumentsPolicy::Deny,
    )
}

/// Build the complete HTTP router with UniFi-owned identity and scope fields.
///
/// Exposed publicly so end-to-end tests exercise the same assembly `main` uses.
///
/// # Errors
///
/// Returns an error when shared HTTP limits or router composition are invalid.
#[allow(clippy::too_many_arguments)]
pub fn build_http_router(
    handler: UnifiServer,
    token_store: Option<Arc<TokenStoreFile<NoGrant>>>,
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    limits: LimitsConfig,
    enable_metrics: bool,
    allow_insecure_bind: bool,
    shutdown: CancellationToken,
) -> Result<ServePlan, HttpTransportBuildError> {
    let identity =
        TransportIdentity::new("rustunifimcp", "unifi", "rustunifimcp", ["controller"]);
    let host_origin = HostOriginPolicy::enforced(allowed_hosts, allowed_origins);

    let config = if let Some(store_file) = token_store {
        let auth_store = store_file.clone();
        let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, move |candidate| {
            let snapshot = auth_store.store();
            snapshot.authenticate(candidate).map(CallerCtx::from)
        });
        let boundary = BearerBoundary::new(
            authenticator,
            BearerResponseProfile::detailed("rustunifimcp"),
        )
        .with_preflight(build_preflight());
        let mut config =
            HttpTransportConfig::authenticated(identity, limits, host_origin, shutdown, boundary)
                .with_metrics(enable_metrics);
        if allow_insecure_bind {
            config = config
                .with_insecure_bind(InsecureBindAcknowledgement::operator_allowed_insecure_bind());
        }
        config
    } else {
        let mut config = HttpTransportConfig::unauthenticated(
            identity,
            limits,
            host_origin,
            shutdown,
            NoAuthAcknowledgement::operator_allowed_no_auth(),
        )
        .with_metrics(enable_metrics);
        if allow_insecure_bind {
            config = config
                .with_insecure_bind(InsecureBindAcknowledgement::operator_allowed_insecure_bind());
        }
        config
    };

    build_streamable_http_router(move || Ok::<_, std::io::Error>(handler.clone()), config)
}
