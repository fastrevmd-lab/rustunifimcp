//! The one error type for the core crate.
//!
//! Two properties are load-bearing and are tested. A private-surface endpoint
//! that has disappeared renders as attributable drift rather than a generic
//! failure — that is the whole reason endpoints carry their surface tag. And no
//! variant carries a URL or a header, because the controller's API key travels
//! in one.

use crate::ApiSurface;

/// Anything that can go wrong talking to a UniFi controller.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UnifiError {
    /// A private, undocumented endpoint is no longer present on this controller.
    ///
    /// Attributable by construction: the surface, the path and the controller
    /// version are all named, so this reads as drift rather than a tool fault.
    #[error(
        "private API {surface:?} path {path} is not present on controller version \
         {controller_version}; this endpoint is undocumented and may have been \
         removed by a controller upgrade"
    )]
    PrivateEndpointAbsent {
        /// Which private surface the path belongs to.
        surface: ApiSurface,
        /// The path that returned 404.
        path: String,
        /// The controller version that no longer serves it.
        controller_version: String,
    },

    /// The caller's token lacks the scope this surface requires.
    #[error("surface {surface:?} requires the `unifi:private-api` scope")]
    SurfaceNotPermitted {
        /// The surface that was refused.
        surface: ApiSurface,
    },

    /// The controller returned a non-success status.
    ///
    /// Deliberately carries no URL: the API key travels in a header on every
    /// request, and an error string is the easiest place for one to leak.
    #[error("controller returned {status}: {detail}")]
    Upstream {
        /// HTTP status code.
        status: u16,
        /// Server-supplied detail, already bounded by the caller.
        detail: String,
    },

    /// A response did not match the shape the model expects.
    #[error("unexpected response shape: {0}")]
    Malformed(String),

    /// Transport, TLS, timeout, or rate-limit failure from `mecmcp-http`.
    #[error(transparent)]
    Http(#[from] mecmcp_http::HttpError),

    /// Inventory load or validation failure.
    #[error(transparent)]
    Inventory(#[from] mecmcp_inventory::InventoryError),

    /// Credential load failure — bad mode, symlink, oversized, or absent.
    #[error(transparent)]
    Secret(#[from] mecmcp_secret::SecretError),
}

#[cfg(test)]
mod tests {
    use super::UnifiError;

    /// A private-surface 404 must name the surface and the version, because
    /// that is the difference between "the controller changed" and "the tool
    /// is broken".
    #[test]
    fn a_private_route_gone_reads_as_drift_not_a_generic_failure() {
        let error = UnifiError::PrivateEndpointAbsent {
            surface: crate::ApiSurface::PrivateV2,
            path: "/v2/api/site/default/traffic-flows".to_owned(),
            controller_version: "9.1.0".to_owned(),
        };
        let rendered = error.to_string();
        assert!(rendered.contains("PrivateV2"), "{rendered}");
        assert!(rendered.contains("/v2/api/site/default/traffic-flows"), "{rendered}");
        assert!(rendered.contains("9.1.0"), "{rendered}");
    }

    /// The controller's API key must never reach an error string.
    #[test]
    fn upstream_errors_do_not_carry_the_url() {
        let error = UnifiError::Upstream {
            status: 401,
            detail: "unauthorized".to_owned(),
        };
        let rendered = error.to_string();
        assert!(!rendered.contains("X-API-KEY"), "{rendered}");
        assert!(!rendered.contains("https://"), "{rendered}");
    }
}
