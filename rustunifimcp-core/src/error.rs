//! The one error type for the core crate.
//!
//! Two properties are load-bearing and are tested. A private-surface endpoint
//! that has disappeared renders as attributable drift rather than a generic
//! failure — that is the whole reason endpoints carry their surface tag. And no
//! variant carries a URL or a header, because the controller's API key travels
//! in one.

use crate::ApiSurface;

/// Maximum bytes for server-supplied detail text before truncation.
const MAX_DETAIL_BYTES: usize = 300;

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

    /// The controller has not opted into this surface via `controllers.json`.
    ///
    /// Fix by editing the controller's `allow_private_api` or `allow_cloud`
    /// field in `controllers.json`, not by reissuing a token.
    #[error(
        "surface {surface:?} requires allow_private_api or allow_cloud set in \
         controllers.json"
    )]
    SurfaceRequiresConfig {
        /// The surface that was refused.
        surface: ApiSurface,
    },

    /// The caller's token lacks the scope this surface requires.
    ///
    /// Fix by reissuing the token with the `unifi:private-api` scope. This
    /// variant is not yet returned — scope enforcement lands with the tool
    /// layer.
    #[error("surface {surface:?} requires the `unifi:private-api` scope")]
    SurfaceRequiresScope {
        /// The surface that was refused.
        surface: ApiSurface,
    },

    /// The controller returned a non-success status.
    ///
    /// Deliberately carries no URL: the API key travels in a header on every
    /// request, and an error string is the easiest place for one to leak.
    ///
    /// The `detail` field is bounded and sanitized at construction to prevent
    /// unbounded server-supplied text from reaching logs or audit records.
    #[error("controller returned {status}: {detail}")]
    Upstream {
        /// HTTP status code.
        status: u16,
        /// Server-supplied detail, bounded and sanitized at construction.
        detail: String,
    },

    /// A response did not match the shape the model expects.
    #[error("unexpected response shape: {0}")]
    Malformed(String),

    /// Transport, TLS, timeout, or rate-limit failure from `mecmcp-http`.
    ///
    /// The underlying error is classified and rendered without URLs, because
    /// several `HttpError` variants carry a redacted URL. This crate's contract
    /// is that no variant carries a URL of any kind, and that includes the
    /// source chain.
    #[error("{}", http_error_class(.0))]
    Http(mecmcp_http::HttpError),

    /// Inventory load or validation failure.
    #[error(transparent)]
    Inventory(#[from] mecmcp_inventory::InventoryError),

    /// Credential load failure — bad mode, symlink, oversized, or absent.
    #[error(transparent)]
    Secret(#[from] mecmcp_secret::SecretError),
}

impl From<mecmcp_http::HttpError> for UnifiError {
    fn from(error: mecmcp_http::HttpError) -> Self {
        Self::Http(error)
    }
}

/// Render the class of HTTP failure without the URL.
///
/// Several `HttpError` variants carry a redacted `SafeUrl`, which still renders
/// as `scheme://host/path`. This function extracts the failure class — timeout,
/// connection failure, TLS failure, body-too-large, queue-full — so the error
/// message conveys the nature of the failure without exposing any URL component.
fn http_error_class(error: &mecmcp_http::HttpError) -> String {
    use mecmcp_http::HttpError;
    match error {
        HttpError::InvalidUrl { .. } => "invalid URL".to_owned(),
        HttpError::InsecureScheme { scheme, .. } => {
            format!("insecure scheme '{scheme}' (only https:// is allowed)")
        }
        HttpError::MissingHost { .. } => "URL has no host component".to_owned(),
        HttpError::UrlHasEmbeddedCredentials { .. } => "URL embeds credentials".to_owned(),
        HttpError::InvalidHeaderName { name } => format!("invalid header name '{name}'"),
        HttpError::FramingHeaderNotAllowed { name } => format!("header '{name}' cannot be supplied"),
        HttpError::InvalidHeaderValue { name } => format!("invalid header value for '{name}'"),
        HttpError::ConfigValidation { field, detail } => {
            format!("configuration field '{field}': {detail}")
        }
        HttpError::NoCryptoProvider => "no rustls CryptoProvider installed".to_owned(),
        HttpError::InvalidRootCertificate { index, .. } => {
            format!("extra_root_certificates[{index}] is not a usable certificate")
        }
        HttpError::ClientConstruction { .. } => "failed to construct HTTP client".to_owned(),
        HttpError::Timeout { timeout, .. } => format!("request timed out after {timeout:?}"),
        HttpError::QueueFull => "HTTP client queue is full".to_owned(),
        HttpError::LimiterClosed => "HTTP client concurrency limiter is closed".to_owned(),
        HttpError::Connect { .. } => "failed to connect".to_owned(),
        HttpError::ResponseTooLarge { limit, .. } => {
            format!("response exceeded the {limit}-byte limit")
        }
        HttpError::BodyRead { .. } => "failed to read response body".to_owned(),
        HttpError::RequestFailed { .. } => "request failed".to_owned(),
    }
}

/// Bound and sanitize server-supplied detail text.
///
/// Caps the text to [`MAX_DETAIL_BYTES`] and strips control characters,
/// including newlines and carriage returns, so a single-line error stays a
/// single line. A hostile or merely broken upstream cannot inject unbounded
/// text or forge log entries.
///
/// Similar to `mecmcp_server::bounded_text` but also sanitizes control
/// characters. `mecmcp_server`'s version does not sanitize, so this
/// crate writes its own.
pub(crate) fn sanitize_detail(input: &str) -> String {
    let bounded = input
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_DETAIL_BYTES)
        .collect::<String>();

    if bounded.len() < input.len() {
        format!("{bounded} [truncated]")
    } else {
        bounded
    }
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
    ///
    /// This is the contract: no variant renders a URL of any kind — neither a
    /// full URL nor a redacted one — and that includes the source chain.
    #[test]
    fn no_variant_carries_a_url() {
        use std::error::Error;

        // Test each variant that could plausibly carry a URL
        let test_cases: Vec<UnifiError> = vec![
            UnifiError::PrivateEndpointAbsent {
                surface: crate::ApiSurface::PrivateV2,
                path: "/v2/api/site/default/traffic-flows".to_owned(),
                controller_version: "9.1.0".to_owned(),
            },
            UnifiError::SurfaceRequiresConfig {
                surface: crate::ApiSurface::PrivateV1,
            },
            UnifiError::SurfaceRequiresScope {
                surface: crate::ApiSurface::PrivateV2,
            },
            UnifiError::Upstream {
                status: 401,
                detail: "unauthorized".to_owned(),
            },
            UnifiError::Malformed("test error".to_owned()),
            // Http variant with a URL-carrying error
            UnifiError::Http(mecmcp_http::HttpError::Timeout {
                url: mecmcp_http::SafeUrl::from_unparsed("https://controller.example/api/test"),
                timeout: std::time::Duration::from_secs(30),
            }),
            UnifiError::Http(mecmcp_http::HttpError::Connect {
                url: mecmcp_http::SafeUrl::from_unparsed("https://controller.example/api/test"),
                detail: "connection refused".to_owned(),
            }),
        ];

        for error in test_cases {
            // Check the top-level Display
            let rendered = error.to_string();
            assert!(!rendered.contains("://"), "variant rendered a URL: {rendered}");
            assert!(!rendered.contains("X-API-KEY"), "variant rendered a header: {rendered}");

            // Check the full source chain with {:#}
            let alternate = format!("{error:#}");
            assert!(!alternate.contains("://"), "source chain contains URL: {alternate}");

            // Walk the source() chain
            let mut current: &dyn Error = &error;
            while let Some(source) = current.source() {
                let source_str = source.to_string();
                assert!(!source_str.contains("://"), "source chain contains URL: {source_str}");
                current = source;
            }
        }
    }
}
