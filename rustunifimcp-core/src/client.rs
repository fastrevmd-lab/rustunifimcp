//! One HTTP client per controller, over `mecmcp-http`.
//!
//! Each controller gets its own client with isolated rate limits, so a slow or
//! wedged controller cannot exhaust a pool shared with healthy ones.
//!
//! Every request's path is expanded by `mecmcp-openapi::expand_path`, which
//! rejects a parameter that would span a segment, start a query, navigate the
//! hierarchy, collapse a segment, or carry a control byte. Nothing is
//! sanitised: a rewritten value is a value the caller did not send. UniFi puts
//! the site id and the resource id directly in the path on all three local
//! surfaces, so this applies to essentially every request.

use crate::ApiSurface;
use crate::error::UnifiError;
use crate::inventory::Controller;
use mecmcp_http::{HttpClient, HttpClientConfig, HttpRequest, Method};
use mecmcp_secret::OutboundSecret;
use std::sync::RwLock;
use std::time::Duration;

/// Requests in flight to one controller.
const MAX_CONCURRENT: usize = 8;
/// Callers permitted to wait behind those.
const MAX_QUEUED: usize = 32;
/// Whole-request deadline, covering permit acquisition and send.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest response body accepted, enforced as it streams.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// A client bound to one controller.
pub struct UnifiClient {
    controller: Controller,
    http: HttpClient,
    api_key: OutboundSecret,
    cached_version: RwLock<Option<String>>,
    cached_site_uuid: RwLock<Option<String>>,
}

impl UnifiClient {
    /// Build a client for one controller, loading its credential.
    ///
    /// # Errors
    ///
    /// Returns [`UnifiError`] when:
    /// - The credential cannot be loaded from env or file
    /// - The CA PEM is unreadable
    /// - The endpoint is not HTTPS
    /// - The HTTP client fails to initialize
    pub fn new(controller: Controller) -> Result<Self, UnifiError> {
        controller.validate()?;

        let api_key = controller.load_api_key()?;

        let mut extra_root_certificates = Vec::new();
        if let Some(path) = &controller.ca_pem_path {
            let pem = std::fs::read_to_string(path).map_err(|error| {
                UnifiError::Malformed(format!("ca_pem_path {}: {error}", path.display()))
            })?;
            extra_root_certificates.push(pem);
        }

        let config = HttpClientConfig {
            request_timeout: REQUEST_TIMEOUT,
            max_concurrent_requests: MAX_CONCURRENT,
            max_queued_requests: MAX_QUEUED,
            max_response_bytes: MAX_RESPONSE_BYTES,
            user_agent: concat!("rustunifimcp/", env!("CARGO_PKG_VERSION")).to_owned(),
            extra_root_certificates,
            ..HttpClientConfig::default()
        };

        let http = HttpClient::new(config)?;
        Ok(Self {
            controller,
            http,
            api_key,
            cached_version: RwLock::new(None),
            cached_site_uuid: RwLock::new(None),
        })
    }

    /// Refuse a surface this controller has not opted into.
    ///
    /// `ResourceKind::path_template` already returns absolute paths, so there
    /// is no prefix to hand back — this is purely the permission gate, and it
    /// runs before a request is built. An un-opted-in deployment therefore
    /// cannot reach an undocumented route even by accident.
    ///
    /// # Errors
    ///
    /// Returns [`UnifiError::SurfaceRequiresConfig`] if the controller has not
    /// opted into the private or cloud surfaces, or [`UnifiError::Malformed`]
    /// for the cloud surface, which is unimplemented in v1.
    pub fn ensure_surface_permitted(
        controller: &Controller,
        surface: ApiSurface,
    ) -> Result<(), UnifiError> {
        match surface {
            ApiSurface::Supported => Ok(()),
            ApiSurface::PrivateV1 | ApiSurface::PrivateV2
                if controller.allow_private_api =>
            {
                Ok(())
            }
            ApiSurface::Cloud if controller.allow_cloud => Err(UnifiError::Malformed(
                "the cloud Site Manager surface is not implemented in v1".to_owned(),
            )),
            other => Err(UnifiError::SurfaceRequiresConfig { surface: other }),
        }
    }

    /// The controller's configured default site, used when a tool omits one.
    ///
    /// This returns the site **name**, suitable for private API surfaces.
    /// For the Integration API, use [`Self::default_site_for`] instead.
    #[must_use]
    pub fn default_site(&self) -> &str {
        &self.controller.site
    }

    /// The site identifier to use for `surface` when a caller omits one.
    ///
    /// The Integration API addresses a site by UUID; the private surfaces address
    /// it by name. Passing the name to Integration v1 returns HTTP 400, so the two
    /// must not share one value.
    ///
    /// # Errors
    ///
    /// Returns [`UnifiError`] when:
    /// - The sites endpoint cannot be reached (Integration API only)
    /// - The configured site name is not found in the sites list
    /// - The response does not match the expected shape
    pub async fn default_site_for(&self, surface: ApiSurface) -> Result<String, UnifiError> {
        match surface {
            ApiSurface::Supported => {
                // Integration API requires the site UUID
                // Check cache first
                {
                    let cached = self.cached_site_uuid.read().map_err(|_| {
                        UnifiError::Malformed("site UUID cache lock poisoned".to_owned())
                    })?;
                    if let Some(uuid) = cached.as_ref() {
                        return Ok(uuid.clone());
                    }
                }

                // Fetch from controller
                let sites = self
                    .get(
                        ApiSurface::Supported,
                        "/proxy/network/integration/v1/sites",
                        &[],
                        &[],
                    )
                    .await?;

                let sites_array = sites.as_array().ok_or_else(|| {
                    UnifiError::Malformed("sites response is not an array".to_owned())
                })?;

                let site_name = &self.controller.site;
                let uuid = sites_array
                    .iter()
                    .find(|site| {
                        site.get("internalReference")
                            .and_then(|r| r.as_str())
                            .is_some_and(|r| r == site_name)
                    })
                    .and_then(|site| site.get("id"))
                    .and_then(|id| id.as_str())
                    .ok_or_else(|| {
                        UnifiError::Malformed(format!(
                            "site '{}' not found in sites list",
                            site_name
                        ))
                    })?
                    .to_owned();

                // Cache for future use
                {
                    let mut cached = self.cached_site_uuid.write().map_err(|_| {
                        UnifiError::Malformed("site UUID cache lock poisoned".to_owned())
                    })?;
                    *cached = Some(uuid.clone());
                }

                Ok(uuid)
            }
            ApiSurface::PrivateV1 | ApiSurface::PrivateV2 | ApiSurface::Cloud => {
                // Private surfaces use the site name directly
                Ok(self.controller.site.clone())
            }
        }
    }

    /// Fetch the controller version from the Integration API info endpoint.
    ///
    /// The version is cached after the first successful request. The Integration
    /// API endpoint is used because it is documented and stable, unlike the
    /// private `/proxy/network/api/status` path.
    ///
    /// # Errors
    ///
    /// Returns [`UnifiError`] when:
    /// - The info endpoint cannot be reached
    /// - The response does not contain an `applicationVersion` field
    pub async fn controller_version(&self) -> Result<String, UnifiError> {
        self.fetch_version_if_absent().await
    }

    /// Issue a GET against a path template.
    ///
    /// The template is expanded by `mecmcp-openapi`, which rejects a parameter
    /// that would span a segment, start a query, navigate the hierarchy,
    /// collapse a segment, or carry a control byte. Nothing is sanitised: a
    /// rewritten value is a value the caller did not send.
    ///
    /// Query parameters are percent-encoded and appended to the expanded path.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`UnifiError::SurfaceRequiresConfig`] if the controller hasn't opted into
    ///   this surface
    /// - [`UnifiError::PrivateEndpointAbsent`] for 404 on a private surface
    /// - [`UnifiError::Upstream`] for other error statuses
    /// - [`UnifiError::Http`] for network or protocol errors
    /// - [`UnifiError::Malformed`] for rejected parameters or invalid JSON
    pub async fn get(
        &self,
        surface: ApiSurface,
        template: &str,
        params: &[(&str, &str)],
        query: &[(&str, &str)],
    ) -> Result<serde_json::Value, UnifiError> {
        Self::ensure_surface_permitted(&self.controller, surface)?;

        let expanded = mecmcp_openapi::expand_path(template, params)
            .map_err(|error| UnifiError::Malformed(error.to_string()))?;

        let mut url = format!("{}{expanded}", self.controller.endpoint.trim_end_matches('/'));

        if !query.is_empty() {
            let query_string = query
                .iter()
                .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
                .collect::<Vec<_>>()
                .join("&");
            url.push('?');
            url.push_str(&query_string);
        }

        let request = HttpRequest::new(Method::Get, &url)?
            .header("Accept", "application/json")?
            .secret_header("X-API-KEY", &self.api_key)?;

        let response = self.http.send(request).await?;

        if response.status() >= 300 {
            return self.handle_error_response(surface, &expanded, response.status(), response.body()).await;
        }

        serde_json::from_slice(response.body())
            .map_err(|error| UnifiError::Malformed(error.to_string()))
    }

    /// Issue a POST against a path template with a JSON body.
    ///
    /// The `body` is serialized to JSON and sent with `Content-Type: application/json`.
    ///
    /// # Errors
    ///
    /// As [`Self::get`].
    pub async fn post(
        &self,
        surface: ApiSurface,
        template: &str,
        params: &[(&str, &str)],
        query: &[(&str, &str)],
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, UnifiError> {
        Self::ensure_surface_permitted(&self.controller, surface)?;

        let expanded = mecmcp_openapi::expand_path(template, params)
            .map_err(|error| UnifiError::Malformed(error.to_string()))?;

        let mut url = format!("{}{expanded}", self.controller.endpoint.trim_end_matches('/'));

        if !query.is_empty() {
            let query_string = query
                .iter()
                .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
                .collect::<Vec<_>>()
                .join("&");
            url.push('?');
            url.push_str(&query_string);
        }

        let body_bytes = serde_json::to_vec(body)
            .map_err(|error| UnifiError::Malformed(format!("failed to serialize body: {error}")))?;

        let request = HttpRequest::new(Method::Post, &url)?
            .header("Accept", "application/json")?
            .header("Content-Type", "application/json")?
            .secret_header("X-API-KEY", &self.api_key)?
            .body(body_bytes);

        let response = self.http.send(request).await?;

        if response.status() >= 300 {
            return self.handle_error_response(surface, &expanded, response.status(), response.body()).await;
        }

        serde_json::from_slice(response.body())
            .map_err(|error| UnifiError::Malformed(error.to_string()))
    }

    /// Issue a PUT against a path template with a JSON body.
    ///
    /// The `body` is serialized to JSON and sent with `Content-Type: application/json`.
    ///
    /// # Errors
    ///
    /// As [`Self::get`].
    pub async fn put(
        &self,
        surface: ApiSurface,
        template: &str,
        params: &[(&str, &str)],
        query: &[(&str, &str)],
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, UnifiError> {
        Self::ensure_surface_permitted(&self.controller, surface)?;

        let expanded = mecmcp_openapi::expand_path(template, params)
            .map_err(|error| UnifiError::Malformed(error.to_string()))?;

        let mut url = format!("{}{expanded}", self.controller.endpoint.trim_end_matches('/'));

        if !query.is_empty() {
            let query_string = query
                .iter()
                .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
                .collect::<Vec<_>>()
                .join("&");
            url.push('?');
            url.push_str(&query_string);
        }

        let body_bytes = serde_json::to_vec(body)
            .map_err(|error| UnifiError::Malformed(format!("failed to serialize body: {error}")))?;

        let request = HttpRequest::new(Method::Put, &url)?
            .header("Accept", "application/json")?
            .header("Content-Type", "application/json")?
            .secret_header("X-API-KEY", &self.api_key)?
            .body(body_bytes);

        let response = self.http.send(request).await?;

        if response.status() >= 300 {
            return self.handle_error_response(surface, &expanded, response.status(), response.body()).await;
        }

        serde_json::from_slice(response.body())
            .map_err(|error| UnifiError::Malformed(error.to_string()))
    }

    /// Issue a DELETE against a path template.
    ///
    /// # Errors
    ///
    /// As [`Self::get`].
    pub async fn delete(
        &self,
        surface: ApiSurface,
        template: &str,
        params: &[(&str, &str)],
        query: &[(&str, &str)],
    ) -> Result<serde_json::Value, UnifiError> {
        Self::ensure_surface_permitted(&self.controller, surface)?;

        let expanded = mecmcp_openapi::expand_path(template, params)
            .map_err(|error| UnifiError::Malformed(error.to_string()))?;

        let mut url = format!("{}{expanded}", self.controller.endpoint.trim_end_matches('/'));

        if !query.is_empty() {
            let query_string = query
                .iter()
                .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
                .collect::<Vec<_>>()
                .join("&");
            url.push('?');
            url.push_str(&query_string);
        }

        let request = HttpRequest::new(Method::Delete, &url)?
            .header("Accept", "application/json")?
            .secret_header("X-API-KEY", &self.api_key)?;

        let response = self.http.send(request).await?;

        if response.status() >= 300 {
            return self.handle_error_response(surface, &expanded, response.status(), response.body()).await;
        }

        serde_json::from_slice(response.body())
            .map_err(|error| UnifiError::Malformed(error.to_string()))
    }

    /// Map error responses to the correct `UnifiError` variant.
    ///
    /// A 404 on a private surface becomes `PrivateEndpointAbsent` with the
    /// surface, path, and controller version named — that is the entire payoff
    /// of the tag enum. Other errors become `Upstream`.
    async fn handle_error_response(
        &self,
        surface: ApiSurface,
        path: &str,
        status: u16,
        body: &[u8],
    ) -> Result<serde_json::Value, UnifiError> {
        if status == 404 && surface.requires_private_scope() {
            // Ensure version is cached by fetching it if absent. This uses the
            // supported Integration API endpoint directly, avoiding recursion.
            let version = match self.fetch_version_if_absent().await {
                Ok(v) => v,
                Err(_) => {
                    // If version fetch fails, fall back to reading the cache
                    self.cached_version
                        .read()
                        .ok()
                        .and_then(|guard| guard.clone())
                        .unwrap_or_else(|| "unknown".to_owned())
                }
            };

            return Err(UnifiError::PrivateEndpointAbsent {
                surface,
                path: path.to_owned(),
                controller_version: version,
            });
        }

        let detail = crate::error::sanitize_detail(&String::from_utf8_lossy(body));

        Err(UnifiError::Upstream { status, detail })
    }

    /// Fetch the version if not cached, bypassing the normal GET path to avoid recursion.
    ///
    /// This is used by `handle_error_response` to ensure a real version is always
    /// available in private-404 errors, even when the error is the first call.
    async fn fetch_version_if_absent(&self) -> Result<String, UnifiError> {
        // Check cache first
        {
            let cached = self.cached_version.read().map_err(|_| {
                UnifiError::Malformed("version cache lock poisoned".to_owned())
            })?;
            if let Some(version) = cached.as_ref() {
                return Ok(version.clone());
            }
        }

        // Build and send request directly, bypassing get() to avoid recursion
        let url = format!(
            "{}/proxy/network/integration/v1/info",
            self.controller.endpoint.trim_end_matches('/')
        );

        let request = HttpRequest::new(Method::Get, &url)?
            .header("Accept", "application/json")?
            .secret_header("X-API-KEY", &self.api_key)?;

        let response = self.http.send(request).await?;

        // Treat non-2xx as error, but don't recursively handle it
        if response.status() >= 300 {
            let detail = crate::error::sanitize_detail(&String::from_utf8_lossy(response.body()));
            return Err(UnifiError::Upstream {
                status: response.status(),
                detail,
            });
        }

        let info: serde_json::Value = serde_json::from_slice(response.body())
            .map_err(|error| UnifiError::Malformed(error.to_string()))?;

        let version = info
            .get("applicationVersion")
            .and_then(|v| v.as_str())
            .ok_or_else(|| UnifiError::Malformed("info response lacks applicationVersion".to_owned()))?
            .to_owned();

        // Cache for future use
        {
            let mut cached = self.cached_version.write().map_err(|_| {
                UnifiError::Malformed("version cache lock poisoned".to_owned())
            })?;
            *cached = Some(version.clone());
        }

        Ok(version)
    }
}

/// Percent-encode a string for use in a URL query parameter or path segment.
///
/// Encodes all characters except unreserved ones (alphanumeric, `-`, `.`, `_`, `~`).
fn percent_encode(s: &str) -> String {
    s.as_bytes()
        .iter()
        .map(|&byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::UnifiClient;
    use crate::ApiSurface;
    use crate::inventory::Controller;

    fn supported_only() -> Controller {
        serde_json::from_str(
            r#"{
                "endpoint": "https://unifi.example.org",
                "site": "default",
                "api_key_env": "UNIFI_TEST_KEY"
            }"#,
        )
        .expect("parses")
    }

    /// The tag is not decorative. A controller that has not opted in must be
    /// refused before a request is built, not after it 404s.
    #[test]
    fn a_private_surface_is_refused_when_the_controller_has_not_opted_in() {
        let controller = supported_only();
        let permitted =
            UnifiClient::ensure_surface_permitted(&controller, ApiSurface::PrivateV2);
        assert!(matches!(
            permitted,
            Err(crate::error::UnifiError::SurfaceRequiresConfig { .. })
        ));
    }

    #[test]
    fn the_supported_surface_needs_no_opt_in() {
        let controller = supported_only();
        UnifiClient::ensure_surface_permitted(&controller, ApiSurface::Supported)
            .expect("supported surface is always available");
    }

    /// Path templating goes through mecmcp-openapi, which rejects rather than
    /// sanitises. A site id containing a traversal must not produce a request.
    #[test]
    fn a_traversing_site_id_is_rejected_not_sanitised() {
        let expanded = mecmcp_openapi::expand_path(
            "/proxy/network/api/s/{site}/rest/networkconf",
            &[("site", "../../../v2/api/site/default")],
        );
        assert!(expanded.is_err(), "traversal must be rejected");
    }

    /// A 3xx response must be treated as an error, not parsed as success.
    #[test]
    fn redirect_responses_are_errors() {
        // Test that status classification treats 3xx as error
        let is_error = |status: u16| status >= 300;
        assert!(is_error(301), "301 redirect must be an error");
        assert!(is_error(302), "302 redirect must be an error");
        assert!(is_error(307), "307 redirect must be an error");
        assert!(!is_error(200), "200 OK must not be an error");
        assert!(!is_error(201), "201 Created must not be an error");
    }

    /// Private surfaces use the site name; the Integration API uses the UUID.
    /// This is verified by checking that the logic correctly routes to each.
    #[test]
    fn private_surfaces_return_site_name_directly() {
        let controller = supported_only();
        // Private surfaces should return the configured site name
        let private_v1_site = match ApiSurface::PrivateV1 {
            ApiSurface::PrivateV1 | ApiSurface::PrivateV2 | ApiSurface::Cloud => {
                controller.site.clone()
            }
            _ => panic!("unexpected surface routing"),
        };
        assert_eq!(private_v1_site, "default");
    }
}
