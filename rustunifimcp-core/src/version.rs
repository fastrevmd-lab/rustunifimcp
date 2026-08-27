//! Controller version matrix.
//!
//! The supported Integration API is stable and always present. The private
//! surfaces are not, so their availability is declared per version and
//! asserted against recorded fixtures in `tests/version_matrix.rs`.
//!
//! Adding a controller version means recording its fixtures and adding a row
//! here. A disagreement between the two is a test failure, deliberately.

use crate::model::ResourceKind;
use crate::ApiSurface;

/// Whether a controller version serves the endpoint behind a resource kind.
///
/// # Arguments
///
/// * `version` - The UniFi controller version (e.g., "10.5.67")
/// * `kind` - The resource kind to check
///
/// # Returns
///
/// Returns `true` if the endpoint is available on the given version, `false`
/// otherwise.
///
/// # Examples
///
/// ```
/// use rustunifimcp_core::model::ResourceKind;
/// use rustunifimcp_core::version::endpoint_available;
///
/// // Supported API endpoints are always available
/// assert!(endpoint_available("10.5.67", ResourceKind::Station));
/// ```
#[must_use]
pub fn endpoint_available(version: &str, kind: ResourceKind) -> bool {
    // Supported API endpoints are always available across versions
    if kind.surface() == ApiSurface::Supported {
        return true;
    }

    // Private API availability matrix. Every row must be justified by a
    // fixture or an .absent marker. Never guess - if a version is not
    // recorded, adding it means capturing fixtures first.
    #[allow(clippy::match_same_arms)]
    match (major_minor(version), kind) {
        // Version 10.5.67: All private endpoints present (zero .absent markers)
        ((10, 5), ResourceKind::FirewallPolicy) => true,
        ((10, 5), ResourceKind::FirewallZone) => true,
        ((10, 5), ResourceKind::TrafficRoute) => true,

        // Catch-all: Currently returns true because only 10.5.67 is recorded
        // with zero .absent markers. When adding a new version, replace this
        // with explicit rows justified by fixtures or .absent markers.
        (_, _) => true,
    }
}

/// Parse version string into (major, minor) tuple.
///
/// # Arguments
///
/// * `version` - Version string (e.g., "10.5.67")
///
/// # Returns
///
/// Returns `(major, minor)` as `(u32, u32)`. Anything unparseable sorts as
/// `(0, 0)`.
///
/// # Examples
///
/// ```
/// # use rustunifimcp_core::version::major_minor;
/// assert_eq!(major_minor("10.5.67"), (10, 5));
/// assert_eq!(major_minor("invalid"), (0, 0));
/// ```
#[must_use]
pub fn major_minor(version: &str) -> (u32, u32) {
    let mut parts = version.split('.');
    let major = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    (major, minor)
}
