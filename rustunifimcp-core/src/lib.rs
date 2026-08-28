//! UniFi Network client, resource model, and MCP tool surface.
//!
//! This crate holds everything vendor-specific to UniFi. Authentication,
//! transport hardening, audit, policy, inventory, and change control come from
//! the [`mecmcp`](https://github.com/fastrevmd-lab/mecmcp) crate family and are
//! deliberately absent here.
//!
//! Implementation has not started; see `PLAN.md` at the workspace root for the
//! phase sequence and the `mecmcp` crates each phase is gated on.

pub mod changeset;
pub mod client;
pub mod error;
pub mod inventory;
pub mod model;
pub mod testing;
pub mod tools;
pub mod version;

/// The UniFi API surface an endpoint belongs to.
///
/// Every endpoint carries its surface so a deployment can decline the
/// undocumented ones. `PrivateV1` and `PrivateV2` require the
/// `unifi:private-api` scope; `Cloud` is opt-in and off by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApiSurface {
    /// `/proxy/network/integration/v1` — Ubiquiti's supported Integration API.
    Supported,
    /// `/proxy/network/api/s/<site>` — the legacy private controller API.
    PrivateV1,
    /// `/proxy/network/v2/api/site/<site>` — the private v2 controller API.
    PrivateV2,
    /// Ubiquiti's cloud Site Manager API.
    Cloud,
}

impl ApiSurface {
    /// Whether reaching this surface requires the `unifi:private-api` scope.
    #[must_use]
    pub const fn requires_private_scope(self) -> bool {
        matches!(self, Self::PrivateV1 | Self::PrivateV2)
    }
}

#[cfg(test)]
mod tests {
    use super::ApiSurface;

    #[test]
    fn only_private_surfaces_are_scope_gated() {
        assert!(!ApiSurface::Supported.requires_private_scope());
        assert!(ApiSurface::PrivateV1.requires_private_scope());
        assert!(ApiSurface::PrivateV2.requires_private_scope());
        assert!(!ApiSurface::Cloud.requires_private_scope());
    }
}
