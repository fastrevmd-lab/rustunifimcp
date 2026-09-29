//! Per-token site write authority.
//!
//! UniFi Network is multi-site: one controller manages many sites, and the
//! operational write tools (`unifi_device_action`, `unifi_client_action`,
//! `unifi_backup_action`) already accept a
//! caller-supplied `site`, defaulting to the controller's configured site
//! when omitted. Before this grant existed there was no way to restrict a
//! token to a subset of a multi-site deployment's sites: any token holding
//! write-tool scope for a controller could write to any site on it.
//!
//! A token with no grant (`grant: None`) is unrestricted by site. That is
//! this crate's pre-MEC-508 behavior, and it is what every token minted
//! before this change carries, so existing tokens keep working unchanged. A
//! token that carries a [`UnifiGrant`] is restricted to exactly the sites
//! named in it.

use mecmcp_auth::{Grant, GrantError, ScopeSet};
use serde::{Deserialize, Serialize};

/// Per-token site write authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnifiGrant {
    /// Sites this token may write to. [`ScopeSet::Wildcard`] permits every
    /// site; an allowlist permits only the named sites.
    pub sites: ScopeSet,
}

impl Grant for UnifiGrant {
    type Action = ();

    fn allows_action(&self, (): Self::Action) -> bool {
        // UniFi's grant distinguishes subjects (sites) only; it has no
        // vendor action taxonomy the way Mist's catalog does, so every
        // grant permits its one action.
        true
    }

    fn allows_subject(&self, subject: &str) -> bool {
        self.sites.allows(subject)
    }

    fn validate(&self) -> Result<(), GrantError> {
        self.sites
            .validate("sites")
            .map_err(|error| GrantError::Invalid(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_allows_any_site() {
        let grant = UnifiGrant {
            sites: ScopeSet::Wildcard,
        };
        assert!(grant.allows_subject("site-a"));
        assert!(grant.allows_subject("site-b"));
    }

    #[test]
    fn allowlist_allows_only_named_sites() {
        let grant = UnifiGrant {
            sites: ScopeSet::Allowlist(vec!["site-a".to_owned()]),
        };
        assert!(grant.allows_subject("site-a"));
        assert!(!grant.allows_subject("site-b"));
    }

    #[test]
    fn allowlist_permits_each_of_its_multiple_sites() {
        let grant = UnifiGrant {
            sites: ScopeSet::Allowlist(vec!["site-a".to_owned(), "site-b".to_owned()]),
        };
        assert!(grant.allows_subject("site-a"));
        assert!(grant.allows_subject("site-b"));
        assert!(!grant.allows_subject("site-c"));
    }

    #[test]
    fn validate_rejects_a_malformed_scope() {
        let grant = UnifiGrant {
            sites: ScopeSet::Allowlist(vec!["dup".to_owned(), "dup".to_owned()]),
        };
        assert!(grant.validate().is_err());
    }

    #[test]
    fn validate_accepts_wildcard() {
        let grant = UnifiGrant {
            sites: ScopeSet::Wildcard,
        };
        assert!(grant.validate().is_ok());
    }
}
