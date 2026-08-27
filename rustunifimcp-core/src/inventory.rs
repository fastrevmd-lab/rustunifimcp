//! Multi-controller inventory.
//!
//! `controllers.json` is read through `mecmcp-inventory`'s hardened loader,
//! which requires mode 0600, a regular file, and ownership by the service user.
//!
//! The UniFi API key never appears in this file. Each controller names an
//! environment variable or a separate 0600 file, loaded through `mecmcp-secret`
//! into an `OutboundSecret` that zeroizes on drop and implements neither
//! `Debug` nor `Serialize`. `deny_unknown_fields` makes an inline key a parse
//! error rather than an ignored field.

use crate::error::UnifiError;
use mecmcp_inventory::{FileInventory, Inventory, InventoryError};
use mecmcp_secret::{OutboundSecret, SecretLimits, load_from_env, load_from_file};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// One UniFi Network controller.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Controller {
    /// Base URL including scheme, e.g. `https://unifi.example.org`.
    pub endpoint: String,
    /// Default site identifier, e.g. `default`.
    pub site: String,
    /// Environment variable holding the UniFi API key.
    #[serde(default)]
    pub api_key_env: Option<String>,
    /// File holding the UniFi API key. Mutually exclusive with the env form.
    #[serde(default)]
    pub api_key_file: Option<PathBuf>,
    /// PEM trust anchor, for a controller behind a private CA.
    ///
    /// `mecmcp-http` offers no insecure-skip-verify at any layer, so this is
    /// the only way to reach such a controller.
    #[serde(default)]
    pub ca_pem_path: Option<PathBuf>,
    /// Whether the undocumented `/api/s/` and `/v2/api/` surfaces may be used.
    ///
    /// Off by default, so a supported-only deployment is the default posture
    /// and a controller upgrade cannot silently break an undocumented route
    /// nobody opted into.
    #[serde(default)]
    pub allow_private_api: bool,
    /// Whether the Ubiquiti cloud Site Manager surface may be used.
    ///
    /// Off by default and unimplemented in v1.
    #[serde(default)]
    pub allow_cloud: bool,
}

impl Controller {
    /// Check the invariants `serde` cannot express.
    ///
    /// # Errors
    ///
    /// Returns [`UnifiError::Malformed`] if the endpoint is not `https://`, or
    /// if the controller names both credential sources or neither.
    pub fn validate(&self) -> Result<(), UnifiError> {
        if !self.endpoint.starts_with("https://") {
            return Err(UnifiError::Malformed(format!(
                "controller endpoint must be https://, got {}",
                self.endpoint
            )));
        }
        match (&self.api_key_env, &self.api_key_file) {
            (Some(_), Some(_)) => Err(UnifiError::Malformed(
                "controller names both api_key_env and api_key_file; name exactly one"
                    .to_owned(),
            )),
            (None, None) => Err(UnifiError::Malformed(
                "controller names neither api_key_env nor api_key_file".to_owned(),
            )),
            _ => Ok(()),
        }
    }

    /// Load the API key through `mecmcp-secret`'s hardened loader.
    ///
    /// # Errors
    ///
    /// Returns [`UnifiError::Secret`] if the file is a symlink, is group- or
    /// world-accessible, is oversized, or is absent.
    pub fn load_api_key(&self) -> Result<OutboundSecret, UnifiError> {
        self.validate()?;
        let limits = SecretLimits::default();
        if let Some(var) = &self.api_key_env {
            return Ok(load_from_env(var, limits)?);
        }
        let path = self
            .api_key_file
            .as_ref()
            .ok_or_else(|| UnifiError::Malformed("no api key source".to_owned()))?;
        Ok(load_from_file(path, limits)?)
    }
}

/// The loaded controller inventory, hot-reloadable on SIGHUP.
pub struct ControllerRegistry {
    inner: FileInventory<Controller, ()>,
}

impl ControllerRegistry {
    /// Load `controllers.json` through the hardened loader.
    ///
    /// # Errors
    /// Returns [`InventoryError`] when the file is missing, wrongly permissioned,
    /// not a regular file, or structurally invalid.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, InventoryError> {
        Ok(Self {
            inner: FileInventory::load(path)?,
        })
    }

    /// Re-read the file in place, returning the number of controllers loaded.
    ///
    /// # Errors
    /// Returns [`InventoryError`] on any load failure. The previous contents
    /// remain in effect when a reload fails.
    pub fn reload(&self) -> Result<usize, InventoryError> {
        self.inner.reload()
    }

    /// All controller names, in stable order.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.inner.names()
    }

    /// Resolve one controller by exact name.
    ///
    /// # Errors
    /// Returns [`UnifiError::Malformed`] when the name is absent.
    pub fn get(&self, name: &str) -> Result<Controller, UnifiError> {
        self.inner
            .get_device(name)
            .map_err(|_| UnifiError::Malformed(format!("unknown controller: {name}")))
    }
}

#[cfg(test)]
mod tests {
    use super::Controller;

    /// The API key must never be storable in the inventory file. `serde`'s
    /// deny_unknown_fields is what enforces it, so a key-bearing document has
    /// to be a hard parse error rather than a silently ignored field.
    #[test]
    fn an_inline_api_key_is_rejected_at_parse_time() {
        let raw = r#"{
            "endpoint": "https://unifi.example.org",
            "site": "default",
            "api_key": "secret-value-that-must-not-parse"
        }"#;
        let parsed: Result<Controller, _> = serde_json::from_str(raw);
        assert!(parsed.is_err(), "an inline api_key must not deserialize");
    }

    /// Naming both sources is ambiguous, and ambiguity about which credential
    /// was used is not something to resolve by precedence.
    #[test]
    fn naming_both_key_sources_is_an_error() {
        let raw = r#"{
            "endpoint": "https://unifi.example.org",
            "site": "default",
            "api_key_env": "UNIFI_API_KEY",
            "api_key_file": "/etc/unifimcp/api.key"
        }"#;
        let controller: Controller = serde_json::from_str(raw).expect("parses");
        assert!(controller.validate().is_err());
    }

    /// Naming neither leaves nothing to authenticate with.
    #[test]
    fn naming_no_key_source_is_an_error() {
        let raw = r#"{
            "endpoint": "https://unifi.example.org",
            "site": "default"
        }"#;
        let controller: Controller = serde_json::from_str(raw).expect("parses");
        assert!(controller.validate().is_err());
    }

    /// mecmcp-http rejects non-https at request construction, but failing here
    /// names the config file rather than the twentieth request.
    #[test]
    fn a_plaintext_endpoint_is_rejected_by_validate() {
        let raw = r#"{
            "endpoint": "http://unifi.example.org",
            "site": "default",
            "api_key_env": "UNIFI_API_KEY"
        }"#;
        let controller: Controller = serde_json::from_str(raw).expect("parses");
        assert!(controller.validate().is_err());
    }

    /// Private and cloud surfaces are off unless a controller opts in.
    #[test]
    fn private_and_cloud_surfaces_default_off() {
        let raw = r#"{
            "endpoint": "https://unifi.example.org",
            "site": "default",
            "api_key_env": "UNIFI_API_KEY"
        }"#;
        let controller: Controller = serde_json::from_str(raw).expect("parses");
        assert!(!controller.allow_private_api);
        assert!(!controller.allow_cloud);
    }
}
