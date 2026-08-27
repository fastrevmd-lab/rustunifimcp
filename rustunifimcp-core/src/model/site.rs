//! UniFi site resource model.

use crate::error::UnifiError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A UniFi site.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Site {
    /// Site UUID.
    pub id: String,
    /// Internal reference (typically `"default"` for the default site).
    #[serde(rename = "internalReference")]
    pub internal_reference: String,
    /// Human-readable name.
    pub name: String,
}

/// Parses sites from the Integration API response.
pub fn parse_sites(val: &serde_json::Value) -> Result<Vec<Site>, UnifiError> {
    let data = super::unwrap_integration_data(val)?;
    data.iter()
        .map(|item| serde_json::from_value(item.clone()).map_err(|e| {
            UnifiError::Malformed(format!("site parse failed: {e}"))
        }))
        .collect()
}
