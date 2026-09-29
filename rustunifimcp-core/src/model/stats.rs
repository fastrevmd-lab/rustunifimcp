//! UniFi statistics resource models.

use crate::error::UnifiError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Device statistics.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct DeviceStats {
    /// Device MAC address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// Device name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Station (client) statistics.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct StationStats {
    /// Client MAC address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// Hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

/// A controller event log entry.
///
/// The controller's own field name for the event-type discriminator is
/// `key` (e.g. `"EVT_WU_Connected"`), which collides with an exact-match
/// entry in the shared crate's denylist (`mecmcp_redact::denylist`) meant to
/// catch WireGuard/API keys named plainly elsewhere. Routing this shape
/// through that denylist-and-shape scan -- as `Site` and `Flow` stats do --
/// would silently redact the one field that says what kind of event this is,
/// on every event. Parsing it into a typed field named `event_type` instead
/// sidesteps the collision: the value is real and non-secret, only the
/// upstream field *name* collided.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Event {
    /// Event ID.
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Event type (the controller's `key` field, e.g. `"EVT_WU_Connected"`).
    ///
    /// Deserializes from the controller's `key`, but serializes back out as
    /// `event_type` -- the projected output must not carry a field literally
    /// named `key`, or the shared crate's denylist-and-shape scan (still run
    /// as defence in depth on `msg`; see
    /// `tools::read::project_stats`'s `StatsSubject::Event` arm, which calls
    /// `redact::redact_in_place` after this type's own projection) would
    /// redact its value on the way out.
    #[serde(rename(serialize = "event_type", deserialize = "key"))]
    pub event_type: String,
    /// Subsystem the event belongs to (e.g., `"wlan"`, `"lan"`, `"wan"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subsystem: Option<String>,
    /// Unix epoch milliseconds the event occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<i64>,
    /// Human-readable event description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msg: Option<String>,
}

/// Parses controller event log entries from the Private v1 API response.
pub fn parse_events(val: &serde_json::Value) -> Result<Vec<Event>, UnifiError> {
    let data = super::unwrap_enveloped_data(val)?;
    data.iter()
        .map(|item| {
            serde_json::from_value(item.clone())
                .map_err(|e| UnifiError::Malformed(format!("event parse failed: {e}")))
        })
        .collect()
}

/// Parses device statistics from the Private v1 API response.
pub fn parse_device_stats(val: &serde_json::Value) -> Result<Vec<DeviceStats>, UnifiError> {
    let data = super::unwrap_enveloped_data(val)?;
    data.iter()
        .map(|item| {
            serde_json::from_value(item.clone())
                .map_err(|e| UnifiError::Malformed(format!("device stats parse failed: {e}")))
        })
        .collect()
}

/// Parses station statistics from the Private v1 API response.
pub fn parse_station_stats(val: &serde_json::Value) -> Result<Vec<StationStats>, UnifiError> {
    let data = super::unwrap_enveloped_data(val)?;
    data.iter()
        .map(|item| {
            serde_json::from_value(item.clone())
                .map_err(|e| UnifiError::Malformed(format!("station stats parse failed: {e}")))
        })
        .collect()
}
