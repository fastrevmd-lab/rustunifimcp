//! Pre-image capture and staged mutations.
//!
//! UniFi has no candidate configuration, so change sets must snapshot the
//! current state before apply. The pre-image is the only thing standing between
//! a partial apply and an unrecoverable one.

use crate::error::UnifiError;
use serde_json::Value;

/// A snapshot of controller state before staging mutations.
///
/// Captures the current state of all resources a change set will touch, so
/// apply can be refused if the controller drifted since staging.
#[derive(Debug, Clone)]
pub struct Preimage {
    resources: Value,
}

impl Preimage {
    /// Construct a pre-image from a recorded fixture for testing.
    #[must_use]
    pub fn from_fixture(fixture: &Value) -> Self {
        Self {
            resources: fixture.clone(),
        }
    }

    /// Capture a pre-image from a live controller.
    ///
    /// # Errors
    ///
    /// Returns an error if any resource fetch fails.
    pub async fn capture_preimage(
        _client: &crate::client::UnifiClient,
        _mutations: &[StagedMutation],
    ) -> Result<Self, UnifiError> {
        // Implementation deferred — Task 27 wires this to the real client
        unimplemented!("capture_preimage requires real client integration")
    }

    /// Check if this pre-image covers a given mutation.
    #[must_use]
    pub fn covers(&self, mutation: &StagedMutation) -> bool {
        match mutation {
            StagedMutation::Update { kind: _, id, .. } => {
                // Check if we have this resource type and ID in the pre-image
                if let Some(data) = self.resources.get("data").and_then(|d| d.as_array()) {
                    data.iter().any(|item| {
                        item.get("_id")
                            .and_then(|v| v.as_str())
                            .is_some_and(|item_id| item_id == id)
                    })
                } else {
                    false
                }
            }
            StagedMutation::Create { .. } => true, // Creates don't need pre-image coverage
            StagedMutation::Delete { .. } => true, // Deletes are checked at validate time
        }
    }

    /// Get the pre-image entry for a resource by ID.
    ///
    /// Returns `None` if the resource does not exist in the pre-image (which is
    /// expected for creates, and an error for updates/deletes).
    #[must_use]
    pub fn get_resource(&self, id: &str) -> Option<Value> {
        if let Some(data) = self.resources.get("data").and_then(|d| d.as_array()) {
            data.iter()
                .find(|item| {
                    item.get("_id")
                        .and_then(|v| v.as_str())
                        .is_some_and(|item_id| item_id == id)
                })
                .cloned()
        } else {
            None
        }
    }

}

/// A planned mutation against live configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StagedMutation {
    /// Create a new resource.
    Create {
        /// The resource kind being created.
        kind: String,
        /// The resource body.
        body: Value,
    },
    /// Update an existing resource.
    Update {
        /// The resource kind being updated.
        kind: String,
        /// The resource ID.
        id: String,
        /// The new resource body.
        body: Value,
    },
    /// Delete a resource.
    Delete {
        /// The resource kind being deleted.
        kind: String,
        /// The resource ID.
        id: String,
    },
}

impl StagedMutation {
    /// Stage a resource creation.
    #[must_use]
    pub fn create(kind: impl Into<String>, body: Value) -> Self {
        Self::Create {
            kind: kind.into(),
            body,
        }
    }

    /// Stage a resource update.
    #[must_use]
    pub fn update(kind: impl Into<String>, id: impl Into<String>, body: Value) -> Self {
        Self::Update {
            kind: kind.into(),
            id: id.into(),
            body,
        }
    }

    /// Stage a resource deletion.
    #[must_use]
    pub fn delete(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self::Delete {
            kind: kind.into(),
            id: id.into(),
        }
    }

    /// Preview this mutation as a human-readable string.
    #[must_use]
    pub fn preview(&self) -> String {
        match self {
            Self::Create { kind, .. } => format!("create {kind}"),
            Self::Update { kind, id, .. } => format!("update {kind} {id}"),
            Self::Delete { kind, id } => format!("delete {kind} {id}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::testing::{fixture, DEFAULT_FIXTURE_VERSION};

    /// The pre-image is the only thing standing between a partial apply and an
    /// unrecoverable one. If a staged mutation touches a resource the pre-image
    /// does not cover, the change set must be refused before apply.
    #[test]
    fn a_mutation_outside_the_preimage_is_refused() {
        let preimage = super::Preimage::from_fixture(&fixture(
            DEFAULT_FIXTURE_VERSION,
            "networkconf",
        ));
        let staged = super::StagedMutation::update(
            "firewall_policy",
            "abc123",
            serde_json::json!({}),
        );
        assert!(
            super::super::validate::validate_locally(&preimage, &[staged]).is_err(),
            "a mutation with no pre-image coverage must not reach apply"
        );
    }
}
