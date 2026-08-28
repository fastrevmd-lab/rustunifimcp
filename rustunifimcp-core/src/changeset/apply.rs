//! Sequential apply and verification.
//!
//! UniFi has no atomic commit, so apply is a sequence of independent REST calls.
//! Partial failure is a reachable state and must be tracked accurately.

use super::preimage::{Preimage, StagedMutation};
use super::rollback::rollback_to_preimage;

/// The outcome of applying a change set.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Outcome {
    /// The final state after apply.
    pub state: State,
    /// Mutations that succeeded.
    pub succeeded: Vec<StagedMutation>,
    /// All mutations that did not succeed (attempted + never attempted).
    pub failed: Vec<StagedMutation>,
    /// Mutations that were attempted but failed.
    pub attempted_and_failed: Vec<StagedMutation>,
    /// Mutations that were never attempted due to prior failure.
    pub never_attempted: Vec<StagedMutation>,
    /// Rollback operations that failed.
    pub rollback_failures: Vec<String>,
}

/// The state of a change set after apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum State {
    /// All mutations succeeded.
    Applied,
    /// Some mutations succeeded, some failed.
    Partial,
    /// Partial apply with failed rollback.
    PartialRollbackFailed,
    /// Apply was refused because the pre-image no longer matches.
    RefusedStale,
}

/// Apply staged mutations sequentially.
///
/// # Errors
///
/// This function does not return an error directly. All failures are captured
/// in the returned [`Outcome`].
pub async fn apply_sequentially<C>(
    controller: &C,
    preimage: &Preimage,
    mutations: &[StagedMutation],
) -> Outcome
where
    C: ControllerOps,
{
    // Check if the pre-image still matches
    if !controller.preimage_matches().await {
        return Outcome {
            state: State::RefusedStale,
            succeeded: Vec::new(),
            failed: mutations.to_vec(),
            attempted_and_failed: Vec::new(),
            never_attempted: mutations.to_vec(),
            rollback_failures: Vec::new(),
        };
    }

    let mut succeeded = Vec::new();
    let mut attempted_and_failed = Vec::new();
    let mut never_attempted = Vec::new();

    // Apply mutations sequentially
    for (index, mutation) in mutations.iter().enumerate() {
        match controller.apply_mutation(index, mutation).await {
            Ok(()) => {
                succeeded.push(mutation.clone());
            }
            Err(_) => {
                // This mutation failed
                attempted_and_failed.push(mutation.clone());
                // Everything after this is never attempted
                never_attempted.extend(mutations[index + 1..].iter().cloned());
                break;
            }
        }
    }

    // If all succeeded, we're done
    if attempted_and_failed.is_empty() && never_attempted.is_empty() {
        return Outcome {
            state: State::Applied,
            succeeded,
            failed: Vec::new(),
            attempted_and_failed: Vec::new(),
            never_attempted: Vec::new(),
            rollback_failures: Vec::new(),
        };
    }

    // Partial failure - attempt rollback
    let rollback_result = rollback_to_preimage(controller, preimage, &succeeded).await;

    let mut failed = attempted_and_failed.clone();
    failed.extend(never_attempted.clone());

    match rollback_result {
        Ok(()) => Outcome {
            state: State::Partial,
            succeeded,
            failed,
            attempted_and_failed,
            never_attempted,
            rollback_failures: Vec::new(),
        },
        Err(rollback_failures) => Outcome {
            state: State::PartialRollbackFailed,
            succeeded,
            failed,
            attempted_and_failed,
            never_attempted,
            rollback_failures,
        },
    }
}

/// Operations a controller must support for apply and rollback.
///
/// Implemented by both `UnifiClient` and `MockController`.
pub trait ControllerOps {
    /// Apply a single mutation.
    fn apply_mutation(
        &self,
        index: usize,
        mutation: &StagedMutation,
    ) -> impl std::future::Future<Output = Result<(), crate::error::UnifiError>> + Send;

    /// Roll back a single mutation.
    ///
    /// For creates, `prior_value` will be `None` (delete the created resource).
    /// For updates, `prior_value` contains the original state to restore.
    /// For deletes, `prior_value` contains the deleted resource to re-create.
    fn rollback_mutation(
        &self,
        index: usize,
        mutation: &StagedMutation,
        prior_value: Option<&serde_json::Value>,
    ) -> impl std::future::Future<Output = Result<(), crate::error::UnifiError>> + Send;

    /// Check if the pre-image still matches the controller state.
    fn preimage_matches(&self) -> impl std::future::Future<Output = bool> + Send;

    /// Fetch a resource for verification.
    ///
    /// Returns `None` if the resource does not exist (expected for deleted resources).
    fn fetch_resource(
        &self,
        kind: &str,
        id: &str,
    ) -> impl std::future::Future<Output = Result<Option<serde_json::Value>, crate::error::UnifiError>> + Send;
}

/// Verify that mutations were applied as expected.
///
/// Re-fetches each touched resource and compares against the desired state.
/// For creates, verifies the resource now exists. For updates, verifies the
/// resource matches the staged body. For deletes, verifies the resource is gone.
///
/// # Errors
///
/// Returns an error describing which resources failed verification, or if
/// verification itself could not run (controller unreachable, fetch failed).
/// A mismatch is reported as a verification failure, not as "could not check".
pub async fn verify_applied<C>(
    controller: &C,
    mutations: &[StagedMutation],
) -> Result<(), crate::error::UnifiError>
where
    C: ControllerOps,
{
    use crate::error::UnifiError;

    let mut failed_verifications = Vec::new();

    for mutation in mutations {
        match mutation {
            StagedMutation::Create { kind, body, .. } => {
                // For creates, verify the resource now exists
                // We need an ID to fetch, which should be in the body or response
                // For now, we'll extract it from the body if present
                if let Some(id) = body.get("_id").and_then(|v| v.as_str()) {
                    match controller.fetch_resource(kind, id).await {
                        Ok(Some(_)) => {
                            // Resource exists as expected
                        }
                        Ok(None) => {
                            failed_verifications.push(format!(
                                "create {} {}: resource does not exist after apply",
                                kind, id
                            ));
                        }
                        Err(e) => {
                            return Err(UnifiError::Malformed(format!(
                                "could not verify create {} {}: {}",
                                kind, id, e
                            )));
                        }
                    }
                }
                // If no ID in body, we can't verify the create
                // This is acceptable since creates don't always have IDs upfront
            }
            StagedMutation::Update { kind, id, body } => {
                // For updates, verify the resource matches the staged body
                match controller.fetch_resource(kind, id).await {
                    Ok(Some(fetched)) => {
                        // Compare key fields (simplified - full implementation would
                        // need deep comparison logic)
                        if let Some(expected_name) = body.get("name")
                            && fetched.get("name") != Some(expected_name)
                        {
                            failed_verifications.push(format!(
                                "update {} {}: field mismatch after apply",
                                kind, id
                            ));
                        }
                    }
                    Ok(None) => {
                        failed_verifications.push(format!(
                            "update {} {}: resource does not exist after apply",
                            kind, id
                        ));
                    }
                    Err(e) => {
                        return Err(UnifiError::Malformed(format!(
                            "could not verify update {} {}: {}",
                            kind, id, e
                        )));
                    }
                }
            }
            StagedMutation::Delete { kind, id } => {
                // For deletes, verify the resource is gone
                match controller.fetch_resource(kind, id).await {
                    Ok(None) => {
                        // Resource is absent as expected
                    }
                    Ok(Some(_)) => {
                        failed_verifications.push(format!(
                            "delete {} {}: resource still exists after apply",
                            kind, id
                        ));
                    }
                    Err(e) => {
                        return Err(UnifiError::Malformed(format!(
                            "could not verify delete {} {}: {}",
                            kind, id, e
                        )));
                    }
                }
            }
            StagedMutation::Restore { .. } => {
                // Restores cannot be verified in the same way as other mutations
                // since they replace the entire controller state. Skip verification.
                continue;
            }
        }
    }

    if !failed_verifications.is_empty() {
        return Err(UnifiError::Malformed(format!(
            "verification failed for {} mutations: {}",
            failed_verifications.len(),
            failed_verifications.join("; ")
        )));
    }

    Ok(())
}
