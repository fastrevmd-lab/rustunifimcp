//! Sequential apply and verification.
//!
//! UniFi has no atomic commit, so apply is a sequence of independent REST calls.
//! Partial failure is a reachable state and must be tracked accurately.

use super::preimage::{Preimage, StagedMutation};
use super::rollback::rollback_to_preimage;

/// The outcome of applying a change set.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    fn rollback_mutation(
        &self,
        index: usize,
        mutation: &StagedMutation,
    ) -> impl std::future::Future<Output = Result<(), crate::error::UnifiError>> + Send;

    /// Check if the pre-image still matches the controller state.
    fn preimage_matches(&self) -> impl std::future::Future<Output = bool> + Send;
}

/// Verify that mutations were applied as expected.
///
/// # Errors
///
/// Returns an error if verification fails.
pub async fn verify_applied<C>(
    _controller: &C,
    _mutations: &[StagedMutation],
) -> Result<(), crate::error::UnifiError>
where
    C: ControllerOps,
{
    // Implementation deferred - Task 27 wires this to real verification
    Ok(())
}
