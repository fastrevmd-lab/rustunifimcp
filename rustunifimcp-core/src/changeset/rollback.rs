//! Best-effort rollback to pre-image state.
//!
//! UniFi has no checkpoint to roll back to, so rollback replays the pre-image
//! as a sequence of REST calls. The rollback itself can fail partway through.

use super::apply::ControllerOps;
use super::preimage::{Preimage, StagedMutation};

/// Attempt to roll back to the pre-image state.
///
/// # Errors
///
/// Returns a Vec of failure descriptions if any rollback operations fail.
/// An empty Vec indicates success; a non-empty Vec indicates partial rollback.
pub async fn rollback_to_preimage<C>(
    controller: &C,
    _preimage: &Preimage,
    succeeded: &[StagedMutation],
) -> Result<(), Vec<String>>
where
    C: ControllerOps,
{
    let mut failures = Vec::new();

    // Roll back in reverse order
    for (index, mutation) in succeeded.iter().enumerate() {
        if let Err(e) = controller.rollback_mutation(index, mutation).await {
            failures.push(format!(
                "rollback failed for {}: {}",
                mutation.preview(),
                e
            ));
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}
