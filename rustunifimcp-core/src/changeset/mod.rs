//! UniFi Network transaction implementation.
//!
//! UniFi has no candidate configuration, no dry-run validation, and no checkpoint
//! to roll back to. Every write is an immediate, independent REST call against
//! live configuration. The [`UnifiTransaction`] type declares this plainly via
//! [`Atomicity`], so shared code that renders approval prompts can say so rather
//! than offering commit-confirmed semantics the vendor cannot deliver.

pub mod apply;
pub mod diff;
pub mod preimage;
pub mod rollback;
pub mod validate;

pub use apply::{apply_sequentially, verify_applied, ControllerOps, Outcome, State};
pub use diff::{diff_against_preimage, Change, Diff};
pub use preimage::{Preimage, StagedMutation};
pub use rollback::rollback_to_preimage;
pub use validate::{check_references, validate_locally};

// Atomicity type is not yet in mecmcp-changeset v0.20.0.
// Tracked: https://github.com/fastrevmd-lab/mecmcp/issues/335
/// What a vendor's transaction implementation can actually guarantee.
///
/// Junos and PAN-OS answer `true` to all three. UniFi answers `false` to all
/// three, and shared code that renders approval prompts can then say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Atomicity {
    /// All staged mutations land, or none do.
    pub atomic_apply: bool,
    /// The device can validate the change before it is applied.
    pub dry_run_validation: bool,
    /// A failed apply can be reverted to the pre-change state reliably.
    pub guaranteed_rollback: bool,
}

/// UniFi Network transaction.
///
/// Implements the vendor-agnostic [`mecmcp_changeset::DeviceTransaction`] trait
/// over UniFi's immediate-write REST API. Because UniFi has no candidate
/// configuration, this is a best-effort approximation: staging snapshots the
/// current state as a pre-image; applying is a sequence of independent REST
/// calls; rollback replays the pre-image and can itself fail.
pub struct UnifiTransaction;

impl UnifiTransaction {
    /// What UniFi can guarantee about applying a change set.
    ///
    /// None of the three. This method exists so a future refactor cannot quietly
    /// make the server claim otherwise.
    #[must_use]
    pub const fn atomicity() -> Atomicity {
        Atomicity {
            atomic_apply: false,
            dry_run_validation: false,
            guaranteed_rollback: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::UnifiTransaction;

    /// UniFi promises none of the three. This test exists so that a future
    /// refactor cannot quietly make the server claim otherwise.
    #[test]
    fn unifi_declares_no_atomicity_guarantees() {
        let atomicity = UnifiTransaction::atomicity();
        assert!(!atomicity.atomic_apply);
        assert!(!atomicity.dry_run_validation);
        assert!(!atomicity.guaranteed_rollback);
    }

    /// The design forbids the word outright, because an operator approving a
    /// UniFi change set is not getting commit-confirmed semantics and the model
    /// relaying the request must be able to say so.
    #[test]
    fn no_change_set_tool_description_claims_atomicity() {
        for (name, description) in crate::tools::changeset::DESCRIPTIONS {
            let lowered = description.to_lowercase();
            assert!(
                !lowered.contains("atomic"),
                "{name} description contains 'atomic': {description}"
            );
            assert!(
                !lowered.contains("all-or-nothing"),
                "{name} description implies atomicity: {description}"
            );
        }
    }

    /// And the descriptions must say the true thing, not merely avoid the
    /// false one.
    #[test]
    fn the_apply_description_states_that_partial_failure_is_reachable() {
        let apply = crate::tools::changeset::DESCRIPTIONS
            .iter()
            .find(|(name, _)| *name == "unifi_apply_change_set")
            .expect("apply is registered");
        let lowered = apply.1.to_lowercase();
        assert!(
            lowered.contains("partial"),
            "apply must state that partial failure is a reachable outcome: {}",
            apply.1
        );
    }
}
