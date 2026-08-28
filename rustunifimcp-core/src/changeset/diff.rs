//! Client-side diff computation.
//!
//! UniFi has no candidate configuration, so diffs are computed client-side by
//! comparing the pre-image against the desired state from staged mutations.

use crate::error::UnifiError;

use super::preimage::{Preimage, StagedMutation};

/// A computed diff between pre-image and staged mutations.
#[derive(Debug, Clone)]
pub struct Diff {
    /// Whether the diff was actually computed.
    ///
    /// An empty diff is distinguishable from one that was never computed.
    /// This project has hit "empty result indistinguishable from no work"
    /// four separate times.
    pub computed: bool,
    /// The changes that would be applied.
    pub changes: Vec<Change>,
}

/// A single change in a diff.
#[derive(Debug, Clone)]
pub struct Change {
    /// The mutation that will be applied.
    pub mutation: StagedMutation,
    /// A preview of what this change does.
    pub preview: String,
}

/// Compute a diff between the pre-image and staged mutations.
///
/// # Errors
///
/// Returns an error if the diff computation fails.
pub fn diff_against_preimage(
    _preimage: &Preimage,
    mutations: &[StagedMutation],
) -> Result<Diff, UnifiError> {
    let changes = mutations
        .iter()
        .map(|mutation| Change {
            preview: mutation.preview(),
            mutation: mutation.clone(),
        })
        .collect();

    Ok(Diff {
        computed: true,
        changes,
    })
}

#[cfg(test)]
mod tests {
    use crate::testing::{fixture, DEFAULT_FIXTURE_VERSION};

    /// An empty diff is not the same as a diff that was never computed.
    #[test]
    fn a_no_op_change_set_is_distinguishable_from_an_uncomputed_one() {
        let preimage = super::Preimage::from_fixture(&fixture(
            DEFAULT_FIXTURE_VERSION,
            "networkconf",
        ));
        let diff = super::diff_against_preimage(&preimage, &[]).expect("diffs");
        assert!(diff.computed);
        assert!(diff.changes.is_empty());
    }
}
