//! The change-set store: `mecmcp-changeset`'s coordinator, and getting onto it.
//!
//! What this replaces was a persisted `HashMap` with `insert` / `get` /
//! `remove` and no state machine. Three protections the rest of the fleet
//! spent three mecmcp minors acquiring were therefore absent here, and each is
//! a way a write reaches a controller it should not have:
//!
//! - **Claim before apply** (0.22.0). Two concurrent applies could both read
//!   `Approved` and both proceed. `claim_change_set_for_apply` does the read
//!   and the write under one lock, and is the only legal route to `Applying`.
//! - **A transition policy** (0.22.0). Any field could be written over any
//!   other at any time. rustmistmcp found its drift path writing
//!   `Approved -> Failed` directly, the refusal being swallowed into an audit
//!   line, and a drifted change set left `Approved` with its approval still
//!   spendable.
//! - **Preview-bound approval** (0.23.0). An approval referenced no preview at
//!   all, so nothing tied a reviewer's consent to what they had read.
//!
//! None of that is reimplemented here. This module builds the coordinator, and
//! refuses to start on a state file written by the old store.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use mecmcp_changeset::{ChangesetCoordinator, OperationLimits};

/// A state file no larger than this is worth reading to see if it is blank.
///
/// Bounded so a large file is never slurped just to check for whitespace.
const MAX_BLANK_STATE_BYTES: u64 = 4096;

/// Ceilings for the change-set store.
///
/// Deliberately small. A single-operator homelab controller does not have a
/// hundred change sets in flight, and an unbounded store is a way for a state
/// file to grow until it stops being loadable.
#[must_use]
pub fn limits() -> OperationLimits {
    OperationLimits {
        max_operations: 100,
        max_change_sets: 100,
        // UniFi applies each mutation as its own REST call with no commit, so a
        // long change set is a long partial-failure window. Ten is generous for
        // a zone-policy edit.
        max_actions_per_set: 10,
        max_change_set_bytes: 1024 * 1024,
        max_state_bytes: 10 * 1024 * 1024,
        // Single-controller change sets only: a change set names one controller
        // and its resource ids mean nothing on another.
        max_targets_per_set: 1,
        max_preview_bytes: 256 * 1024,
    }
}

/// A change-set identifier the shared lifecycle will accept.
///
/// 64 hex characters, which is what `mecmcp_changeset` validates ids against.
/// The old store minted `cs-<uuid>`, which that check refuses.
#[must_use]
pub fn new_change_set_id() -> String {
    mecmcp_changeset::digest::digest_hex(uuid::Uuid::new_v4().as_bytes())
}

/// Build the change-set coordinator.
///
/// # Errors
///
/// Returns a message naming what to do if the state file was written by the
/// old store, if the path cannot be made absolute, or if the coordinator
/// refuses the state.
pub fn build_coordinator(
    state_file: Option<&Path>,
    approval_ttl: Duration,
    lab_mode: bool,
    evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
) -> Result<Arc<ChangesetCoordinator>, String> {
    let absolute = match state_file {
        Some(path) => Some(absolute_path(path)?),
        None => None,
    };

    if let Some(ref path) = absolute {
        discard_blank_state_file(path)?;
        refuse_legacy_state_file(path)?;
    }

    let mut coordinator =
        ChangesetCoordinator::load(absolute.as_deref(), limits(), approval_ttl, lab_mode).map_err(
            |error| format!("change-set state ({}): {}", error.field(), error.message()),
        )?;

    if let Some(recorder) = evidence {
        coordinator = coordinator.with_evidence(recorder);
    }

    Ok(Arc::new(coordinator))
}

/// Remove a state file that holds nothing.
///
/// The coordinator refuses to parse an empty file -- "EOF while parsing a
/// value" -- and the store this replaces tolerated one deliberately. A blank
/// file is reachable: an interrupted first write, or a packaging step that
/// pre-creates the path under a `StateDirectory`. Refusing to start on it
/// would be a regression, and it carries no state to lose, so it goes and
/// `load` creates a real one on the first write.
///
/// # Errors
///
/// Returns a message if the file exists, is blank, and cannot be removed.
fn discard_blank_state_file(path: &Path) -> Result<(), String> {
    let Ok(metadata) = std::fs::metadata(path) else {
        return Ok(());
    };
    if !metadata.is_file() || metadata.len() > MAX_BLANK_STATE_BYTES {
        return Ok(());
    }
    match std::fs::read_to_string(path) {
        Ok(contents) if contents.trim().is_empty() => {
            std::fs::remove_file(path).map_err(|error| {
                format!(
                    "{} holds no change-set state and could not be removed: {error}",
                    path.display()
                )
            })?;
            tracing::info!(
                path = %path.display(),
                "change-set state file was empty; starting with an empty store"
            );
            Ok(())
        }
        // Non-empty, or unreadable. `load` reports both, with the path.
        _ => Ok(()),
    }
}

/// The coordinator requires an absolute path; `--state-file` may be relative.
fn absolute_path(path: &Path) -> Result<PathBuf, String> {
    std::path::absolute(path).map_err(|error| {
        format!(
            "--state-file {} cannot be made absolute: {error}",
            path.display()
        )
    })
}

/// Refuse a state file written by the store this replaces.
///
/// The old file was a bare JSON object of change-set id to record. The
/// coordinator's is `{"version": <n>, "state": {...}}`, and it rejects the old
/// shape with a deserialization error that says nothing about what happened or
/// what to do.
///
/// It is not converted, and the reason is the approvals. An approval is now
/// bound to the digest of the preview the reviewer read, and the old records
/// have no preview -- there was none to store. Synthesising one would mint an
/// approval digest over text nobody ever saw, which is precisely the thing
/// preview binding exists to prevent. The mutations could be carried across as
/// unapproved plans, but a change set that has to be re-approved is a change
/// set that may as well be re-planned, and re-planning re-reads the controller
/// rather than trusting a pre-image of unknown age.
///
/// So: name the file, say what is in it, and stop.
fn refuse_legacy_state_file(path: &Path) -> Result<(), String> {
    let Ok(contents) = std::fs::read_to_string(path) else {
        // Unreadable or absent. `load` reports both, with the path.
        return Ok(());
    };
    if contents.trim().is_empty() {
        return Ok(());
    }

    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&contents) else {
        // Not JSON at all. `load` is the right place to complain.
        return Ok(());
    };

    let Some(object) = parsed.as_object() else {
        return Ok(());
    };
    if object.contains_key("version") {
        return Ok(());
    }

    // The old store's records are the giveaway: it keyed on the change-set id
    // and every value carried `controller` and `mutations`.
    let legacy: Vec<&String> = object
        .iter()
        .filter(|(_, record)| {
            record.get("controller").is_some() && record.get("mutations").is_some()
        })
        .map(|(id, _)| id)
        .collect();

    if legacy.is_empty() {
        return Ok(());
    }

    Err(format!(
        "{} was written by the change-set store this version replaces, and holds {} change \
         set(s): {}. They are not carried forward: an approval is now bound to the digest of \
         the preview its approver read, and these records have no preview, so carrying one \
         across would mint an approval over text nobody saw. Move the file aside and re-plan \
         the change sets -- re-planning re-reads the controller rather than trusting a \
         pre-image of unknown age.",
        path.display(),
        legacy.len(),
        legacy
            .iter()
            .map(|id| id.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    ))
}

#[cfg(test)]
mod tests {
    use super::{build_coordinator, limits, new_change_set_id};
    use std::time::Duration;

    /// The coordinator reads the state file through the workspace's hardened
    /// file reader, which refuses a group- or world-readable mode. The store
    /// this replaces wrote 0600 but did not require it on read, so an existing
    /// file at a laxer mode is a startup failure with a `chmod` in the message.
    fn coordinator_from(contents: &str) -> Result<(), String> {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("changesets.json");
        std::fs::write(&path, contents).expect("write state");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("harden the state file");
        }
        build_coordinator(Some(&path), Duration::from_secs(300), true, None).map(|_| ())
    }

    /// The id has to satisfy the shared lifecycle's validator. The old store
    /// minted `cs-<uuid>`, which it refuses, so every insert would fail.
    #[test]
    fn a_minted_id_is_one_the_lifecycle_accepts() {
        let id = new_change_set_id();
        mecmcp_changeset::OperationId::new(id.clone())
            .unwrap_or_else(|error| panic!("the lifecycle refused {id}: {error}"));
    }

    #[test]
    fn ids_are_not_reused() {
        assert_ne!(new_change_set_id(), new_change_set_id());
    }

    /// A change set targets one controller, so more than one target is not a
    /// shape this server can mean.
    #[test]
    fn a_change_set_may_name_only_one_controller() {
        assert_eq!(limits().max_targets_per_set, 1);
    }

    /// The old state file must stop the server with an explanation, not with a
    /// deserialization error, and not by silently starting empty -- which would
    /// leave two stored change sets looking as though they had never existed.
    #[test]
    fn a_legacy_state_file_stops_the_server_and_says_what_to_do() {
        let legacy = serde_json::json!({
            "cs-11111111-1111-4111-8111-111111111111": {
                "id": "cs-11111111-1111-4111-8111-111111111111",
                "controller": "home",
                "description": "probe",
                "creator": "alice",
                "approver": "bob",
                "mutations": [],
                "outcome": null
            }
        })
        .to_string();

        let error = coordinator_from(&legacy).expect_err("a legacy file must not load");
        assert!(
            error.contains("cs-11111111-1111-4111-8111-111111111111"),
            "the operator needs to know which change sets are in it: {error}"
        );
        assert!(error.contains("re-plan"), "{error}");
        assert!(error.contains("preview"), "{error}");
    }

    /// And the refusal must not fire on the coordinator's own file, or the
    /// server stops starting after its first clean run.
    #[test]
    fn the_coordinators_own_state_file_loads() {
        let current = serde_json::json!({
            "version": 6,
            "state": { "operations": {}, "change_sets": {} }
        })
        .to_string();
        coordinator_from(&current).expect("the coordinator's own file must load");
    }

    /// An empty file is a fresh start, which is how an interrupted first write
    /// or a pre-created path under a `StateDirectory` looks. The coordinator
    /// refuses to parse one, and the store this replaces tolerated it, so
    /// refusing to start would be a regression.
    #[test]
    fn an_empty_state_file_is_a_fresh_store() {
        coordinator_from("").expect("an empty file is an empty store");
        coordinator_from("   \n").expect("whitespace is not state either");
    }

    /// Only a blank file is discarded. Anything with content in it is the
    /// coordinator's to accept or refuse.
    #[test]
    fn a_populated_state_file_is_never_discarded() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("changesets.json");
        std::fs::write(&path, "{\"version\": 6, \"state\": {}}").expect("write");
        super::discard_blank_state_file(&path).expect("not blank, so nothing to do");
        assert!(path.exists(), "a populated state file must not be removed");
    }

    /// A relative `--state-file` is accepted here and made absolute, because
    /// the coordinator refuses a relative path outright.
    #[test]
    fn no_state_file_means_an_in_memory_store() {
        build_coordinator(None, Duration::from_secs(300), false, None)
            .expect("no state file is a valid configuration");
    }
}
