//! Change-set state storage.
//!
//! UniFi change sets must persist across tool calls. This module provides
//! in-memory storage with optional file-backed persistence.

use rustunifimcp_core::changeset::{Outcome, Preimage, StagedMutation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

/// A stored change set with its lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeSet {
    /// Unique identifier for this change set.
    pub id: String,
    /// The controller this change set targets.
    pub controller: String,
    /// Human-readable description.
    pub description: String,
    /// The creator's token name.
    pub creator: String,
    /// The approver's token name, if approved.
    pub approver: Option<String>,
    /// Approval waiver reason, if in lab mode.
    pub approval_waiver: Option<String>,
    /// When the approval was granted, as seconds since the Unix epoch.
    ///
    /// An approval is a statement about a controller state at a moment. Without
    /// a time it cannot expire, and a persisted approval would stay usable for
    /// as long as the file survives -- which is what `--approval-timeout-secs`
    /// exists to prevent.
    #[serde(default)]
    pub approved_at: Option<u64>,
    /// The pre-image snapshot.
    pub preimage: Option<Preimage>,
    /// Staged mutations.
    pub mutations: Vec<StagedMutation>,
    /// Apply outcome, if applied.
    pub outcome: Option<Outcome>,
}

/// Write `contents` to `path` so a reader sees the old file or the new one.
///
/// A direct write can be interrupted midway and leave truncated JSON, which on
/// the next start is a store that will not parse -- every persisted approval
/// lost to a partial write.
fn write_atomically(path: &std::path::Path, contents: &str) -> Result<(), String> {
    let directory = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let temporary = directory.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("changesets")
    ));
    std::fs::write(&temporary, contents).map_err(|e| format!("failed to write state file: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // The store holds pre-images of controller configuration.
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("failed to set state file permissions: {e}"))?;
    }
    std::fs::rename(&temporary, path).map_err(|e| format!("failed to commit state file: {e}"))
}

/// In-memory change-set store with optional file persistence.
#[derive(Clone)]
pub struct ChangeSetStore {
    /// The in-memory map of change sets.
    sets: Arc<RwLock<HashMap<String, ChangeSet>>>,
    /// Optional path to persist the state file.
    state_file: Option<PathBuf>,
}

impl ChangeSetStore {
    /// Create a new store with optional file backing.
    ///
    /// If `state_file` is provided, the store will attempt to load existing
    /// state from it and persist changes on every write.
    ///
    /// # Errors
    ///
    /// Returns an error if the state file exists but cannot be read or parsed.
    pub fn new(state_file: Option<PathBuf>) -> Result<Self, String> {
        let sets = if let Some(ref path) = state_file {
            if path.exists() {
                let contents = std::fs::read_to_string(path)
                    .map_err(|e| format!("failed to read state file: {e}"))?;
                // Handle empty files gracefully
                if contents.trim().is_empty() {
                    HashMap::new()
                } else {
                    let loaded: HashMap<String, ChangeSet> = serde_json::from_str(&contents)
                        .map_err(|e| format!("failed to parse state file: {e}"))?;
                    loaded
                }
            } else {
                HashMap::new()
            }
        } else {
            HashMap::new()
        };

        Ok(Self {
            sets: Arc::new(RwLock::new(sets)),
            state_file,
        })
    }

    /// Insert or update a change set.
    ///
    /// # Errors
    ///
    /// Returns an error if the state file cannot be written.
    pub fn insert(&self, set: ChangeSet) -> Result<(), String> {
        let mut sets = self.sets.write().map_err(|_| "lock poisoned".to_owned())?;

        // Persist before memory, and only commit memory if persistence held.
        //
        // Writing memory first meant a failed write left the process believing
        // an approval it had reported as failed: the caller saw an error, the
        // next call saw the approval. Restart then disagreed with both.
        if let Some(ref path) = self.state_file {
            let mut candidate = sets.clone();
            candidate.insert(set.id.clone(), set.clone());
            let contents = serde_json::to_string_pretty(&candidate)
                .map_err(|e| format!("failed to serialize state: {e}"))?;
            write_atomically(path, &contents)?;
        }

        sets.insert(set.id.clone(), set);
        Ok(())
    }

    /// Retrieve a change set by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned.
    pub fn get(&self, id: &str) -> Result<Option<ChangeSet>, String> {
        let sets = self.sets.read().map_err(|_| "lock poisoned".to_owned())?;
        Ok(sets.get(id).cloned())
    }

    /// Remove a change set by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the state file cannot be written.
    pub fn remove(&self, id: &str) -> Result<Option<ChangeSet>, String> {
        let mut sets = self.sets.write().map_err(|_| "lock poisoned".to_owned())?;

        let removed = sets.remove(id);

        if removed.is_some()
            && let Some(ref path) = self.state_file
        {
            let contents = serde_json::to_string_pretty(&*sets)
                .map_err(|e| format!("failed to serialize state: {e}"))?;
            std::fs::write(path, contents)
                .map_err(|e| format!("failed to write state file: {e}"))?;
        }

        Ok(removed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {

    /// A failed persist must not leave the change set live in memory.
    ///
    /// Writing memory first meant a caller could be told the approval failed
    /// while the next call saw it succeed, and a restart agreed with neither.
    #[test]
    fn a_failed_persist_leaves_no_trace_in_memory() {
        let unwritable = PathBuf::from("/nonexistent-directory-for-tests/state.json");
        let store =
            ChangeSetStore::new(Some(unwritable)).expect("a missing file is an empty store");
        let set = ChangeSet {
            approved_at: None,
            id: "cs-1".to_owned(),
            controller: "home".to_owned(),
            description: "probe".to_owned(),
            creator: "alice".to_owned(),
            approver: None,
            approval_waiver: None,
            preimage: None,
            mutations: Vec::new(),
            outcome: None,
        };
        assert!(
            store.insert(set).is_err(),
            "an unwritable state file must fail the insert"
        );
        assert!(
            store.get("cs-1").expect("lock").is_none(),
            "a change set whose persistence failed must not be readable"
        );
    }

    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn in_memory_store_works() {
        let store = ChangeSetStore::new(None).unwrap();

        let set = ChangeSet {
            approved_at: None,
            id: "test-1".to_owned(),
            controller: "home".to_owned(),
            description: "test".to_owned(),
            creator: "alice".to_owned(),
            approver: None,
            approval_waiver: None,
            preimage: None,
            mutations: Vec::new(),
            outcome: None,
        };

        store.insert(set.clone()).unwrap();

        let retrieved = store.get("test-1").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, "test-1");
    }

    #[test]
    fn file_backed_store_persists() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path().to_path_buf();

        let set = ChangeSet {
            approved_at: None,
            id: "test-2".to_owned(),
            controller: "home".to_owned(),
            description: "test".to_owned(),
            creator: "alice".to_owned(),
            approver: None,
            approval_waiver: None,
            preimage: None,
            mutations: Vec::new(),
            outcome: None,
        };

        {
            let store = ChangeSetStore::new(Some(path.clone())).unwrap();
            store.insert(set.clone()).unwrap();
        }

        // Reload from file
        let store2 = ChangeSetStore::new(Some(path)).unwrap();
        let retrieved = store2.get("test-2").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, "test-2");
    }

    #[test]
    fn remove_updates_file() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path().to_path_buf();

        let set = ChangeSet {
            approved_at: None,
            id: "test-3".to_owned(),
            controller: "home".to_owned(),
            description: "test".to_owned(),
            creator: "alice".to_owned(),
            approver: None,
            approval_waiver: None,
            preimage: None,
            mutations: Vec::new(),
            outcome: None,
        };

        let store = ChangeSetStore::new(Some(path.clone())).unwrap();
        store.insert(set.clone()).unwrap();
        store.remove("test-3").unwrap();

        // Reload from file
        let store2 = ChangeSetStore::new(Some(path)).unwrap();
        let retrieved = store2.get("test-3").unwrap();
        assert!(retrieved.is_none());
    }
}
