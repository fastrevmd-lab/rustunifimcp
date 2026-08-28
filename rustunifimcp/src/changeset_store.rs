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
    /// The pre-image snapshot.
    pub preimage: Option<Preimage>,
    /// Staged mutations.
    pub mutations: Vec<StagedMutation>,
    /// Apply outcome, if applied.
    pub outcome: Option<Outcome>,
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
        let mut sets = self.sets.write()
            .map_err(|_| "lock poisoned".to_owned())?;

        sets.insert(set.id.clone(), set);

        if let Some(ref path) = self.state_file {
            let contents = serde_json::to_string_pretty(&*sets)
                .map_err(|e| format!("failed to serialize state: {e}"))?;
            std::fs::write(path, contents)
                .map_err(|e| format!("failed to write state file: {e}"))?;
        }

        Ok(())
    }

    /// Retrieve a change set by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned.
    pub fn get(&self, id: &str) -> Result<Option<ChangeSet>, String> {
        let sets = self.sets.read()
            .map_err(|_| "lock poisoned".to_owned())?;
        Ok(sets.get(id).cloned())
    }

    /// Remove a change set by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the state file cannot be written.
    pub fn remove(&self, id: &str) -> Result<Option<ChangeSet>, String> {
        let mut sets = self.sets.write()
            .map_err(|_| "lock poisoned".to_owned())?;

        let removed = sets.remove(id);

        if removed.is_some() && let Some(ref path) = self.state_file {
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
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn in_memory_store_works() {
        let store = ChangeSetStore::new(None).unwrap();

        let set = ChangeSet {
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
