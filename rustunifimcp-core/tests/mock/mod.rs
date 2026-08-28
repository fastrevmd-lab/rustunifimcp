//! Mock controller for lifecycle testing.
//!
//! A plain in-memory struct that simulates UniFi controller behavior without
//! needing an HTTP server.

use rustunifimcp_core::changeset::{ControllerOps, StagedMutation};
use rustunifimcp_core::error::UnifiError;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Rollback history entry: (index, prior_value, created_id).
type RollbackEntry = (usize, Option<serde_json::Value>, Option<String>);

/// Mock controller state shared across async calls.
#[derive(Clone)]
pub struct MockController {
    state: Arc<MockState>,
}

struct MockState {
    behavior: Behavior,
    write_calls: AtomicUsize,
    rollback_calls: AtomicUsize,
    /// Records (index, prior_value, created_id) for each rollback call
    rollback_history: Mutex<Vec<RollbackEntry>>,
}

#[derive(Clone)]
enum Behavior {
    SucceedAll,
    FailAt(usize),
    FailAtWithRollbackFailure { fail_at: usize, rollback_fail_at: usize },
    DriftBeforeApply,
}

impl MockController {
    /// Create a new mock controller.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(MockState {
                behavior: Behavior::SucceedAll,
                write_calls: AtomicUsize::new(0),
                rollback_calls: AtomicUsize::new(0),
                rollback_history: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Configure the mock to succeed all operations.
    #[must_use]
    pub fn succeed_all(mut self) -> Self {
        Arc::get_mut(&mut self.state)
            .expect("mock state should be exclusively owned during configuration")
            .behavior = Behavior::SucceedAll;
        self
    }

    /// Configure the mock to fail at the nth mutation (1-indexed).
    #[must_use]
    pub fn fail_at(mut self, n: usize) -> Self {
        Arc::get_mut(&mut self.state)
            .expect("mock state should be exclusively owned during configuration")
            .behavior = Behavior::FailAt(n);
        self
    }

    /// Configure the mock to fail rollback at the nth rollback operation (1-indexed).
    #[must_use]
    pub fn fail_rollback_at(mut self, rollback_fail_at: usize) -> Self {
        let fail_at = match &self.state.behavior {
            Behavior::FailAt(n) => *n,
            _ => panic!("fail_rollback_at requires fail_at to be set first"),
        };
        Arc::get_mut(&mut self.state)
            .expect("mock state should be exclusively owned during configuration")
            .behavior = Behavior::FailAtWithRollbackFailure {
            fail_at,
            rollback_fail_at,
        };
        self
    }

    /// Configure the mock to report drift before apply.
    #[must_use]
    pub fn drift_before_apply(mut self) -> Self {
        Arc::get_mut(&mut self.state)
            .expect("mock state should be exclusively owned during configuration")
            .behavior = Behavior::DriftBeforeApply;
        self
    }

    /// Get the count of write calls.
    #[must_use]
    pub fn write_calls(&self) -> usize {
        self.state.write_calls.load(Ordering::SeqCst)
    }

    /// Get the count of rollback calls.
    #[must_use]
    pub fn rollback_calls(&self) -> usize {
        self.state.rollback_calls.load(Ordering::SeqCst)
    }

    /// Get the rollback history (index, prior_value, created_id) for each call.
    #[must_use]
    pub fn rollback_history(&self) -> Vec<RollbackEntry> {
        self.state
            .rollback_history
            .lock()
            .expect("lock should not be poisoned")
            .clone()
    }

    /// Check if the pre-image matches (for drift detection).
    #[must_use]
    pub fn preimage_matches_sync(&self) -> bool {
        !matches!(self.state.behavior, Behavior::DriftBeforeApply)
    }
}

impl ControllerOps for MockController {
    async fn apply_mutation(&self, index: usize, mutation: &StagedMutation) -> Result<Option<String>, UnifiError> {
        let should_fail = match &self.state.behavior {
            Behavior::SucceedAll => false,
            Behavior::FailAt(n) | Behavior::FailAtWithRollbackFailure { fail_at: n, .. } => {
                index + 1 >= *n
            }
            Behavior::DriftBeforeApply => false,
        };

        self.state.write_calls.fetch_add(1, Ordering::SeqCst);

        if should_fail {
            Err(UnifiError::Upstream {
                status: 500,
                detail: format!("mock failure at mutation {}", index + 1),
            })
        } else {
            // Return a mock ID for creates
            let created_id = match mutation {
                StagedMutation::Create { kind, .. } => Some(format!("mock-{}-{}", kind, index)),
                _ => None,
            };
            Ok(created_id)
        }
    }

    async fn rollback_mutation(
        &self,
        index: usize,
        _mutation: &StagedMutation,
        prior_value: Option<&serde_json::Value>,
        created_id: Option<&str>,
    ) -> Result<(), UnifiError> {
        let should_fail = match &self.state.behavior {
            Behavior::FailAtWithRollbackFailure { rollback_fail_at, .. } => {
                index + 1 >= *rollback_fail_at
            }
            _ => false,
        };

        self.state.rollback_calls.fetch_add(1, Ordering::SeqCst);

        // Record the rollback call with its prior_value and created_id
        self.state
            .rollback_history
            .lock()
            .expect("lock should not be poisoned")
            .push((index, prior_value.cloned(), created_id.map(str::to_owned)));

        if should_fail {
            Err(UnifiError::Upstream {
                status: 500,
                detail: format!("mock rollback failure at index {}", index + 1),
            })
        } else {
            Ok(())
        }
    }

    async fn preimage_matches(&self) -> bool {
        self.preimage_matches_sync()
    }

    async fn fetch_resource(
        &self,
        _kind: &str,
        _id: &str,
    ) -> Result<Option<serde_json::Value>, UnifiError> {
        // Mock always reports resources as existing for verification
        Ok(Some(serde_json::json!({"_id": _id})))
    }
}
