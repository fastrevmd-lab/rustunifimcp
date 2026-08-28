//! The change-set state machine, including the paths that only exist because
//! UniFi cannot apply atomically.
//!
//! These matter more here than in the sibling servers. Junos and PAN-OS either
//! commit or do not; UniFi can leave three of five mutations applied, and the
//! server has to say so accurately.

mod mock;

use mock::MockController;
use rustunifimcp_core::changeset::apply::{apply_sequentially, Outcome, State};
use rustunifimcp_core::changeset::{Preimage, StagedMutation};
use serde_json::json;

/// Run a change set through the full lifecycle.
async fn run_change_set(controller: &MockController, mutations: Vec<StagedMutation>) -> Outcome {
    let preimage = Preimage::from_fixture(&json!({"data": []}));
    apply_sequentially(controller, &preimage, &mutations).await
}

/// Five staged mutations for testing the lifecycle.
fn five_mutations() -> Vec<StagedMutation> {
    vec![
        StagedMutation::create("network", json!({"name": "test1"})),
        StagedMutation::create("network", json!({"name": "test2"})),
        StagedMutation::update("network", "id3", json!({"name": "test3"})),
        StagedMutation::update("network", "id4", json!({"name": "test4"})),
        StagedMutation::delete("network", "id5"),
    ]
}

#[tokio::test]
async fn a_clean_apply_reports_applied() {
    let controller = MockController::new().succeed_all();
    let outcome = run_change_set(&controller, five_mutations()).await;
    assert_eq!(outcome.state, State::Applied);
    assert_eq!(outcome.succeeded.len(), 5);
    assert!(outcome.failed.is_empty());
}

#[tokio::test]
async fn a_failure_midway_reports_partial_and_names_both_sides() {
    let controller = MockController::new().fail_at(3);
    let outcome = run_change_set(&controller, five_mutations()).await;

    assert_eq!(outcome.state, State::Partial);
    assert_eq!(outcome.succeeded.len(), 2, "the first two landed");
    assert_eq!(outcome.failed.len(), 3, "the third failed and two never ran");
    // The distinction matters to whoever cleans up.
    assert_eq!(outcome.attempted_and_failed.len(), 1);
    assert_eq!(outcome.never_attempted.len(), 2);
}

#[tokio::test]
async fn a_partial_apply_attempts_rollback_of_what_landed() {
    let controller = MockController::new().fail_at(3);
    let _outcome = run_change_set(&controller, five_mutations()).await;
    assert_eq!(
        controller.rollback_calls(),
        2,
        "only what landed is rolled back"
    );
}

/// The path the sibling servers never have to consider.
#[tokio::test]
async fn a_failed_rollback_is_recorded_not_swallowed() {
    let controller = MockController::new().fail_at(3).fail_rollback_at(1);
    let outcome = run_change_set(&controller, five_mutations()).await;

    assert_eq!(outcome.state, State::PartialRollbackFailed);
    assert!(
        !outcome.rollback_failures.is_empty(),
        "a rollback that failed must be reported; this is the state an operator \
         has to be woken for"
    );
}

/// Applying against a controller whose state moved since approval must be
/// refused -- the pre-image is what the approval was bound to.
#[tokio::test]
async fn apply_refuses_when_the_preimage_no_longer_matches() {
    let controller = MockController::new().drift_before_apply();
    let outcome = run_change_set(&controller, five_mutations()).await;
    assert_eq!(outcome.state, State::RefusedStale);
    assert_eq!(controller.write_calls(), 0, "nothing was written");
}

/// Rollback must pass the pre-image value for updates and deletes.
#[tokio::test]
async fn rollback_of_update_passes_preimage_value() {
    use serde_json::json;

    let preimage_data = json!({
        "data": [{
            "_id": "id3",
            "name": "original_name"
        }]
    });
    let preimage = Preimage::from_fixture(&preimage_data);

    // fail_at(3) means fail at the 3rd mutation, so the first two succeed and are rolled back
    let controller = MockController::new().fail_at(3);
    let mutations = vec![
        StagedMutation::create("network", json!({"name": "test1"})),
        StagedMutation::update("network", "id3", json!({"name": "new_name"})),
        StagedMutation::create("network", json!({"name": "test2"})), // This will fail
    ];

    let _outcome = apply_sequentially(&controller, &preimage, &mutations).await;

    let history = controller.rollback_history();
    assert_eq!(history.len(), 2, "first two mutations should be rolled back");

    // First rollback (index 1, the update) should have the pre-image value
    assert_eq!(history[0].0, 1, "first rollback should be for index 1 (reverse order)");
    assert!(
        history[0].1.is_some(),
        "update rollback must receive the pre-image value"
    );
    assert_eq!(
        history[0].1.as_ref().expect("pre-image value").get("name").and_then(|v| v.as_str()),
        Some("original_name"),
        "the pre-image value should be the original"
    );

    // Second rollback (index 0, the create) should have None
    assert_eq!(history[1].0, 0, "second rollback should be for index 0");
    assert!(
        history[1].1.is_none(),
        "create rollback should receive None (delete it)"
    );
}

/// Rollback must proceed in reverse order - last mutation first.
#[tokio::test]
async fn rollback_proceeds_in_reverse_order() {
    let controller = MockController::new().fail_at(4);
    let _outcome = run_change_set(&controller, five_mutations()).await;
    
    let history = controller.rollback_history();
    assert_eq!(history.len(), 3, "three mutations should be rolled back");
    
    // Rollback order should be reverse: index 2, then 1, then 0
    let indices: Vec<usize> = history.iter().map(|(idx, _)| *idx).collect();
    assert_eq!(
        indices,
        vec![2, 1, 0],
        "rollback must proceed in reverse order"
    );
}
