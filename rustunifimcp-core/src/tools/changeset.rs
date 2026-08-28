//! Change-set lifecycle tools.
//!
//! UniFi Network has no candidate configuration, no dry-run validation, and no
//! checkpoint to roll back to. The seven tools below implement the change-control
//! lifecycle over UniFi's immediate-write REST API as a best-effort approximation,
//! with explicit honesty about what cannot be guaranteed.

/// Tool descriptions for all seven change-set tools.
///
/// Written here so the honesty tests in `changeset/mod.rs` can run before the
/// handlers exist. Task 27 registers handlers against these same names.
pub const DESCRIPTIONS: &[(&str, &str)] = &[
    (
        "unifi_create_change_set",
        "Creates a new change set with a fingerprint snapshot of current running \
         configuration for the touched resources. Returns the change set ID. \
         UniFi has no candidate configuration, so the fingerprint is computed \
         over live state rather than a staged candidate."
    ),
    (
        "unifi_stage_actions",
        "Stages one or more actions into an existing change set. Each action is \
         recorded as a planned mutation against live configuration. Because UniFi \
         writes directly to running state, staging is a planning step only — it \
         snapshots the current state as a pre-image and defers the actual writes \
         until apply."
    ),
    (
        "unifi_get_change_set_diff",
        "Returns a diff showing what applying the change set would do, based on \
         the staged actions and the current running state. Because UniFi has no \
         candidate to diff against running, this is a projection of the planned \
         mutations, not a server-generated diff."
    ),
    (
        "unifi_validate_change_set",
        "Validates the change set as far as possible without applying it. UniFi \
         has no server-side dry-run validation, so this performs client-side \
         checks only: referential integrity, schema constraints, and fingerprint \
         staleness. It cannot detect issues the controller would find on apply."
    ),
    (
        "unifi_apply_change_set",
        "Applies the staged changes as a sequence of independent REST calls \
         against live configuration. UniFi has no candidate configuration and no \
         commit, so a partial failure is a reachable outcome and is recorded as \
         `partial`. Rollback replays a stored pre-image and is best-effort; it \
         can itself fail."
    ),
    (
        "unifi_rollback_change_set",
        "Attempts to revert the change set by replaying the stored pre-image as \
         a sequence of REST calls. Because UniFi has no checkpoint to roll back \
         to, this is best-effort compensation — the rollback itself can fail \
         partway through. Only available after a failed or partial apply."
    ),
    (
        "unifi_get_change_set_status",
        "Returns the current status of a change set: pending, applied, failed, \
         partial, or rolled back. Includes the fingerprint, staged actions, any \
         apply outcome, and whether rollback is available."
    ),
];
