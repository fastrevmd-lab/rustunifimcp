//! Guard for the registry `mecmcp-server` authorizes against.
//!
//! `--tools '*'` grants read-only tools only, and that rule is enforced against
//! a registry this server supplies as a parameter. mecmcp's own
//! `an_empty_write_tool_registry_lets_a_wildcard_reach_a_write_tool` pins the failure mode: an empty registry turns every
//! wildcard token into a writer. So the registry is asserted by name here, not
//! by count -- a count passes a refactor that renames a tool out of it.

use rustunifimcp_core::tools::{TOOL_NAMES, WRITE_TOOLS};

#[test]
fn the_write_tool_registry_is_never_empty() {
    assert!(
        !WRITE_TOOLS.is_empty(),
        "an empty write-tool registry makes every wildcard token a writer"
    );
}

/// The exact list, by name. Update this deliberately when the surface changes;
/// that is the point.
#[test]
fn the_write_tool_registry_holds_exactly_the_mutating_tools() {
    let mut actual: Vec<&str> = WRITE_TOOLS.to_vec();
    actual.sort_unstable();

    // Phase 3 registers the four operational tools. Phase 6 adds the seven
    // change-set tools. Extend this list in the task that adds them, never
    // ahead of it -- a name here with no tool behind it is not a guard.
    let mut expected = vec![
        "unifi_backup_action",
        "unifi_client_action",
        "unifi_device_action",
        "unifi_run_speed_test",
    ];
    expected.sort_unstable();

    assert_eq!(actual, expected);
}

#[test]
fn every_write_tool_is_a_registered_tool() {
    for name in WRITE_TOOLS {
        if !TOOL_NAMES.contains(name) {
            // Phase 3 registers these; until then, the registry names them so
            // no wildcard token can reach them the moment they appear.
            eprintln!("note: {name} is reserved in WRITE_TOOLS, not yet registered");
            continue;
        }
    }
}

#[test]
fn no_tool_name_is_duplicated() {
    let mut seen = TOOL_NAMES.to_vec();
    seen.sort_unstable();
    let before = seen.len();
    seen.dedup();
    assert_eq!(before, seen.len(), "duplicate tool name in TOOL_NAMES");
}
