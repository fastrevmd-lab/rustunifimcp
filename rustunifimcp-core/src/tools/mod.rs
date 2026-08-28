//! The MCP tool surface.
//!
//! Roughly 24 tools, against roughly 270 on the server this replaces. The shape
//! follows the mechub family: typed primitives, a change-control lifecycle, and
//! a small number of workflows that earn their names.

pub mod read;

/// Every tool this server registers.
///
/// Kept in one place so `filter_tools_for_scope` and the registry guard read
/// the same list.
pub const TOOL_NAMES: &[&str] = &[
    // Read (5)
    "unifi_list_resources",
    "unifi_get_resource",
    "unifi_query_stats",
    "unifi_search",
    "unifi_list_sites",
    // Administration (3)
    "unifi_list_controllers",
    "unifi_add_controller",
    "unifimcp_status",
];

/// The mutating tools, passed to `mecmcp_server::authorize_call`.
///
/// **This must never be empty and must never be computed.** `--tools '*'`
/// grants read-only tools only, and the rule is enforced against exactly this
/// slice. `mecmcp-server`'s own `an_empty_write_tool_registry_lets_a_wildcard_reach_a_write_tool` demonstrates that an empty
/// registry turns every wildcard token into a writer, so the list is written
/// out by hand and asserted by name in `tests/write_tool_registry.rs`.
pub const WRITE_TOOLS: &[&str] = &[
    // Administration — inventory mutation
    "unifi_add_controller",
    // Phase 3 — operational actions
    "unifi_device_action",
    "unifi_client_action",
    "unifi_backup_action",
    "unifi_run_speed_test",
    // Phase 6 adds the seven change-set tools here.
];
