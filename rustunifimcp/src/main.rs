//! `rustunifimcp` — enterprise MCP server for UniFi Network.
//!
//! The binary is deliberately thin: CLI, TLS bootstrap, and serve, all of which
//! come from `mecmcp-runtime` once that crate is tagged. Implementation is
//! gated on `mecmcp`; see `PLAN.md` at the workspace root.

fn main() {
    eprintln!(
        "rustunifimcp is not implemented yet — see PLAN.md for the mecmcp crates each phase is gated on."
    );
    std::process::exit(1);
}
