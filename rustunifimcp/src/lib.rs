//! `rustunifimcp` binary library.
//!
//! The binary crate is thin: CLI, transport bootstrap, and token utilities.
//! All vendor logic belongs in `rustunifimcp-core`.

pub mod changeset_store;
pub mod cli;
pub mod http_transport;
pub mod server;
