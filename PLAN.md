# rustunifimcp plan

Phase sequence for building the UniFi Network MCP server described in
[`docs/superpowers/specs/2026-07-24-rustunifimcp-design.md`](docs/superpowers/specs/2026-07-24-rustunifimcp-design.md).

Written 2026-07-24. **Implementation has not started and is gated on `mecmcp`.**

## The gate

`rustunifimcp` is built mecmcp-native by design — it contains no local auth,
transport, audit, policy, inventory, or change-control code. Today `mecmcp` has
shipped exactly one crate, `mecmcp-auth` (tag `auth-v0.1.1`). Everything else in
its crate map is planned but unwritten.

Starting implementation now would mean writing local versions of the missing
crates and promising to upstream them later. That is the third divergent
implementation, and preventing it is the entire reason `mecmcp` exists. So the
order is: **finish `mecmcp`, then build this.**

The phases below each name the crates they need. A phase is unblocked when its
crates are tagged.

## Phase 0 — Upstream feedback *(do this now, before mecmcp-changeset is written)*

One design issue is already known and should reach `mecmcp` before the crate it
affects gets written.

`mecmcp-changeset`'s `DeviceTransaction` trait assumes candidate configuration:
stage off to the side, diff against running, validate on-box, apply atomically.
Junos and PAN-OS both provide this. **UniFi provides none of it** — every write
is an immediate REST call against live configuration.

The trait needs to expose what a vendor can actually promise:

```rust
pub struct Atomicity {
    pub atomic_apply: bool,        // UniFi: false
    pub dry_run_validation: bool,  // UniFi: false
    pub guaranteed_rollback: bool, // UniFi: false
}
```

Shared code that renders approval prompts can then be honest per vendor rather
than uniformly optimistic. File this against `mecmcp` as the first concrete
piece of evidence that a third vendor stresses the abstraction usefully.

**Gate:** none. **Output:** a mecmcp issue.

## Phase 1 — Client and resource model

The UniFi HTTP client and the typed resource model, with no MCP surface at all.
Fixture-driven, no network in tests.

- API-key authentication, TLS verification on by default
- The four-surface tag enum (`Supported`, `PrivateV1`, `PrivateV2`, `Cloud`) and
  its scope gating
- Typed models for the resource kinds the tool surface addresses
- Recorded-fixture tests plus the controller version matrix

**Gate:** none — this is the vendor-specific layer, and it is the one part of
the project that does not depend on `mecmcp` at all. It can be built in parallel
with mecmcp development.

**Exit:** the client reads every resource kind in the design from recorded
fixtures, and the version matrix distinguishes at least two controller versions.

## Phase 2 — Read-only server

The first runnable binary: the five read primitives plus the three
administration tools, served over hardened streamable-HTTP with bearer auth,
scopes, and audit.

**Gate:** `mecmcp-auth` ✅, `mecmcp-transport`, `mecmcp-runtime`,
`mecmcp-audit`, `mecmcp-inventory`.

**Exit:** deployed alongside the Python server in the lab, answering read
queries against the live controller with a bearer token and an audit trail.
Tool count in the single digits.

## Phase 3 — Operational actions

`unifi_device_action`, `unifi_client_action`, `unifi_backup_action`,
`unifi_run_speed_test`. Individually scoped; `backup restore` gated separately
for blast radius.

**Gate:** `mecmcp-policy`.

**Exit:** an operator token can restart an AP and block a client; a read-only
token provably cannot.

## Phase 4 — Change control

The seven change-set tools, implementing `DeviceTransaction` over UniFi's
non-atomic REST semantics: pre-image capture, client-side diff, local
validation, sequential apply, verify, best-effort rollback.

**Gate:** `mecmcp-changeset`, including the Phase 0 atomicity capability.

**Exit:** a firewall-policy change is planned, approved by a second principal,
applied, and verified — and a deliberately-induced partial failure is recorded
as partial and rolled back, with the rollback's own failure mode tested.

## Phase 5 — Workflows

`unifi_site_health_report`, `unifi_topology_report`, `unifi_firewall_audit`,
`unifi_traffic_flow_report`, `unifi_client_troubleshoot`.

**Gate:** phases 1–2.

**Exit:** each workflow answers in one call what the Python server needed a
dozen for.

## Phase 6 — Cutover

Packaging (systemd unit, LXC install script) matching the sibling servers, then
parity review against the workflows actually used against LXC 603, then
replacement.

**Gate:** phases 1–5.

**Exit:** LXC 603 runs `rustunifimcp`; the Python server is stopped but its
container is kept intact for rollback, per the pattern used for the
rustjunosmcp 0.7 → 0.8 migration.

## Constraints

Inherited from `mecmcp` and non-negotiable per phase:

- Edition 2024, MSRV 1.88
- `missing_docs = "warn"`, `unsafe_code = "forbid"`, `clippy::all = "warn"`
  (priority −1), `dbg_macro = "deny"`, `todo = "deny"`, `unwrap_used = "warn"`
- MIT, single license
- mecmcp crates as git dependencies pinned by tag
- TLS verification defaults on; disabling it is an explicit, logged flag
