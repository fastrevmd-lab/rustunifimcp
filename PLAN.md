# rustunifimcp plan

Phase sequence for building the UniFi Network MCP server and retiring the
dependency on LXC 980.

Design of record:
[`docs/superpowers/specs/2026-08-26-rustunifimcp-cutover-design.md`](docs/superpowers/specs/2026-08-26-rustunifimcp-cutover-design.md),
which supersedes the sequencing written 2026-07-24 and corrects seven facts in
[`2026-07-24-rustunifimcp-design.md`](docs/superpowers/specs/2026-07-24-rustunifimcp-design.md).
The 2026-07-24 document remains authoritative for the tool surface, the API
tagging scheme, and the change-control adaptation.

Rewritten 2026-08-26.

## The gate is open

The previous version of this file deferred all implementation on the grounds
that `mecmcp` had tagged exactly one crate. That is no longer true. `mecmcp` is
at **v0.20.0 with 14 crates**, and every phase gate this file used to carry has
opened.

Waiting was the right call and it paid: `mecmcp-http` now supplies the outbound
client, so the UniFi HTTP layer never has to be written here at all.

## Sequence

Two cutovers. 981 goes live without change control; 980 keeps serving
configuration writes until Phase 7 removes the last dependency on it.

| Phase | What | Blocks on |
|---|---|---|
| **0a** | Upstream: `Atomicity` capability against `mecmcp-changeset` — filed as [mecmcp#335](https://github.com/fastrevmd-lab/mecmcp/issues/335) ✅ | — |
| **0b** | Controller certificate — issue `unifi.mechub.org`, install, renewal hook | — |
| **0c** | Recorded fixtures + the legacy parity audit | 0b |
| **1** | UniFi client and resource model; no MCP surface | 0c |
| **2** | Read-only server (5 read + 3 admin) → deploy 623, then 622 | 1 |
| **3** | Operational actions (4), individually scoped | 2 |
| **4** | Workflows (5) | 2 |
| **5** | **Cutover #1 → 981.** Read, ops, workflows, admin live | 3, 4 |
| **6** | Change control (7 tools), including `backup restore` | 0a, 5 |
| **7** | **Cutover #2.** 980 dependency dropped; 981 tagged `protected` | 6 |

Phase detail, exit criteria, and the reasoning behind each are in the design
document. What follows is only what an operator needs at a glance.

## Guests

| VMID | Name | IP | Endpoint | Mode |
|---|---|---|---|---|
| 622 | `test-twoperson-unifi` | 192.168.1.242 | `http://test-twoperson-unifi.mechub.org:30033/mcp` | two-person |
| 623 | `test-labmode-unifi` | 192.168.1.243 | `http://test-labmode-unifi.mechub.org:30033/mcp` | `--lab-mode` |
| 981 | `prod-unifimcp` | 192.168.1.216 | `https://prod-unifimcp.mechub.org:30033/mcp` | two-person, TLS |

Both rigs are `disposable`-tagged. **981 is tagged `protected` only at Phase 7**
— doing it earlier would make the guardrail block the rebuilds the earlier
phases need.

**LXC 980 is never modified.** It is tagged `notmechub;protected`; retirement
means ceasing to depend on it, exactly as `rustproxmoxmcp` treats LXC 970.

## Two things that will bite if forgotten

**There is no way to disable TLS verification.** `mecmcp-http` says so in its
own documentation, and no `danger_accept_invalid_certs` exists anywhere in
`mecmcp`. The controller's self-signed `CN=unifi.local` certificate does not
cover `192.168.1.30`, so **Phase 0b blocks every call to the live controller**,
including the first fixture capture.

**A wildcard token is read-only — but only if the write-tool registry is
populated.** `mecmcp-server` enforces the rule against a registry the server
supplies as a parameter, and `crates/mecmcp-server/src/authorize.rs:237` pins
the failure mode: an empty registry turns every wildcard token into a writer.
All four operational tools and all seven change-set tools must be registered,
and a test must assert the list.

## Constraints

Inherited from `mecmcp` and non-negotiable per phase:

- Edition 2024, MSRV 1.88
- `missing_docs = "warn"`, `unsafe_code = "forbid"`, `clippy::all = "warn"`
  (priority −1), `dbg_macro = "deny"`, `todo = "deny"`, `unwrap_used = "warn"`
- `[profile.release]` present from the first release
- MIT, single license
- `mecmcp` crates as git dependencies pinned to an exact tag
- TLS verification is always on; there is no flag to turn it off
