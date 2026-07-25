# rustunifimcp — design

Written 2026-07-24. Status: **approved, implementation deferred.**

`rustunifimcp` is the UniFi Network member of the mechub MCP server family. It
does for UniFi what [`rustjunosmcp`](https://github.com/fastrevmd-lab/rustjunosmcp)
does for Junos and [`rustpanosmcp`](https://github.com/fastrevmd-lab/rustpanosmcp)
does for PAN-OS: a curated, scoped, audited MCP surface over one vendor's
management API.

Implementation is deliberately deferred until
[`mecmcp`](https://github.com/fastrevmd-lab/mecmcp) is fully developed. This
document records the decisions so that work can start cold. See
[`PLAN.md`](../../../PLAN.md) for the phase sequence and its mecmcp gates.

## Why replace the current server

The homelab runs `enuno/unifi-mcp-server` 0.2.5 (Python / FastMCP) on LXC 603.
It is a capable API client, and the capability is worth keeping. Two things are
not.

**The tool surface is undesigned.** `tool_registry.py` registers *every public
async function* in `src/tools/` by reflection. 205 such functions across 37
modules become roughly 270 MCP tools. Nobody chose that number; it is a
byproduct of the module layout. The cost lands on every model that loads the
server — a tool list that large crowds context and makes selection unreliable.

**There is no MCP-layer security.** The server listens on plain HTTP with no
bearer token, no scopes, no audit trail, and no rate limiting. Any host that can
reach the port gets unrestricted write access to the UniFi controller. Both
sibling servers solved this years of engineering ago; none of it is reused here.

Rewriting in Rust is not the point. Reusing `mecmcp` is the point — the rewrite
is what makes the reuse possible.

## Position in the family

`rustunifimcp` is the first server built **mecmcp-native**: it has no local
auth, transport, audit, policy, inventory, or change-control code at all. Where
a `mecmcp` crate cannot be used cleanly, that is a `mecmcp` design bug to file
upstream, not a local workaround to write. Junos and PAN-OS were the two data
points that produced the abstraction; UniFi is the first test of whether the
abstraction holds for a vendor that was not in the room when it was designed.

This is why the project is worth building even though the Python server works.

## Architecture

```
rustunifimcp/            binary — CLI, TLS bootstrap, serve; thin
rustunifimcp-core/       UniFi client, resource model, tool surface, workflows
```

Two crates, not three. Auth does not get its own crate here — that is
`mecmcp-auth`.

### Consumed from mecmcp

| Crate | What rustunifimcp gets |
|---|---|
| `mecmcp-auth` | Token mint/digest/verify, `tokens.json` hot-reload, `ScopeSet`, `CallerCtx` |
| `mecmcp-transport` | Streamable-HTTP, host/Origin checks, bearer middleware, scope preflight, body limits, rate limits, concurrency + session caps, `/metrics`, `/healthz` |
| `mecmcp-runtime` | CLI skeleton (`serve`, `token add\|revoke\|rotate\|list`, `validate-config`), TLS, signals, graceful shutdown |
| `mecmcp-audit` | `Attribution`, audit events, redaction, sinks |
| `mecmcp-inventory` | Controller registry, hot-reload, atomic write |
| `mecmcp-policy` | Allow/deny rules over tool and resource subjects |
| `mecmcp-changeset` | Plan → digest → approve → apply → verify, two-principal enforcement |

Pinned by git tag, per the mecmcp convention.

### Written here

The UniFi client, the resource model, the tool surface, and the workflows.
Nothing else.

## The API layer

The current server reaches four distinct UniFi surfaces. `rustunifimcp` keeps
all of them — the reach is the capability — but **tags every endpoint in code**
so a deployment can choose its own risk posture.

| Tag | Base path | Availability |
|---|---|---|
| `Supported` | `/proxy/network/integration/v1` | Always |
| `PrivateV1` | `/proxy/network/api/s/<site>` | Requires the `unifi:private-api` scope |
| `PrivateV2` | `/proxy/network/v2/api/site/<site>` | Requires the `unifi:private-api` scope |
| `Cloud` | Site Manager (Ubiquiti cloud) | Off by default; explicit opt-in |

The tag is a property of the endpoint, carried through to the tool. Two
consequences follow, and both are the point:

- A supported-only deployment is a real, runnable configuration. It exposes a
  smaller tool surface and cannot be broken by a controller upgrade changing an
  undocumented route.
- When a private endpoint does break, the failure is attributable. A tagged
  endpoint that starts returning 404 produces a diagnosable "private API
  `/v2/api/site/{}/traffic-flows` no longer present on controller version X"
  rather than a generic tool failure.

Controller authentication is by UniFi Network API key (`X-API-KEY`), the same
mechanism the current server uses, which UniFi OS honours on all three local
surfaces. TLS verification defaults to **on**; disabling it is an explicit flag
that is logged at startup, not a quiet config default.

### Multi-controller

Inventory is a `controllers.json` registry over `mecmcp-inventory`, directly
analogous to `devices.json` in the sibling servers. One server instance can
front several controllers; every tool takes a controller reference, and
`mecmcp-policy` can scope a token to a subset. The current server handles
exactly one controller from environment variables.

## Tool surface

Roughly 24 tools, against roughly 270 today. The shape follows the family: typed
primitives, a change-control lifecycle, and a small number of workflows that
earn their names by doing something a model cannot assemble from primitives
cheaply.

### Read (5)

| Tool | Notes |
|---|---|
| `unifi_list_resources` | `kind` = `firewall_policy \| firewall_zone \| firewall_group \| network \| wlan \| port_profile \| dhcp_reservation \| traffic_route \| radius_profile \| client \| device \| voucher \| …` |
| `unifi_get_resource` | `kind`, `id` |
| `unifi_query_stats` | `subject` = `site \| device \| client \| wlan \| flow`, plus a time window |
| `unifi_search` | Free-text across clients, devices, and sites |
| `unifi_list_sites` | |

The `kind` enum is where the collapsed surface goes. Roughly 130 of the current
server's tools are `list_x` / `get_x` pairs that differ only in the resource
they address; they become enum variants with a shared, documented envelope.

### Change control (7)

`unifi_create_change_set`, `unifi_stage_change`, `unifi_diff_change_set`,
`unifi_validate_change_set`, `unifi_approve_change_set`,
`unifi_apply_change_set`, `unifi_get_change_set`.

Every write to controller configuration goes through this. There is no
`unifi_create_firewall_policy` tool; there is a change set containing a staged
firewall-policy creation.

### Device and client operations (4)

`unifi_device_action` (`restart \| locate \| adopt \| upgrade \| port-action`),
`unifi_client_action` (`block \| unblock \| reconnect \| authorize \| limit-bandwidth`),
`unifi_backup_action` (`trigger \| list \| download \| validate \| restore`),
`unifi_run_speed_test`.

These are operational commands, not configuration, so they bypass change
control — but each is individually scoped and audited. `restore` is the
exception in blast radius and is gated behind its own scope.

### Workflows (5)

`unifi_site_health_report`, `unifi_topology_report`, `unifi_firewall_audit`,
`unifi_traffic_flow_report`, `unifi_client_troubleshoot`.

Each aggregates many API calls into one answer. `unifi_client_troubleshoot`, for
example, correlates a client's association history, signal, DHCP lease, applied
firewall policy, and recent flows — a dozen round trips and a join that a model
should not be orchestrating one tool call at a time.

### Administration (3)

`unifi_list_controllers`, `unifi_add_controller`, `unifimcp_status`.

## The change-control adaptation

This is the one part of the family design that does not port, and it must be
stated plainly rather than papered over.

**UniFi has no candidate configuration and no commit.** `mecmcp-changeset`'s
`DeviceTransaction` trait was derived from Junos NETCONF candidate/commit and
PAN-OS candidate/commit. Both vendors can stage an arbitrary set of changes
off to the side, diff it against running, validate it on-box, and then apply it
atomically. UniFi's REST API can do none of that. Every write is an immediate,
independent `POST`/`PUT`/`DELETE` against live configuration.

The adaptation:

| Stage | UniFi implementation |
|---|---|
| `stage` | Capture a **pre-image** — `GET` every resource the change set touches — and store it alongside the intended mutations |
| `diff` | Computed **client-side**: pre-image versus desired state |
| `validate` | Schema and referential checks **locally**; no controller-side dry run exists |
| `apply` | Sequential REST calls. **Not atomic.** Partial failure is a reachable state and is recorded as such |
| `verify` | Re-`GET` the touched resources and compare against desired |
| `rollback` | Re-`PUT` the stored pre-image. **Best-effort**, not guaranteed |

Two requirements follow.

**The tool descriptions must say this.** An operator approving a UniFi change
set is not getting Junos commit-confirmed semantics, and the model relaying the
approval request must be able to tell them so. The word "atomic" must not
appear in any `rustunifimcp` change-set description.

**`mecmcp-changeset` needs an atomicity capability.** The trait should expose
what a vendor can actually promise — atomic apply, dry-run validation,
guaranteed rollback — rather than assuming candidate config. UniFi declares none
of the three. Shared code that renders approval prompts can then be honest per
vendor instead of uniformly optimistic. This is the first concrete piece of
upstream feedback the project produces, and it should be filed against mecmcp
before `mecmcp-changeset` is written, not after.

## Testing

Following the sibling servers:

- **Fixture tests** — recorded controller JSON responses per UniFi Network
  version, exercising the client and resource model with no network.
- **Version matrix** — the analogue of `rustpanosmcp`'s
  `panos_version_matrix.rs`, asserting which endpoints exist on which controller
  version. This is where private-API drift gets caught, and it is the reason the
  tags are worth carrying.
- **Lifecycle tests** — change-set state machine, including partial-apply and
  rollback-failure paths, against a mock controller. These matter more here than
  in the sibling servers precisely because apply is not atomic.
- **Lab tests** — feature-gated, against the live controller at the homelab
  address. Not run in CI.

## Non-goals

- **Replacing the Python server before parity is proven.** Both run in
  parallel; LXC 603 keeps serving until `rustunifimcp` covers the workflows
  actually in use.
- **Reimplementing anything mecmcp owns.** If it is not UniFi-specific, it does
  not get written here.
- **UniFi Protect, Access, or Talk.** Network only.
- **Preserving the current tool names.** Unlike the sibling servers, whose tool
  surfaces are a public API under a compatibility promise, this server has one
  known consumer and the whole point is to change the surface.

## Constraints inherited from mecmcp

- Edition 2024, MSRV 1.88.
- Workspace lints: `missing_docs = "warn"`, `unsafe_code = "forbid"`,
  `clippy::all = "warn"` (priority −1), `dbg_macro = "deny"`, `todo = "deny"`,
  `unwrap_used = "warn"`.
- MIT, single license.
- mecmcp crates consumed as git dependencies pinned by tag.
- Product name lowercase with no dashes, per the mechub brand standard.
