# rustunifimcp — build and cutover design

Written 2026-08-26. Status: **approved.**

Supersedes the sequencing in [`PLAN.md`](../../../PLAN.md) and corrects seven
facts in
[`2026-07-24-rustunifimcp-design.md`](2026-07-24-rustunifimcp-design.md), which
remains authoritative for the tool surface, the API tagging scheme, and the
change-control adaptation.

The goal is one sentence: **stop depending on LXC 980.**

## Why this document exists

The 2026-07-24 design was written when `mecmcp` had tagged exactly one crate.
It deferred implementation on that basis and said so plainly. A month later the
premise is gone — `mecmcp` is at **v0.23.0 with 14 crates**, and every phase
gate in `PLAN.md` is open. Rather than amend a plan whose organising idea was
"wait", this document replaces the sequence and records what else moved.

## Corrections to the 2026-07-24 design

### 1. The gate is open

`PLAN.md` states that `mecmcp` "has shipped exactly one crate, `mecmcp-auth`
(tag `auth-v0.1.1`)". As of v0.23.0 the workspace ships:

```
mecmcp-audit   mecmcp-auth    mecmcp-changeset  mecmcp-device
mecmcp-http    mecmcp-inventory  mecmcp-job     mecmcp-openapi
mecmcp-policy  mecmcp-runtime mecmcp-scp        mecmcp-secret
mecmcp-server  mecmcp-transport
```

Nothing in this project is blocked on `mecmcp` any more. `PLAN.md` is rewritten
against the sequence in this document.

### 2. `mecmcp-http` changes the shape of Phase 1

The old design assumed `rustunifimcp` would write its own UniFi HTTP layer.
It will not. `mecmcp-http` supplies the outbound client, and with it:

- connect / request timeouts and a whole-request deadline
- `max_concurrent_requests` with bounded queueing and `QueueFull` backpressure
- `max_response_bytes` enforced **while the body streams**, not from
  `Content-Length`
- connection pooling
- URL validation at construction: `https://` only, host required, embedded
  credentials rejected
- `extra_root_certificates` — **additive trust only**

Phase 1 therefore reduces to the UniFi *resource model* and the four-surface tag
enum. This is a material reduction in scope, and it is the direct payoff of
having waited.

**The consequence that governs deployment** is in the crate's own words:

> Each string is a PEM-encoded certificate. There is **no** API to disable
> certificate verification.

There is no `danger_accept_invalid_certs` anywhere in `mecmcp`. The legacy
server's `UNIFI_LOCAL_VERIFY_SSL=false` has no equivalent and will not be given
one. See §"Controller trust".

### 3. Four more crates join the consumed set

| Crate | What `rustunifimcp` gets |
|---|---|
| `mecmcp-http` | The outbound UniFi client (above) |
| `mecmcp-server` | Tool registration, scope authorization, the write-tool registry |
| `mecmcp-secret` | The UniFi API key: a zeroizing type plus a loader that rejects symlinks, oversized values, and group- or world-readable files |
| `mecmcp-job` | Polling for asynchronous vendor work — first probe, capped backoff, cooperative cancellation, whole-operation deadline |
| `mecmcp-openapi` | `expand_path` — path-template expansion that rejects a parameter which would span a segment, start a query, navigate the hierarchy, collapse a segment, or carry a control byte; plus `page` for bounded pagination |

`mecmcp-secret` closes a gap the old design left open: it named the API key as
the controller credential but never said where it lives. It lives in a 0600 file
named by `controllers.json`, never in the inventory file and never in an
`EnvironmentFile` — which is where LXC 980 keeps it today.

`mecmcp-job` is a **candidate**, not a commitment. `unifi_backup_action`
(trigger, download) and `unifi_run_speed_test` are not synchronous, and the
crate is the family's answer to that shape. Whether UniFi's responses fit
`Probe::Pending` / `Probe::Ready` is a Phase 3 finding, not a design assertion.

`mecmcp-openapi::expand_path` is not optional. UniFi puts the site ID and the
resource ID directly in the path on all three local surfaces, so every request
this server builds interpolates caller-influenced values into a URL. The
template expander refuses a parameter that would span a segment, start a query,
navigate the hierarchy, collapse a segment, or carry a control byte — and it
rejects rather than sanitises, because a rewritten value is a value the caller
did not send. `rustproxmoxmcp` routes every request through it for the same
reason.

`mecmcp-device` and `mecmcp-scp` are not expected to be used.

### 4. The wildcard-scope rule is inherited, and it has a footgun

`--tools '*'` grants **read-only tools only**. Every mutating tool must be named
explicitly in a token's scope. This is enforced in `mecmcp-server`, not per
repo.

It is enforced against a **write-tool registry the server supplies as a
parameter**. `mecmcp-server`'s `an_empty_write_tool_registry_lets_a_wildcard_reach_a_write_tool` pins the failure mode
in a test named for it: passing an empty registry turns every wildcard token
into a writer.

So `rustunifimcp` must register as write tools:

- all four operational tools — `unifi_device_action`, `unifi_client_action`,
  `unifi_backup_action`, `unifi_run_speed_test`
- all seven change-set tools

and it must have a test asserting the registry is non-empty and contains exactly
those, so that a future refactor cannot quietly empty it.

### 5. `rustunifimcp` is not the first mecmcp-native server

`rustproxmoxmcp` v0.8.1 is, and it is also the precedent for this exact
migration: a third-party server on LXC 970 tagged `notmechub;protected`,
replaced by mecmcp-native `prod-proxmoxmcp` on 971, documented in
`docs/MIGRATING-FROM-PROXMOX-MCP.md`.

The interesting claim survives with its facts corrected: **UniFi is the first
vendor in the family with no candidate configuration at all.** Junos and PAN-OS
have candidate/commit; Proxmox and SDC have server-side task semantics to bind
to. UniFi has immediate REST writes against live configuration and nothing else.
That is the real test of whether `mecmcp-changeset` generalises.

### 6. The target is LXC 980

Not 603 — the fleet was renumbered on 2026-08-12.

```
980  unifi-mcp  pve2  192.168.1.203  tags: notmechub;protected
     enuno/unifi-mcp-server 0.2.5, /opt/unifi-mcp/venv
     ExecStart=/opt/unifi-mcp/venv/bin/unifi-mcp-server
     EnvironmentFile=/etc/unifi-mcp/unifi-mcp.env
     MCP_SERVER_TRANSPORT=http  MCP_SERVER_HOST=0.0.0.0  MCP_SERVER_PORT=30033
     UNIFI_LOCAL_HOST=192.168.1.30  UNIFI_LOCAL_VERIFY_SSL=false
```

980 is tagged `protected`. **Retirement means ceasing to depend on it, not
acting on the guest.** It is not ours to modify, exactly as
`MIGRATING-FROM-PROXMOX-MCP.md` says of 970.

### 7. The Cloud surface is out of v1

The old design lists a `Cloud` tag (Ubiquiti Site Manager), off by default.
LXC 980 runs `UNIFI_API_TYPE=local` and never reaches it. v1 ships the three
local surfaces only; the `Cloud` enum variant may exist unimplemented so the tag
scheme stays honest, but no cloud client is written.

## Controller trust

The controller at `192.168.1.30` presents:

```
subject = CN=unifi.local
issuer  = CN=unifi.local          (self-signed)
SAN     = DNS:unifi.local, DNS:localhost, DNS:[::1],
          IP:127.0.0.1, IP:FE80::1
notAfter = 2028-04-08
```

`unifi.mechub.org` already resolves to `192.168.1.30`, but the certificate
carries neither that name nor that address. Combined with §2 — no verification
bypass exists — **no `rustunifimcp` call to this controller can succeed until
the certificate is replaced.** This blocks even the first fixture-recording
session.

**Decision: replace the certificate on the controller.** Issue
`unifi.mechub.org` through the Let's Encrypt automation already running on pve2,
install it on the controller, and add a renewal deploy hook beside the five that
exist:

```
/etc/letsencrypt/live/          prod-{junos,panos,sdc,mist,proxmox}mcp.mechub.org
/etc/letsencrypt/renewal-hooks/deploy/  prod-*mcp-lxc9*, vaultwarden-lxc930
                                        + unifi-controller          (new)
```

Two alternatives were considered and rejected. Trusting the self-signed leaf via
`extra_root_certificates` and dialling `https://unifi.local` works today with no
controller change, but `.local` is mDNS territory on a LAN that runs an avahi
reflector (LXC 906), and a 2028 expiry outlives anyone's memory of the
workaround. Adding a pinned-fingerprint trust anchor to `mecmcp-http` is the
right primitive for appliances generally and is worth filing upstream on its own
merits, but it would block Phase 1 on a `mecmcp` release for a problem the
controller can fix itself.

**The certificate replacement is non-destructive and reversible** — the existing
self-signed cert is retained — but it touches gear serving the house LAN and
belongs in a window.

## Deployment topology

| VMID | Name | Node | IP | Endpoint | Tags | Mode |
|---|---|---|---|---|---|---|
| 622 | `test-twoperson-unifi` | pve2 | 192.168.1.242 | `http://test-twoperson-unifi.mechub.org:30033/mcp` | `disposable;test;twoperson` | two-person |
| 623 | `test-labmode-unifi` | pve2 | 192.168.1.243 | `http://test-labmode-unifi.mechub.org:30033/mcp` | `disposable;labmode;test` | `--lab-mode` |
| 981 | `prod-unifimcp` | pve2 | 192.168.1.216 | `https://prod-unifimcp.mechub.org:30033/mcp` | see below | two-person, TLS |

Conventions this follows, all read off the running fleet rather than invented:

- **Matched pair per server.** 610–619 hold five such pairs; even VMID is
  two-person, odd is lab mode. 621 is skipped to preserve that parity — 620
  `srx345-jump` is unrelated and sits on `192.168.101.50`.
- **Test-rig IP = VMID − 380.** 610→.230 … 619→.239, so 622→.242, 623→.243.
  Both verified free.
- **Production IPs are allocated ad hoc**; `.216` follows 971's `.215` and is
  verified free.
- **Port 30033** is retained. It is the UniFi port, and 981 does not share 980's
  address, so 980 and 981 run concurrently without collision.
- Test rigs: Debian 13, 1 core, 512 MB, 4 G rootfs, `features: nesting=1`
  (systemd 257 degrades without it), `onboot: 0`.

Three DNS A records are new: `test-twoperson-unifi`, `test-labmode-unifi`,
`prod-unifimcp`, all under `mechub.org`.

### The `protected` tag is applied last

981 is tagged `protected` **only after Cutover #2**. Tagging it at creation
would make the guardrail block our own rebuilds during the phases that need
them. Until then it carries no protective tag and is treated as rebuildable.

### Snapshots

622 and 623 are `disposable` and need no snapshot discipline. 981 takes a
snapshot before every release install, per the 950/960 pattern — the fleet has
already learned that backups do not carry snapshots, so a snapshot chain is the
only complete revert.

## Build sequence

`PLAN.md` is rewritten to this. Two cutovers, not one.

### Phase 0a — Upstream: the `Atomicity` capability

Unchanged from the old `PLAN.md` Phase 0 and still not filed. File it against
`mecmcp` before `mecmcp-changeset` is consumed here:

```rust
pub struct Atomicity {
    pub atomic_apply: bool,        // UniFi: false
    pub dry_run_validation: bool,  // UniFi: false
    pub guaranteed_rollback: bool, // UniFi: false
}
```

Shared code that renders approval prompts can then be honest per vendor instead
of uniformly optimistic.

**Blocks on:** nothing. **Output:** a `mecmcp` issue — filed 2026-08-26 as
[mecmcp#335](https://github.com/fastrevmd-lab/mecmcp/issues/335).

### Phase 0b — Controller certificate

Per §"Controller trust". Issue, install, hook, verify with
`openssl s_client` against `unifi.mechub.org:443` showing a valid chain and a
matching name.

**Blocks on:** nothing. **Blocks:** every phase that touches the live
controller, starting with 0c.

### Phase 0c — Fixtures and the parity audit

Two artefacts, both inputs to everything after.

**Recorded fixtures** — controller JSON for every resource kind the tool surface
addresses, captured per controller version, so Phase 1 has no network in its
tests.

**The parity audit** — the list of legacy tools actually invoked against 980,
recovered from session history. This *is* the cutover bar chosen for this
project: the ~24-tool surface is held, and every legacy tool in the audit must
be shown reachable through a read primitive's `kind` enum, a workflow, or a
change set. Anything unreachable becomes a **named, signed-off gap**, never a
silent loss. It ships as a checked-in table, not prose.

**Blocks on:** 0b.

### Phase 1 — Client and resource model

No MCP surface. The four-surface tag enum (`Supported`, `PrivateV1`,
`PrivateV2`, `Cloud`) with its scope gating, typed models per resource kind, and
the controller version matrix. Thinner than the old design assumed, per §2.

**Exit:** every resource kind reads from recorded fixtures; the version matrix
distinguishes at least two controller versions.

### Phase 2 — Read-only server

Five read primitives plus three administration tools over hardened
streamable-HTTP with bearer auth, scopes, and audit. Deployed to **623 first**
(lab mode is the simpler configuration), then **622**.

**Exit:** both rigs answer read queries against the live controller with a
bearer token and an audit trail; a `tools/list` on each returns the filtered
surface the token actually permits.

### Phase 3 — Operational actions

`unifi_device_action`, `unifi_client_action`, `unifi_backup_action`,
`unifi_run_speed_test`. All four registered as **write** tools per §4.

This is also where the `mecmcp-job` question is answered against real controller
behaviour.

**Exit:** an operator token can restart an AP and block a client; a wildcard
token provably cannot do either.

### Phase 4 — Workflows

`unifi_site_health_report`, `unifi_topology_report`, `unifi_firewall_audit`,
`unifi_traffic_flow_report`, `unifi_client_troubleshoot`.

**Exit:** each answers in one call what the legacy server needed a dozen for,
and each is exercised on both rigs.

### Phase 5 — Cutover #1 → 981

Create 981, install, TLS, tokens, DNS. Read, ops, workflows, and admin go live.
**980 keeps serving configuration writes only** — its dependency surface is
narrowed, not removed.

Ship `docs/MIGRATING-FROM-UNIFI-MCP.md` in the shape of the proxmox one: tool
mapping (same name/same meaning · reached through the change-set flow instead ·
no equivalent by decision · here but not there), plus what surprises a 980
caller.

Rename the legacy client registration to `unifi-mcp-legacy` so that during
phases 5–7 it is unambiguous which server a call is reaching.

**Exit:** 981 serves the audit's read, ops, and workflow entries under bearer
auth over TLS; every gap is named.

### Phase 6 — Change control

The seven change-set tools over UniFi's non-atomic REST semantics: pre-image
capture, client-side diff, local validation, sequential apply, verify,
best-effort rollback. `unifi_backup_action`'s `restore` moves here (see below).

The word "atomic" must not appear in any change-set tool description.

**Exit:** a firewall-policy change is planned, approved by a second principal on
622, applied, and verified — and a deliberately induced partial failure is
recorded as partial and rolled back, with the rollback's own failure mode
tested.

### Phase 7 — Cutover #2

Change control goes live on 981. The dependency on 980 is dropped and the
`unifi-mcp-legacy` registration removed. 981 is tagged `protected`.

**980 is left running and untouched.** It is `protected` and not ours to modify.

## `backup_action: restore` moves into change control

The 2026-07-24 design groups `restore` with the operational actions that "bypass
change control", gated behind its own scope for blast radius.

That is the wrong side of the line. A controller restore overwrites the entire
configuration — it is the single largest blast radius in the surface, larger
than any change set the seven tools will ever carry. Scoping it separately
controls *who* may call it but not *whether anyone reviewed it*, and on 981 the
whole point of two-person control is the second reviewer.

`restore` therefore becomes a change-set operation in Phase 6, inheriting
approval, digest binding, and pre-image capture. `trigger`, `list`, `download`,
and `validate` stay as operational actions.

The cost is that restore is unavailable on 981 between Cutover #1 and Cutover
#2. That is acceptable: it is a recovery operation performed rarely and
deliberately, 980 still serves it throughout, and a restore run through the
legacy server during that window is a conscious act rather than a convenience.

## Testing

The four kinds from the old design stand:

- **Fixture tests** — recorded controller JSON per version, no network.
- **Version matrix** — which endpoints exist on which controller version; this
  is where private-API drift is caught and the reason the tags are carried.
- **Lifecycle tests** — the change-set state machine including partial-apply and
  rollback-failure paths against a mock controller. These matter more here than
  in the sibling servers precisely because apply is not atomic.
- **Lab tests** — feature-gated, against the live controller. Not run in CI.

Two the fleet has learned since and this project adopts:

- **Packaging smoke test on 622/623 before every 981 touch.** No release reaches
  production without being installed on a rig first.
- **The parity audit as a checked-in artefact**, re-run before each cutover.

And one this design adds:

- **A write-tool registry assertion** — a test that the registry passed to
  `mecmcp-server` is non-empty and contains exactly the mutating tools that
  exist at that phase: four after Phase 3, eleven after Phase 6. The assertion
  is written against an explicit list, not a count, so the `an_empty_write_tool_registry_lets_a_wildcard_reach_a_write_tool`
  footgun cannot be reintroduced by refactor.

## Risks

**Private-API drift is the top technical risk.** Most of the reads worth having
— traffic flows, DPI, firewall zones v2 — are `PrivateV2`, on undocumented
routes a controller upgrade may change without notice. The tag enum and version
matrix exist for exactly this, and they turn a generic tool failure into
"private API `/v2/api/site/{}/traffic-flows` no longer present on controller
version X". The risk is not eliminated; it is made diagnosable.

**The certificate replacement touches live gear.** Non-destructive, reversible,
old cert retained — but it serves the house LAN and belongs in a window.

**Two servers are registered concurrently through phases 5–7.** Mitigated by
renaming the legacy registration to `unifi-mcp-legacy` at Cutover #1.

**Review throughput.** Seven phases at reviewable commit size is roughly 15–20
PRs, each needing `codex exec review --commit <sha>`. Quota exhaustion presents
as a transient error; a run producing no verdict is reported as not run, never
as a pass.

## Non-goals

- Preserving the legacy tool names. This server has one known consumer and
  changing the surface is the point.
- UniFi Protect, Access, or Talk. Network only.
- Reimplementing anything `mecmcp` owns. Where a `mecmcp` crate cannot be used
  cleanly, that is an upstream issue, not a local workaround.
- Acting on LXC 980 in any way.

## Constraints

Inherited from `mecmcp`, non-negotiable per phase:

- Edition 2024, MSRV 1.88
- `missing_docs = "warn"`, `unsafe_code = "forbid"`, `clippy::all = "warn"`
  (priority −1), `dbg_macro = "deny"`, `todo = "deny"`, `unwrap_used = "warn"`
- `[profile.release]` present from the first release
- MIT, single license
- `mecmcp` crates as git dependencies pinned to an exact tag; the pin is not
  relaxed, and bumping it is a coordinated fleet change
- TLS verification is always on — there is no flag to disable it
