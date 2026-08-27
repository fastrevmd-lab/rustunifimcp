<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">rustunifimcp</h1>

<p align="center"><strong>Enterprise MCP server for UniFi Network — curated tools, scoped access, audited change control</strong><br>
<em>a mechub project — sovereign network-security automation</em></p>

---

`rustunifimcp` is the UniFi Network member of the mechub MCP server family. It
does for UniFi what [`rustjunosmcp`](https://github.com/fastrevmd-lab/rustjunosmcp)
does for Junos and [`rustpanosmcp`](https://github.com/fastrevmd-lab/rustpanosmcp)
does for PAN-OS: a curated, scoped, audited MCP surface over one vendor's
management API.

It is built **mecmcp-native** — no local authentication, transport, audit,
policy, inventory, or change-control code at all. All of that comes from
[`mecmcp`](https://github.com/fastrevmd-lab/mecmcp), the shared Rust foundation.
What is written here is the UniFi resource model, the tool surface, and the
workflows. Nothing else.

UniFi is the first vendor in the family with **no candidate configuration at
all** — no staging area, no commit, no on-box validation. Junos and PAN-OS have
candidate/commit; Proxmox and Security Director have server-side task semantics
to bind an approval to. UniFi has immediate REST writes against live
configuration and nothing else, which makes it the real test of whether
`mecmcp-changeset` generalises beyond the two vendors that produced it.

## Status

**Design approved, implementation starting.**

Implementation was deferred through July and August while `mecmcp` was
extracted. That gate is now open: `mecmcp` is at **v0.20.0 with 14 crates**, and
the wait paid — `mecmcp-http` supplies the outbound client, so the UniFi HTTP
layer never has to be written here at all.

| Document | What it is |
|---|---|
| [`PLAN.md`](PLAN.md) | The phase sequence and its two cutovers, at a glance |
| [`docs/superpowers/specs/2026-08-26-rustunifimcp-cutover-design.md`](docs/superpowers/specs/2026-08-26-rustunifimcp-cutover-design.md) | Build and cutover design: deployment topology, controller trust, phase detail, risks |
| [`docs/superpowers/specs/2026-07-24-rustunifimcp-design.md`](docs/superpowers/specs/2026-07-24-rustunifimcp-design.md) | The original design — still authoritative for tool surface, API tagging, and the change-control adaptation |

## What it replaces

The homelab runs `enuno/unifi-mcp-server` (Python / FastMCP). It is a capable
API client with two problems this project exists to fix.

**Tool sprawl.** Its registry auto-registers every public async function in
`src/tools/` by reflection — 205 functions across 37 modules become roughly
**270 MCP tools**. Nobody chose that number. `rustunifimcp` targets **~24**:
typed read primitives over a resource enum, a change-control lifecycle, scoped
operational actions, and five workflows that earn their names.

**No MCP-layer security.** It listens on plain HTTP with no bearer token, no
scopes, no audit trail, and no rate limiting. Anything that can reach the port
has unrestricted write access to the controller. `rustunifimcp` inherits the
full `mecmcp` security layer instead.

## Design highlights

**Three API surfaces, each labelled.** UniFi's supported Integration API is far
narrower than what the controller can actually do, so the private `/api/s/` and
`/v2/api/` routes stay in — but every endpoint carries its tag in code, and the
private ones are gated behind an explicit scope. A supported-only deployment is
a real, runnable configuration that a controller upgrade cannot silently break.

**Change control adapted honestly.** UniFi has no candidate configuration and no
commit. The change-set lifecycle is implemented with client-side pre-image
capture, local validation, sequential apply, and best-effort rollback — and the
tool descriptions say so. An operator approving a UniFi change set is not
getting commit-confirmed semantics, and the server does not pretend otherwise.

**Multi-controller.** Controllers live in an inventory registry rather than
environment variables, so one instance can front several and a token can be
scoped to a subset.

## License

Licensed under [MIT](LICENSE).
