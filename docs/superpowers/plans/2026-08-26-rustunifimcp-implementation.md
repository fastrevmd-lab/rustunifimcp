# rustunifimcp Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the UniFi Network MCP server and retire the homelab's dependency on LXC 980, replacing ~270 unauthenticated tools with ~24 curated, scoped, audited ones.

**Architecture:** Two crates. `rustunifimcp-core` holds everything vendor-specific — the UniFi resource model, the four-surface tag enum, the tool surface, the workflows, and the change-set adaptation. `rustunifimcp` is a thin binary: CLI, TLS bootstrap, serve. Authentication, transport hardening, the outbound HTTP client, audit, policy, inventory, secrets, and change-set machinery all come from `mecmcp` v0.20.0 and are deliberately absent from this repo.

**Tech Stack:** Rust edition 2024 (MSRV 1.88), `mecmcp` v0.20.0 (git, tag-pinned), `rmcp` 3, `axum` 0.8, `tokio` 1, `serde`/`serde_json`, `schemars` 1, `rustls` 0.23.

**Spec:** [`docs/superpowers/specs/2026-08-26-rustunifimcp-cutover-design.md`](../specs/2026-08-26-rustunifimcp-cutover-design.md), which supersedes the sequencing in the [2026-07-24 design](../specs/2026-07-24-rustunifimcp-design.md). That earlier document remains authoritative for the tool surface, the API tagging scheme, and the change-control adaptation; read both.

## Global Constraints

Every task's requirements implicitly include this section.

- **Edition 2024, MSRV 1.88.** `rust-version = "1.88"` in `[workspace.package]`.
- **Workspace lints, already present in `Cargo.toml`:** `missing_docs = "warn"`, `unsafe_code = "forbid"`, `clippy::all = "warn"` (priority −1), `dbg_macro = "deny"`, `todo = "deny"`, `unwrap_used = "warn"`. Do not add `#[allow]` to silence these; fix the code.
- **`mecmcp` is pinned to an exact tag: `v0.20.0`.** Never relax the tag to a branch or a version range. Bumping it is a coordinated seven-repo change.
- **TLS verification is always on.** `mecmcp-http` exposes no way to disable certificate verification and no `danger_accept_invalid_certs` exists anywhere in `mecmcp`. Private CAs are reached through `extra_root_certificates` (additive trust) only. Do not add an insecure flag; if you believe you need one, the deployment is wrong.
- **Secrets never live in the inventory file.** The UniFi API key is named by `controllers.json` and loaded through `mecmcp-secret` from a 0600 file or an environment variable. Modes are enforced at startup — wrong mode is a startup failure, deliberately.
- **The word "atomic" must not appear in any change-set tool description.** UniFi cannot promise it.
- **`[profile.release]`** must carry `lto = "thin"`, `codegen-units = 1`, `strip = "symbols"` before the first release.
- **MIT, single license.** Product name lowercase, no dashes.
- **Commits stay reviewable.** Each task is one commit or a small handful. A ~700-line commit has repeatedly timed out the codex review gate.
- **LXC 980 is never modified.** It is tagged `notmechub;protected`. Retirement means ceasing to depend on it.

## File Structure

```
rustunifimcp-core/src/
  lib.rs              crate root; re-exports; ApiSurface (exists today)
  error.rs            UnifiError — one error enum for the whole core crate
  inventory.rs        controllers.json: Controller, ControllerPolicy, loader
  client.rs           UnifiClient over mecmcp-http; one client per controller
  version.rs          controller version matrix; endpoint availability
  model/
    mod.rs            ResourceKind enum + the shared Resource envelope
    site.rs           Site
    device.rs         Device (APs, switches, gateways)
    station.rs        Station (wireless/wired clients; "client" is taken)
    network.rs        Network, Wlan, PortProfile, DhcpReservation
    firewall.rs       FirewallPolicy, FirewallZone, FirewallGroup
    routing.rs        TrafficRoute, RadiusProfile
    stats.rs          StatsSubject and the query envelope
  tools/
    mod.rs            registration + the WRITE_TOOLS registry
    read.rs           5 read primitives
    admin.rs          3 administration tools
    ops.rs            4 operational tools
    workflow.rs       5 workflows
    changeset.rs      7 change-set tools
  changeset/
    mod.rs            UnifiTransaction; the Atomicity declaration
    preimage.rs       GET-every-touched-resource capture
    diff.rs           client-side pre-image vs desired
    validate.rs       schema and referential checks, local only
    apply.rs          sequential REST apply; partial failure is a real state
    rollback.rs       best-effort pre-image restore
  testing.rs          fixture loading helpers

rustunifimcp/src/
  main.rs             thin entrypoint
  lib.rs              wiring
  cli.rs              clap definitions
  http_transport.rs   streamable-HTTP bring-up
  server/mod.rs       rmcp ServerHandler; tool dispatch

rustunifimcp-core/tests/
  fixtures/<version>/*.json     recorded controller responses
  version_matrix.rs             which endpoints exist on which version
  changeset_lifecycle.rs        state machine incl. partial apply + rollback failure
  write_tool_registry.rs        the authorize.rs:237 footgun guard
  lab.rs                        feature-gated; live controller; not run in CI

packaging/
  systemd/rustunifimcp.service
  systemd/rustunifimcp.sysusers
  systemd/rustunifimcp.tmpfiles
  lxc/install.sh
  examples/controllers.example.json

docs/
  MIGRATING-FROM-UNIFI-MCP.md
  PARITY-AUDIT.md
```

**Why `station.rs` and not `client.rs` for wireless clients:** `client.rs` is the HTTP client. UniFi calls an associated device a "client", which would collide in every import in the crate. `Station` is the 802.11 term and reads unambiguously next to `Device`.

---

## Phase 0a — Upstream: the Atomicity capability

### Task 1: File the `Atomicity` issue against mecmcp

`mecmcp-changeset`'s `DeviceTransaction` trait was derived from Junos NETCONF and PAN-OS candidate/commit. Both can stage changes off to the side, diff against running, validate on-box, and apply atomically. UniFi can do none of it. The trait needs to expose what a vendor can actually promise, so shared approval-prompt rendering can be honest per vendor instead of uniformly optimistic.

This is filed **before** `mecmcp-changeset` is consumed here, so the capability lands before Phase 6 depends on it.

**Files:**
- Create: none in this repo — the deliverable is an upstream issue.

**Interfaces:**
- Consumes: nothing.
- Produces: a `mecmcp` issue number, referenced by Task 25.

- [ ] **Step 1: Read the current trait to quote it accurately**

```bash
cd ~/Projects/mecmcp
grep -n -A40 "pub trait DeviceTransaction" crates/mecmcp-changeset/src/*.rs
```

Note the exact method names and their doc comments. The issue must argue against what the trait actually says, not a paraphrase.

- [ ] **Step 2: File the issue**

```bash
cd ~/Projects/mecmcp
gh issue create \
  --title "changeset: DeviceTransaction should declare vendor atomicity rather than assume candidate config" \
  --body "$(cat <<'BODY'
`DeviceTransaction` was derived from two vendors that both have candidate
configuration: Junos NETCONF and PAN-OS candidate/commit. Each can stage an
arbitrary set of changes off to the side, diff it against running, validate it
on-box, and apply it atomically.

UniFi has none of the four. Every write is an immediate, independent
POST/PUT/DELETE against live configuration. There is no candidate, no commit,
no server-side dry run, and no transactional rollback.

`rustunifimcp` implements the lifecycle as pre-image capture, client-side diff,
local validation, sequential non-atomic apply, re-GET verify, and best-effort
rollback. All of that is honest and implementable. What is not implementable is
the trait's implicit promise, which shared code currently renders uniformly.

Proposal — let a vendor declare what it can promise:

```rust
pub struct Atomicity {
    /// All staged mutations land, or none do.
    pub atomic_apply: bool,        // junos/panos: true   unifi: false
    /// The device can validate the change before it is applied.
    pub dry_run_validation: bool,  // junos/panos: true   unifi: false
    /// A failed apply can be reverted to the pre-change state reliably.
    pub guaranteed_rollback: bool, // junos/panos: true   unifi: false
}

pub trait DeviceTransaction {
    fn atomicity(&self) -> Atomicity;
    // ... existing methods
}
```

The value is in the approval prompt. An operator approving a UniFi change set
is not getting commit-confirmed semantics, and the model relaying the approval
request must be able to tell them so. Today the shared renderer cannot
distinguish the cases.

UniFi is the first vendor in the family with no candidate configuration at all,
which is why this surfaces now rather than during the Junos/PAN-OS extraction.

Filed from rustunifimcp before its Phase 6 consumes `mecmcp-changeset`, per
that repo's design doc.
BODY
)"
```

- [ ] **Step 3: Record the issue number**

```bash
cd ~/Projects/rustunifimcp
# Replace NNN with the issue number gh printed.
sed -i 's|file it against `mecmcp` as the first concrete|file it against `mecmcp` (filed as mecmcp#NNN) as the first concrete|' \
  docs/superpowers/specs/2026-07-24-rustunifimcp-design.md || true
git add -A docs
git commit -m "docs: record the upstream Atomicity issue number"
```

**Verification:** `gh issue view 335 --repo fastrevmd-lab/mecmcp` shows the issue open. This task has no test — its deliverable is upstream.

**Done 2026-08-26 — [mecmcp#335](https://github.com/fastrevmd-lab/mecmcp/issues/335).** The filed issue argues from three quoted trait contracts rather than the one the plan anticipated: `fingerprint()` is defined over "the device's candidate configuration"; `stage()` requires that a partial failure "must revert the first action"; and `rollback(to: RollbackRef)` enumerates only Junos archives and PAN-OS candidate revert. UniFi satisfies none of the three. The proposal uses a **defaulted** `atomicity()` method so Junos and PAN-OS are unchanged and the change is non-breaking.

---

## Phase 0b — Controller certificate

Blocks every subsequent phase. `mecmcp-http` has no verification bypass, and the controller's self-signed `CN=unifi.local` certificate covers neither `192.168.1.30` nor `unifi.mechub.org`. Until this is done, no `rustunifimcp` call to the controller can succeed — including the first fixture capture in Phase 0c.

### Task 2: Issue and install a real certificate on the UniFi controller

**Files:**
- Create: `/etc/letsencrypt/renewal-hooks/deploy/unifi-controller` on pve2
- Create: `docs/runbooks/controller-certificate.md` in this repo

**Interfaces:**
- Consumes: nothing.
- Produces: `https://unifi.mechub.org` verifying against the public trust store — relied on by every task from Task 3 onward.

- [ ] **Step 1: Record the current state, so the revert is known**

```bash
echo | openssl s_client -connect 192.168.1.30:443 -servername unifi.mechub.org 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

Expected today:

```
subject=CN=unifi.local
issuer=CN=unifi.local
notAfter=Apr  8 05:13:03 2028 GMT
X509v3 Subject Alternative Name:
    DNS:unifi.local, DNS:localhost, DNS:[::1], IP Address:127.0.0.1, IP Address:FE80:...:1
```

Save that output into the runbook. It is the proof of what was replaced.

- [ ] **Step 2: Back up the controller's existing keystore before touching it**

Take a UniFi controller backup through its own UI or API first, and copy the current certificate material aside. Do not proceed without this — the revert path depends on it.

- [ ] **Step 3: Issue the certificate on pve2**

```bash
ssh root@pve2.mechub.org
certbot certonly --dns-<provider> -d unifi.mechub.org
ls -la /etc/letsencrypt/live/unifi.mechub.org/
```

Use the same challenge method the five existing `prod-*mcp.mechub.org` certificates use. Check first:

```bash
ssh root@pve2.mechub.org 'cat /etc/letsencrypt/renewal/prod-proxmoxmcp.mechub.org.conf'
```

- [ ] **Step 4: Install it on the controller and write the deploy hook**

Model the hook on the existing ones — read `prod-proxmoxmcp-lxc971` first, since it is the newest:

```bash
ssh root@pve2.mechub.org 'cat /etc/letsencrypt/renewal-hooks/deploy/prod-proxmoxmcp-lxc971'
```

The UniFi hook differs: the target is a network appliance, not an LXC, so it pushes the cert rather than using `pct exec`. Write `/etc/letsencrypt/renewal-hooks/deploy/unifi-controller` accordingly, `chmod 0755`, and make it idempotent and safe to run when the cert has not changed.

- [ ] **Step 5: Verify the chain and the name**

```bash
echo | openssl s_client -connect unifi.mechub.org:443 -servername unifi.mechub.org 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

Expected: `subject=CN=unifi.mechub.org`, a real issuer, and `DNS:unifi.mechub.org` in the SAN.

Then verify it the way `mecmcp-http` will — full verification, no `-k`:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' https://unifi.mechub.org/
```

Expected: `200`. **A non-zero curl exit or a TLS error here means the phase is not done.** Do not proceed to Task 3.

- [ ] **Step 6: Confirm the API key still works over the new cert**

```bash
curl -sS -H "X-API-KEY: $UNIFI_API_KEY" \
  https://unifi.mechub.org/proxy/network/integration/v1/sites | head -c 400
```

Expected: JSON listing sites. A 401 means the key needs reissuing; a TLS error means step 5 lied.

- [ ] **Step 7: Write the runbook and commit**

```bash
cd ~/Projects/rustunifimcp
mkdir -p docs/runbooks
# docs/runbooks/controller-certificate.md must contain:
#   - the before/after openssl output from steps 1 and 5
#   - the hook's path and contents
#   - the revert procedure using the backup from step 2
#   - a note that UniFi regenerates its self-signed cert on some upgrades,
#     which is why the hook exists rather than a one-off install
git add docs/runbooks/controller-certificate.md
git commit -m "docs: runbook for the UniFi controller certificate and its renewal hook"
```

**Verification:** `curl https://unifi.mechub.org/` returns 200 with no `-k`. Re-run after a forced renewal (`certbot renew --force-renewal --cert-name unifi.mechub.org`) to prove the hook fires.

---

## Phase 0c — Fixtures and the parity audit

Two artefacts, both inputs to everything after. The parity audit **is** the cutover bar: the ~24-tool surface is held, and every legacy tool actually in use must be shown reachable, or named as a signed-off gap.

### Task 3: Build the legacy parity audit

**Files:**
- Create: `docs/PARITY-AUDIT.md`
- Create: `scripts/audit-legacy-usage.sh`

**Interfaces:**
- Consumes: nothing.
- Produces: `docs/PARITY-AUDIT.md` — a table with columns `legacy tool | times called | reachable via | status`. Tasks 13, 17, 20, and 24 each tick rows in it; Task 22 and Task 27 gate on it having no unresolved rows.

- [ ] **Step 1: Write the usage-extraction script**

```sh
#!/bin/sh
# scripts/audit-legacy-usage.sh
# Count INVOCATIONS of the legacy unifi-mcp tools across Claude Code session
# history. Output is TSV: count, tool name. Sorted most-used first.
#
# The legacy server is enuno/unifi-mcp-server on LXC 980; its tools appear in
# transcripts as mcp__unifi-mcp__<name>.
#
# A plain `grep -o mcp__unifi-mcp__[a-z_]*` DOES NOT WORK and is the reason this
# script parses JSON instead. Every session transcript embeds the server's full
# tool list in its prompt, so grep counts tool *availability*: it returns all
# ~198 registered tools at a near-uniform ~1,790 hits each (one per session).
# That sets the parity bar to "everything" and defeats the audit. Only a
# `"type":"tool_use"` block is an actual call.
set -eu

HISTORY_ROOT="${HISTORY_ROOT:-$HOME/.claude}"

find "$HISTORY_ROOT" -name '*.jsonl' -type f -print0 2>/dev/null \
  | xargs -0 cat 2>/dev/null \
  | python3 -c '
import json, sys, collections

calls = collections.Counter()

def walk(node):
    """Transcript records nest tool_use blocks at varying depths."""
    if isinstance(node, dict):
        if node.get("type") == "tool_use" and str(node.get("name", "")).startswith(
            "mcp__unifi-mcp__"
        ):
            calls[node["name"].removeprefix("mcp__unifi-mcp__")] += 1
        for value in node.values():
            walk(value)
    elif isinstance(node, list):
        for value in node:
            walk(value)

for line in sys.stdin:
    try:
        walk(json.loads(line))
    except Exception:
        continue

for name, count in calls.most_common():
    print(f"{count}\t{name}")
'
```

- [ ] **Step 2: Run it and confirm it finds something**

```bash
cd ~/Projects/rustunifimcp
chmod +x scripts/audit-legacy-usage.sh
./scripts/audit-legacy-usage.sh | head -40
./scripts/audit-legacy-usage.sh | wc -l
```

Expected, as measured on 2026-08-26: **34 distinct tools, 114 total invocations.**

Two failure modes, in opposite directions, and both are real:

- **Zero rows** — the parity bar would be silently set to nothing. Check that
  `$HISTORY_ROOT` is right and that transcripts contain `mcp__unifi-mcp__`.
- **~198 rows at a near-uniform count** — you are counting the tool list in each
  session's prompt rather than calls, which sets the bar to "everything". That is
  what the naive `grep` did before this script parsed JSON. If every count lands
  in the same narrow band, this is what happened.

Neither is a result to write into the audit. Stop and fix the extraction.

- [ ] **Step 3: Write the audit document**

Create `docs/PARITY-AUDIT.md`:

```markdown
# Parity audit — legacy unifi-mcp (LXC 980) → rustunifimcp

Generated by `scripts/audit-legacy-usage.sh`, last run YYYY-MM-DD.

This table is the cutover bar. The ~24-tool surface is held; a legacy tool
below is either shown reachable through a read primitive's `kind` enum, a
workflow, or a change set — or it is a named gap that was signed off, never a
silent loss.

Re-run the script and refresh this table before each cutover.

| Legacy tool | Calls | Reachable via | Status |
|---|---|---|---|
| get_traffic_flows | 42 | `unifi_traffic_flow_report` | planned |
| list_firewall_policies | 31 | `unifi_list_resources kind=firewall_policy` | planned |
| ... | ... | ... | ... |

## Status vocabulary

- **planned** — a named tool in the design covers it; not yet built
- **covered** — built and verified against the live controller
- **gap (accepted)** — deliberately not carried; the reason is recorded below
- **gap (open)** — no coverage and no decision yet. **A cutover cannot proceed
  with an open gap.**

## Accepted gaps

(One subsection per accepted gap, each stating what is lost and why that is
acceptable.)
```

Fill the table from step 2's output. Every row starts as `planned` or `gap (open)`.

- [ ] **Step 4: Commit**

```bash
git add scripts/audit-legacy-usage.sh docs/PARITY-AUDIT.md
git commit -m "docs: parity audit against the legacy unifi-mcp tool surface

The cutover bar for a ~24-tool surface replacing ~270 is not a count, it is
coverage of what was actually called. This is that list, extracted from
session history rather than guessed."
```

**Verification:** `docs/PARITY-AUDIT.md` has one row per tool the script found, and no row is blank.

### Task 4: Capture recorded fixtures

**Files:**
- Create: `scripts/capture-fixtures.sh`
- Create: `rustunifimcp-core/tests/fixtures/<controller-version>/*.json`
- Create: `rustunifimcp-core/src/testing.rs`
- Modify: `rustunifimcp-core/src/lib.rs`

**Interfaces:**
- Consumes: Task 2's working TLS.
- Produces: `rustunifimcp_core::testing::fixture(version: &str, name: &str) -> serde_json::Value` — used by every model test from Task 8 onward.

- [ ] **Step 1: Write the capture script**

```sh
#!/bin/sh
# scripts/capture-fixtures.sh
# Record controller JSON per endpoint into tests/fixtures/<version>/.
#
# Requires UNIFI_API_KEY in the environment and a controller reachable over
# verified TLS -- no -k, because the server it feeds cannot use -k either.
set -eu

: "${UNIFI_API_KEY:?set UNIFI_API_KEY}"
CONTROLLER="${CONTROLLER:-https://unifi.mechub.org}"
SITE="${SITE:-default}"

VERSION=$(curl -sS -H "X-API-KEY: $UNIFI_API_KEY" \
    "$CONTROLLER/proxy/network/integration/v1/info" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["applicationVersion"])')

OUT="rustunifimcp-core/tests/fixtures/$VERSION"
mkdir -p "$OUT"
printf 'capturing controller %s into %s\n' "$VERSION" "$OUT"

capture() {
    name=$1; path=$2
    printf '  %-28s %s\n' "$name" "$path"
    if curl -sS --fail-with-body -H "X-API-KEY: $UNIFI_API_KEY" "$CONTROLLER$path" \
        | python3 -m json.tool > "$OUT/$name.json" 2>/dev/null; then
        :
    else
        # A 404 on a private route is a finding, not a failure: record it so the
        # version matrix can assert the endpoint's absence on this version.
        printf 'MISSING\n' > "$OUT/$name.absent"
        rm -f "$OUT/$name.json"
        printf '    -> absent on this version\n'
    fi
}

# Supported surface
capture info               "/proxy/network/integration/v1/info"
capture sites              "/proxy/network/integration/v1/sites"
capture devices            "/proxy/network/integration/v1/sites/$SITE/devices"
capture clients            "/proxy/network/integration/v1/sites/$SITE/clients"

# PrivateV1
capture networkconf        "/proxy/network/api/s/$SITE/rest/networkconf"
capture wlanconf           "/proxy/network/api/s/$SITE/rest/wlanconf"
capture portconf           "/proxy/network/api/s/$SITE/rest/portconf"
capture firewallgroup      "/proxy/network/api/s/$SITE/rest/firewallgroup"
capture firewallrule       "/proxy/network/api/s/$SITE/rest/firewallrule"
capture routing            "/proxy/network/api/s/$SITE/rest/routing"
capture user               "/proxy/network/api/s/$SITE/rest/user"
capture radiusprofile      "/proxy/network/api/s/$SITE/rest/radiusprofile"
capture stat_device        "/proxy/network/api/s/$SITE/stat/device"
capture stat_sta           "/proxy/network/api/s/$SITE/stat/sta"
capture health             "/proxy/network/api/s/$SITE/stat/health"

# PrivateV2 -- the drift-prone surface, and the reason the tags exist
capture zones              "/proxy/network/v2/api/site/$SITE/firewall/zone"
capture policies           "/proxy/network/v2/api/site/$SITE/firewall-policies"
capture traffic_routes     "/proxy/network/v2/api/site/$SITE/trafficroutes"
capture topology           "/proxy/network/v2/api/site/$SITE/topology"

printf 'done: %s\n' "$OUT"
ls -1 "$OUT"
```

- [ ] **Step 2: Redact and run**

The controller returns MAC addresses, client hostnames, and PSKs. Fixtures are committed to a public repo, so scrub before committing:

```bash
cd ~/Projects/rustunifimcp
chmod +x scripts/capture-fixtures.sh
UNIFI_API_KEY=... ./scripts/capture-fixtures.sh
grep -rilE 'x_passphrase|psk|password|"key"' rustunifimcp-core/tests/fixtures/
```

Replace every secret-bearing value with a fixed placeholder, and rewrite MACs and hostnames to documentation-range values. **Do not commit until this grep is clean.**

- [ ] **Step 3: Write the failing test for the fixture loader**

```rust
// rustunifimcp-core/src/testing.rs
#[cfg(test)]
mod tests {
    use super::fixture;

    #[test]
    fn loads_a_recorded_sites_response() {
        let value = fixture(super::DEFAULT_FIXTURE_VERSION, "sites");
        assert!(value.is_object() || value.is_array());
    }

    #[test]
    #[should_panic(expected = "no fixture")]
    fn a_missing_fixture_panics_with_the_path_it_looked_for() {
        let _ = fixture(super::DEFAULT_FIXTURE_VERSION, "no_such_endpoint");
    }
}
```

- [ ] **Step 4: Run it and watch it fail**

```bash
cargo test -p rustunifimcp-core testing::
```

Expected: FAIL — `cannot find function `fixture``.

- [ ] **Step 5: Implement the loader**

```rust
//! Test helpers for loading recorded controller responses.
//!
//! Fixtures are recorded per controller version by `scripts/capture-fixtures.sh`
//! and committed scrubbed. Tests read them instead of reaching the network, so
//! the model and client layers are exercised with no controller present.

use std::path::PathBuf;

/// The controller version whose fixtures the unit tests default to.
///
/// The version matrix in `tests/version_matrix.rs` deliberately reads others.
pub const DEFAULT_FIXTURE_VERSION: &str = "9.0.114"; // set to what step 2 captured

/// Load a recorded controller response.
///
/// # Panics
///
/// Panics if the fixture is absent or is not valid JSON. Both are test-authoring
/// errors, and a panic naming the path is the fastest way to fix them.
#[must_use]
pub fn fixture(version: &str, name: &str) -> serde_json::Value {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "fixtures",
        version,
        &format!("{name}.json"),
    ]
    .iter()
    .collect();

    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("no fixture at {}: {error}", path.display()));

    serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("fixture {} is not JSON: {error}", path.display()))
}

/// Whether an endpoint was recorded as absent on this controller version.
///
/// `capture-fixtures.sh` writes a `.absent` marker when a route 404s, so the
/// version matrix can assert absence as a fact rather than inferring it from a
/// missing file.
#[must_use]
pub fn is_absent(version: &str, name: &str) -> bool {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "fixtures",
        version,
        &format!("{name}.absent"),
    ]
    .iter()
    .collect();
    path.exists()
}
```

Add to `rustunifimcp-core/src/lib.rs`:

```rust
pub mod testing;
```

- [ ] **Step 6: Run the tests**

```bash
cargo test -p rustunifimcp-core testing::
```

Expected: PASS, both tests.

- [ ] **Step 7: Commit**

```bash
git add scripts/capture-fixtures.sh rustunifimcp-core/tests/fixtures rustunifimcp-core/src/testing.rs rustunifimcp-core/src/lib.rs
git commit -m "test: recorded controller fixtures and their loader

Captured over verified TLS, scrubbed of MACs, hostnames and PSKs. A 404 on a
private route is recorded as an .absent marker rather than dropped, so the
version matrix can assert an endpoint's absence instead of inferring it."
```

**Verification:** `cargo test -p rustunifimcp-core` passes; `ls rustunifimcp-core/tests/fixtures/*/` lists at least the four Supported and four PrivateV2 captures.

---

## Phase 1 — Client and resource model

No MCP surface. This is the one layer that is entirely UniFi-specific.

### Task 5: Wire the mecmcp dependencies and the error type

**Files:**
- Modify: `Cargo.toml`
- Modify: `rustunifimcp-core/Cargo.toml`
- Create: `rustunifimcp-core/src/error.rs`
- Modify: `rustunifimcp-core/src/lib.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `rustunifimcp_core::error::UnifiError` — the error type every later task returns.

- [ ] **Step 1: Add the pinned mecmcp dependencies**

Replace the commented-out block in the workspace `Cargo.toml`:

```toml
[workspace.dependencies]
rustunifimcp-core = { path = "rustunifimcp-core", version = "0.0.0" }

anyhow      = "1"
async-trait = "0.1"
axum        = "0.8"
axum-server = { version = "0.8", default-features = false, features = ["tls-rustls-no-provider"] }
chrono      = { version = "0.4", default-features = false, features = ["serde", "clock"] }
clap        = { version = "4", features = ["derive"] }
http        = "1"
rmcp        = { version = "3", features = ["server", "transport-io", "transport-streamable-http-server", "transport-streamable-http-server-session"] }
rustls      = { version = "0.23", default-features = false, features = ["aws-lc-rs", "std", "tls12", "logging"] }
schemars    = "1"
serde       = { version = "1", features = ["derive"] }
serde_json  = "1"
sha2        = "0.11"
thiserror   = "2"
tokio       = { version = "1", features = ["macros", "rt-multi-thread", "signal", "sync", "time"] }
tokio-util  = { version = "0.7", default-features = false, features = ["rt"] }
tracing     = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt"] }
url         = "2"
uuid        = { version = "1", features = ["v4"] }

# Test-only
rcgen        = "0.14"
tokio-rustls = "0.26"

# mecmcp is consumed read-only at an exact pinned version. Do not relax the tag.
mecmcp-audit     = { version = "0.20.0", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "v0.20.0" }
mecmcp-auth      = { version = "0.20.0", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "v0.20.0" }
mecmcp-changeset = { version = "0.20.0", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "v0.20.0" }
mecmcp-http      = { version = "0.20.0", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "v0.20.0" }
mecmcp-inventory = { version = "0.20.0", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "v0.20.0" }
mecmcp-job       = { version = "0.20.0", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "v0.20.0" }
mecmcp-openapi   = { version = "0.20.0", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "v0.20.0" }
mecmcp-policy    = { version = "0.20.0", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "v0.20.0" }
mecmcp-runtime   = { version = "0.20.0", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "v0.20.0" }
mecmcp-secret    = { version = "0.20.0", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "v0.20.0" }
mecmcp-server    = { version = "0.20.0", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "v0.20.0" }
mecmcp-transport = { version = "0.20.0", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "v0.20.0" }
```

And complete `[profile.release]`, which currently has only `codegen-units`:

```toml
[profile.release]
lto           = "thin"
codegen-units = 1
strip         = "symbols"
```

- [ ] **Step 2: Declare them in the core crate**

```toml
# rustunifimcp-core/Cargo.toml
[dependencies]
mecmcp-audit.workspace     = true
mecmcp-changeset.workspace = true
mecmcp-http.workspace      = true
mecmcp-inventory.workspace = true
mecmcp-job.workspace       = true
mecmcp-openapi.workspace   = true
mecmcp-secret.workspace    = true
mecmcp-server.workspace    = true
rmcp.workspace             = true
schemars.workspace         = true
serde.workspace            = true
serde_json.workspace       = true
thiserror.workspace        = true
tokio.workspace            = true
tracing.workspace          = true
```

- [ ] **Step 3: Verify the pin resolves**

```bash
cargo fetch
grep -A2 'name = "mecmcp-http"' Cargo.lock
```

Expected: the lock names `mecmcp-http 0.20.0` from the git source at tag `v0.20.0`. If cargo resolves a different version, the tag is wrong — fix it, do not proceed.

- [ ] **Step 4: Write the failing test for the error type**

```rust
// rustunifimcp-core/src/error.rs
#[cfg(test)]
mod tests {
    use super::UnifiError;

    /// A private-surface 404 must name the surface and the version, because
    /// that is the difference between "the controller changed" and "the tool
    /// is broken".
    #[test]
    fn a_private_route_gone_reads_as_drift_not_a_generic_failure() {
        let error = UnifiError::PrivateEndpointAbsent {
            surface: crate::ApiSurface::PrivateV2,
            path: "/v2/api/site/default/traffic-flows".to_owned(),
            controller_version: "9.1.0".to_owned(),
        };
        let rendered = error.to_string();
        assert!(rendered.contains("PrivateV2"), "{rendered}");
        assert!(rendered.contains("/v2/api/site/default/traffic-flows"), "{rendered}");
        assert!(rendered.contains("9.1.0"), "{rendered}");
    }

    /// The controller's API key must never reach an error string.
    #[test]
    fn upstream_errors_do_not_carry_the_url() {
        let error = UnifiError::Upstream {
            status: 401,
            detail: "unauthorized".to_owned(),
        };
        let rendered = error.to_string();
        assert!(!rendered.contains("X-API-KEY"), "{rendered}");
        assert!(!rendered.contains("https://"), "{rendered}");
    }
}
```

- [ ] **Step 5: Run it and watch it fail**

```bash
cargo test -p rustunifimcp-core error::
```

Expected: FAIL — `cannot find type `UnifiError``.

- [ ] **Step 6: Implement the error type**

```rust
//! The one error type for the core crate.
//!
//! Two properties are load-bearing and are tested. A private-surface endpoint
//! that has disappeared renders as attributable drift rather than a generic
//! failure — that is the whole reason endpoints carry their surface tag. And no
//! variant carries a URL or a header, because the controller's API key travels
//! in one.

use crate::ApiSurface;

/// Anything that can go wrong talking to a UniFi controller.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UnifiError {
    /// A private, undocumented endpoint is no longer present on this controller.
    ///
    /// Attributable by construction: the surface, the path and the controller
    /// version are all named, so this reads as drift rather than a tool fault.
    #[error(
        "private API {surface:?} path {path} is not present on controller version \
         {controller_version}; this endpoint is undocumented and may have been \
         removed by a controller upgrade"
    )]
    PrivateEndpointAbsent {
        /// Which private surface the path belongs to.
        surface: ApiSurface,
        /// The path that returned 404.
        path: String,
        /// The controller version that no longer serves it.
        controller_version: String,
    },

    /// The caller's token lacks the scope this surface requires.
    #[error("surface {surface:?} requires the `unifi:private-api` scope")]
    SurfaceNotPermitted {
        /// The surface that was refused.
        surface: ApiSurface,
    },

    /// The controller returned a non-success status.
    ///
    /// Deliberately carries no URL: the API key travels in a header on every
    /// request, and an error string is the easiest place for one to leak.
    #[error("controller returned {status}: {detail}")]
    Upstream {
        /// HTTP status code.
        status: u16,
        /// Server-supplied detail, already bounded by the caller.
        detail: String,
    },

    /// A response did not match the shape the model expects.
    #[error("unexpected response shape: {0}")]
    Malformed(String),

    /// Transport, TLS, timeout, or rate-limit failure from `mecmcp-http`.
    #[error(transparent)]
    Http(#[from] mecmcp_http::HttpError),

    /// Inventory load or validation failure.
    #[error(transparent)]
    Inventory(#[from] mecmcp_inventory::InventoryError),

    /// Credential load failure — bad mode, symlink, oversized, or absent.
    #[error(transparent)]
    Secret(#[from] mecmcp_secret::SecretError),
}
```

Add to `lib.rs`:

```rust
pub mod error;
```

- [ ] **Step 7: Run the tests**

```bash
cargo test -p rustunifimcp-core error::
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: PASS, and clippy clean.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml Cargo.lock rustunifimcp-core/Cargo.toml rustunifimcp-core/src/error.rs rustunifimcp-core/src/lib.rs
git commit -m "feat: pin mecmcp v0.20.0 and add the core error type

Two properties are tested rather than assumed: a vanished private endpoint
renders as attributable drift naming surface, path and controller version, and
no variant carries a URL, because the API key travels in a header on every
request."
```

**Verification:** `cargo test -p rustunifimcp-core` passes; `Cargo.lock` pins every mecmcp crate at `v0.20.0`.

### Task 6: Controller inventory

**Files:**
- Create: `rustunifimcp-core/src/inventory.rs`
- Create: `packaging/examples/controllers.example.json`
- Modify: `rustunifimcp-core/src/lib.rs`

**Interfaces:**
- Consumes: `UnifiError` (Task 5).
- Produces:
  - `Controller { name, endpoint, site, api_key_env: Option<String>, api_key_file: Option<PathBuf>, ca_pem_path: Option<PathBuf>, allow_private_api: bool, allow_cloud: bool }`
  - `ControllerRegistry::load(path: &Path) -> Result<Self, UnifiError>`
  - `ControllerRegistry::get(&self, name: &str) -> Result<&Controller, UnifiError>`
  - `Controller::load_api_key(&self) -> Result<OutboundSecret, UnifiError>`

- [ ] **Step 1: Write the failing tests**

```rust
// rustunifimcp-core/src/inventory.rs
#[cfg(test)]
mod tests {
    use super::Controller;

    /// The API key must never be storable in the inventory file. `serde`'s
    /// deny_unknown_fields is what enforces it, so a key-bearing document has
    /// to be a hard parse error rather than a silently ignored field.
    #[test]
    fn an_inline_api_key_is_rejected_at_parse_time() {
        let raw = r#"{
            "endpoint": "https://unifi.example.org",
            "site": "default",
            "api_key": "secret-value-that-must-not-parse"
        }"#;
        let parsed: Result<Controller, _> = serde_json::from_str(raw);
        assert!(parsed.is_err(), "an inline api_key must not deserialize");
    }

    /// Naming both sources is ambiguous, and ambiguity about which credential
    /// was used is not something to resolve by precedence.
    #[test]
    fn naming_both_key_sources_is_an_error() {
        let raw = r#"{
            "endpoint": "https://unifi.example.org",
            "site": "default",
            "api_key_env": "UNIFI_API_KEY",
            "api_key_file": "/etc/unifimcp/api.key"
        }"#;
        let controller: Controller = serde_json::from_str(raw).expect("parses");
        assert!(controller.validate().is_err());
    }

    /// Naming neither leaves nothing to authenticate with.
    #[test]
    fn naming_no_key_source_is_an_error() {
        let raw = r#"{
            "endpoint": "https://unifi.example.org",
            "site": "default"
        }"#;
        let controller: Controller = serde_json::from_str(raw).expect("parses");
        assert!(controller.validate().is_err());
    }

    /// mecmcp-http rejects non-https at request construction, but failing here
    /// names the config file rather than the twentieth request.
    #[test]
    fn a_plaintext_endpoint_is_rejected_by_validate() {
        let raw = r#"{
            "endpoint": "http://unifi.example.org",
            "site": "default",
            "api_key_env": "UNIFI_API_KEY"
        }"#;
        let controller: Controller = serde_json::from_str(raw).expect("parses");
        assert!(controller.validate().is_err());
    }

    /// Private and cloud surfaces are off unless a controller opts in.
    #[test]
    fn private_and_cloud_surfaces_default_off() {
        let raw = r#"{
            "endpoint": "https://unifi.example.org",
            "site": "default",
            "api_key_env": "UNIFI_API_KEY"
        }"#;
        let controller: Controller = serde_json::from_str(raw).expect("parses");
        assert!(!controller.allow_private_api);
        assert!(!controller.allow_cloud);
    }
}
```

- [ ] **Step 2: Run and watch them fail**

```bash
cargo test -p rustunifimcp-core inventory::
```

Expected: FAIL — `cannot find type `Controller``.

- [ ] **Step 3: Implement**

```rust
//! Multi-controller inventory.
//!
//! `controllers.json` is read through `mecmcp-inventory`'s hardened loader,
//! which requires mode 0600, a regular file, and ownership by the service user.
//!
//! The UniFi API key never appears in this file. Each controller names an
//! environment variable or a separate 0600 file, loaded through `mecmcp-secret`
//! into an `OutboundSecret` that zeroizes on drop and implements neither
//! `Debug` nor `Serialize`. `deny_unknown_fields` makes an inline key a parse
//! error rather than an ignored field.

use crate::error::UnifiError;
use mecmcp_secret::{OutboundSecret, SecretLimits, load_from_env, load_from_file};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// One UniFi Network controller.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Controller {
    /// Base URL including scheme, e.g. `https://unifi.example.org`.
    pub endpoint: String,
    /// Default site identifier, e.g. `default`.
    pub site: String,
    /// Environment variable holding the UniFi API key.
    #[serde(default)]
    pub api_key_env: Option<String>,
    /// File holding the UniFi API key. Mutually exclusive with the env form.
    #[serde(default)]
    pub api_key_file: Option<PathBuf>,
    /// PEM trust anchor, for a controller behind a private CA.
    ///
    /// `mecmcp-http` offers no insecure-skip-verify at any layer, so this is
    /// the only way to reach such a controller.
    #[serde(default)]
    pub ca_pem_path: Option<PathBuf>,
    /// Whether the undocumented `/api/s/` and `/v2/api/` surfaces may be used.
    ///
    /// Off by default, so a supported-only deployment is the default posture
    /// and a controller upgrade cannot silently break an undocumented route
    /// nobody opted into.
    #[serde(default)]
    pub allow_private_api: bool,
    /// Whether the Ubiquiti cloud Site Manager surface may be used.
    ///
    /// Off by default and unimplemented in v1.
    #[serde(default)]
    pub allow_cloud: bool,
}

impl Controller {
    /// Check the invariants `serde` cannot express.
    ///
    /// # Errors
    ///
    /// Returns [`UnifiError::Malformed`] if the endpoint is not `https://`, or
    /// if the controller names both credential sources or neither.
    pub fn validate(&self) -> Result<(), UnifiError> {
        if !self.endpoint.starts_with("https://") {
            return Err(UnifiError::Malformed(format!(
                "controller endpoint must be https://, got {}",
                self.endpoint
            )));
        }
        match (&self.api_key_env, &self.api_key_file) {
            (Some(_), Some(_)) => Err(UnifiError::Malformed(
                "controller names both api_key_env and api_key_file; name exactly one"
                    .to_owned(),
            )),
            (None, None) => Err(UnifiError::Malformed(
                "controller names neither api_key_env nor api_key_file".to_owned(),
            )),
            _ => Ok(()),
        }
    }

    /// Load the API key through `mecmcp-secret`'s hardened loader.
    ///
    /// # Errors
    ///
    /// Returns [`UnifiError::Secret`] if the file is a symlink, is group- or
    /// world-accessible, is oversized, or is absent.
    pub fn load_api_key(&self) -> Result<OutboundSecret, UnifiError> {
        self.validate()?;
        let limits = SecretLimits::default();
        if let Some(var) = &self.api_key_env {
            return Ok(load_from_env(var, limits)?);
        }
        let path = self
            .api_key_file
            .as_ref()
            .ok_or_else(|| UnifiError::Malformed("no api key source".to_owned()))?;
        Ok(load_from_file(path, limits)?)
    }
}
```

Add the registry in the same file, reading the `devices`-keyed envelope through `mecmcp_inventory::FileInventory` exactly as `rustproxmoxmcp/crates/rust-proxmoxmcp-core/src/inventory.rs` does — read that file first and follow its shape rather than inventing a second one.

Add to `lib.rs`:

```rust
pub mod inventory;
```

- [ ] **Step 4: Run the tests**

```bash
cargo test -p rustunifimcp-core inventory::
```

Expected: PASS, all five.

- [ ] **Step 5: Write the example config**

```json
{
  "devices": {
    "home": {
      "endpoint": "https://unifi.example.org",
      "site": "default",
      "api_key_file": "/etc/unifimcp/api.key",
      "allow_private_api": true
    }
  }
}
```

Save as `packaging/examples/controllers.example.json`. Add a comment in the packaging docs that the file must be mode 0600 and owned by the service user, and that `api.key` must be 0600 too.

- [ ] **Step 6: Commit**

```bash
git add rustunifimcp-core/src/inventory.rs rustunifimcp-core/src/lib.rs packaging/examples/controllers.example.json
git commit -m "feat: controller inventory with the API key held outside it

deny_unknown_fields makes an inline api_key a parse error rather than an
ignored field. Private and cloud surfaces default off, so supported-only is
the default posture rather than an opt-out."
```

### Task 7: The UniFi client

**Files:**
- Create: `rustunifimcp-core/src/client.rs`
- Modify: `rustunifimcp-core/src/lib.rs`

**Interfaces:**
- Consumes: `Controller` (Task 6), `UnifiError` (Task 5), `ApiSurface` (already in `lib.rs`).
- Produces:
  - `UnifiClient::new(controller: Controller) -> Result<Self, UnifiError>`
  - `UnifiClient::get(&self, surface: ApiSurface, template: &str, params: &[(&str, &str)], query: &[(&str, &str)]) -> Result<serde_json::Value, UnifiError>`
  - `UnifiClient::post`, `put`, `delete` with the same shape
  - `UnifiClient::controller_version(&self) -> Result<String, UnifiError>`
  - `UnifiClient::default_site(&self) -> &str` — used by Task 11 when a tool omits `site`
  - `UnifiClient::ensure_surface_permitted(controller: &Controller, surface: ApiSurface) -> Result<(), UnifiError>` — the permission gate, called by every request helper before the path is expanded

- [ ] **Step 1: Write the failing tests**

```rust
// rustunifimcp-core/src/client.rs
#[cfg(test)]
mod tests {
    use super::UnifiClient;
    use crate::ApiSurface;
    use crate::inventory::Controller;

    fn supported_only() -> Controller {
        serde_json::from_str(
            r#"{
                "endpoint": "https://unifi.example.org",
                "site": "default",
                "api_key_env": "UNIFI_TEST_KEY"
            }"#,
        )
        .expect("parses")
    }

    /// The tag is not decorative. A controller that has not opted in must be
    /// refused before a request is built, not after it 404s.
    #[test]
    fn a_private_surface_is_refused_when_the_controller_has_not_opted_in() {
        let controller = supported_only();
        let permitted =
            UnifiClient::ensure_surface_permitted(&controller, ApiSurface::PrivateV2);
        assert!(matches!(
            permitted,
            Err(crate::error::UnifiError::SurfaceNotPermitted { .. })
        ));
    }

    #[test]
    fn the_supported_surface_needs_no_opt_in() {
        let controller = supported_only();
        UnifiClient::ensure_surface_permitted(&controller, ApiSurface::Supported)
            .expect("supported surface is always available");
    }

    /// Path templating goes through mecmcp-openapi, which rejects rather than
    /// sanitises. A site id containing a traversal must not produce a request.
    #[test]
    fn a_traversing_site_id_is_rejected_not_sanitised() {
        let expanded = mecmcp_openapi::expand_path(
            "/proxy/network/api/s/{site}/rest/networkconf",
            &[("site", "../../../v2/api/site/default")],
        );
        assert!(expanded.is_err(), "traversal must be rejected");
    }
}
```

- [ ] **Step 2: Run and watch them fail**

```bash
cargo test -p rustunifimcp-core client::
```

Expected: FAIL — `cannot find type `UnifiClient``.

- [ ] **Step 3: Implement**

Follow `rustproxmoxmcp/crates/rust-proxmoxmcp-core/src/client.rs` closely — read it before writing. The differences that matter for UniFi:

```rust
//! One HTTP client per controller, over `mecmcp-http`.
//!
//! Each controller gets its own client with isolated rate limits, so a slow or
//! wedged controller cannot exhaust a pool shared with healthy ones.
//!
//! Every request's path is expanded by `mecmcp-openapi::expand_path`, which
//! rejects a parameter that would span a segment, start a query, navigate the
//! hierarchy, collapse a segment, or carry a control byte. Nothing is
//! sanitised: a rewritten value is a value the caller did not send. UniFi puts
//! the site id and the resource id directly in the path on all three local
//! surfaces, so this applies to essentially every request.

use crate::ApiSurface;
use crate::error::UnifiError;
use crate::inventory::Controller;
use mecmcp_http::{HttpClient, HttpClientConfig, HttpRequest, Method};
use mecmcp_secret::OutboundSecret;
use std::time::Duration;

/// Requests in flight to one controller.
const MAX_CONCURRENT: usize = 8;
/// Callers permitted to wait behind those.
const MAX_QUEUED: usize = 32;
/// Whole-request deadline, covering permit acquisition and send.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest response body accepted, enforced as it streams.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// A client bound to one controller.
pub struct UnifiClient {
    controller: Controller,
    http: HttpClient,
    api_key: OutboundSecret,
}

impl UnifiClient {
    /// Refuse a surface this controller has not opted into.
    ///
    /// `ResourceKind::path_template` already returns absolute paths, so there
    /// is no prefix to hand back — this is purely the permission gate, and it
    /// runs before a request is built. An un-opted-in deployment therefore
    /// cannot reach an undocumented route even by accident.
    ///
    /// # Errors
    ///
    /// Returns [`UnifiError::SurfaceNotPermitted`] if the controller has not
    /// opted into the private or cloud surfaces, or [`UnifiError::Malformed`]
    /// for the cloud surface, which is unimplemented in v1.
    pub fn ensure_surface_permitted(
        controller: &Controller,
        surface: ApiSurface,
    ) -> Result<(), UnifiError> {
        match surface {
            ApiSurface::Supported => Ok(()),
            ApiSurface::PrivateV1 | ApiSurface::PrivateV2
                if controller.allow_private_api =>
            {
                Ok(())
            }
            ApiSurface::Cloud if controller.allow_cloud => Err(UnifiError::Malformed(
                "the cloud Site Manager surface is not implemented in v1".to_owned(),
            )),
            other => Err(UnifiError::SurfaceNotPermitted { surface: other }),
        }
    }

    /// The controller's configured default site, used when a tool omits one.
    #[must_use]
    pub fn default_site(&self) -> &str {
        &self.controller.site
    }
}
```

Then build the client in `new` exactly as proxmox does — `HttpClientConfig` with the four constants above, `extra_root_certificates` from `ca_pem_path` if set, `user_agent` of `concat!("rustunifimcp/", env!("CARGO_PKG_VERSION"))`.

Authentication differs from proxmox: UniFi uses the `X-API-KEY` header, set with `HttpRequest::secret_header("X-API-KEY", &self.api_key)` — **not** `bearer_auth`, and never `header`, which would take the secret as a plain `&str` and defeat the redaction.

In the request helpers, map a 404 on a private surface to `UnifiError::PrivateEndpointAbsent` carrying the surface, the expanded path, and the cached controller version. That mapping is the entire payoff of the tag enum; a generic `Upstream { status: 404 }` throws it away.

Add to `lib.rs`:

```rust
pub mod client;
```

- [ ] **Step 4: Run the tests**

```bash
cargo test -p rustunifimcp-core client::
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: PASS, all three; clippy clean.

- [ ] **Step 5: Commit**

```bash
git add rustunifimcp-core/src/client.rs rustunifimcp-core/src/lib.rs
git commit -m "feat: UniFi client over mecmcp-http

A private surface is refused before a request is built rather than after it
404s, and a 404 that does happen is mapped to PrivateEndpointAbsent naming
surface, path and controller version -- which is the entire payoff of the tag
enum. The API key goes through secret_header, never header."
```

### Task 8: Resource model and the `ResourceKind` enum

**Files:**
- Create: `rustunifimcp-core/src/model/mod.rs`, `site.rs`, `device.rs`, `station.rs`, `network.rs`, `firewall.rs`, `routing.rs`, `stats.rs`
- Modify: `rustunifimcp-core/src/lib.rs`

**Interfaces:**
- Consumes: `fixture` (Task 4), `UnifiError` (Task 5), `ApiSurface`.
- Produces:
  - `ResourceKind` — the enum that collapses ~130 legacy `list_x`/`get_x` pairs
  - `ResourceKind::surface(self) -> ApiSurface`
  - `ResourceKind::path_template(self) -> &'static str`
  - one typed struct per kind, each `Deserialize + Serialize + JsonSchema`

- [ ] **Step 1: Write the failing tests**

```rust
// rustunifimcp-core/src/model/mod.rs
#[cfg(test)]
mod tests {
    use super::ResourceKind;
    use crate::ApiSurface;
    use crate::testing::{DEFAULT_FIXTURE_VERSION, fixture};

    /// Every kind must declare a surface. A kind whose surface is wrong is how
    /// an undocumented route gets reached by a supported-only deployment.
    #[test]
    fn every_kind_declares_its_surface_and_path() {
        for kind in ResourceKind::ALL {
            let template = kind.path_template();
            assert!(!template.is_empty(), "{kind:?} has no path template");
            assert!(template.starts_with('/'), "{kind:?} template is not absolute");
            // A supported-surface kind must not point at a private route.
            if kind.surface() == ApiSurface::Supported {
                assert!(
                    !template.contains("/api/s/") && !template.contains("/v2/api/"),
                    "{kind:?} claims Supported but uses a private path: {template}"
                );
            }
        }
    }

    #[test]
    fn firewall_zones_are_tagged_private_v2() {
        assert_eq!(ResourceKind::FirewallZone.surface(), ApiSurface::PrivateV2);
    }

    #[test]
    fn sites_parse_from_the_recorded_response() {
        let raw = fixture(DEFAULT_FIXTURE_VERSION, "sites");
        let sites = crate::model::site::parse_sites(&raw).expect("sites parse");
        assert!(!sites.is_empty(), "the recorded controller has at least one site");
    }

    #[test]
    fn networks_parse_from_the_recorded_response() {
        let raw = fixture(DEFAULT_FIXTURE_VERSION, "networkconf");
        let networks = crate::model::network::parse_networks(&raw).expect("networks parse");
        assert!(!networks.is_empty());
    }
}
```

- [ ] **Step 2: Run and watch them fail**

```bash
cargo test -p rustunifimcp-core model::
```

Expected: FAIL — `cannot find type `ResourceKind``.

- [ ] **Step 3: Implement the enum**

```rust
//! The resource model, and the enum that collapses the legacy surface.
//!
//! Roughly 130 of the legacy server's tools are `list_x` / `get_x` pairs that
//! differ only in the resource they address. They become variants here, behind
//! a shared, documented envelope, reached through `unifi_list_resources` and
//! `unifi_get_resource`.
//!
//! Each variant carries its API surface, which is what lets a supported-only
//! deployment refuse the undocumented ones structurally rather than by
//! convention.

use crate::ApiSurface;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub mod device;
pub mod firewall;
pub mod network;
pub mod routing;
pub mod site;
pub mod station;
pub mod stats;

/// A kind of UniFi resource addressable by the read primitives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ResourceKind {
    /// A wireless or wired client associated with the site.
    Station,
    /// An adopted UniFi device: AP, switch, or gateway.
    Device,
    /// A configured network / VLAN.
    Network,
    /// A wireless network.
    Wlan,
    /// A switch port profile.
    PortProfile,
    /// A static DHCP mapping.
    DhcpReservation,
    /// A zone-based firewall policy.
    FirewallPolicy,
    /// A firewall zone.
    FirewallZone,
    /// A firewall address or port group.
    FirewallGroup,
    /// A policy-based traffic route.
    TrafficRoute,
    /// A RADIUS profile.
    RadiusProfile,
}

impl ResourceKind {
    /// Every variant, for exhaustive tests and for `unifi_list_resources`'
    /// schema.
    pub const ALL: &'static [Self] = &[
        Self::Station,
        Self::Device,
        Self::Network,
        Self::Wlan,
        Self::PortProfile,
        Self::DhcpReservation,
        Self::FirewallPolicy,
        Self::FirewallZone,
        Self::FirewallGroup,
        Self::TrafficRoute,
        Self::RadiusProfile,
    ];

    /// Which API surface this kind is served from.
    #[must_use]
    pub const fn surface(self) -> ApiSurface {
        match self {
            Self::Station | Self::Device => ApiSurface::Supported,
            Self::Network
            | Self::Wlan
            | Self::PortProfile
            | Self::DhcpReservation
            | Self::FirewallGroup
            | Self::RadiusProfile => ApiSurface::PrivateV1,
            Self::FirewallPolicy | Self::FirewallZone | Self::TrafficRoute => {
                ApiSurface::PrivateV2
            }
        }
    }

    /// The path template, expanded by `mecmcp-openapi::expand_path`.
    #[must_use]
    pub const fn path_template(self) -> &'static str {
        match self {
            Self::Station => "/proxy/network/integration/v1/sites/{site}/clients",
            Self::Device => "/proxy/network/integration/v1/sites/{site}/devices",
            Self::Network => "/proxy/network/api/s/{site}/rest/networkconf",
            Self::Wlan => "/proxy/network/api/s/{site}/rest/wlanconf",
            Self::PortProfile => "/proxy/network/api/s/{site}/rest/portconf",
            Self::DhcpReservation => "/proxy/network/api/s/{site}/rest/user",
            Self::FirewallGroup => "/proxy/network/api/s/{site}/rest/firewallgroup",
            Self::RadiusProfile => "/proxy/network/api/s/{site}/rest/radiusprofile",
            Self::FirewallPolicy => "/proxy/network/v2/api/site/{site}/firewall-policies",
            Self::FirewallZone => "/proxy/network/v2/api/site/{site}/firewall/zone",
            Self::TrafficRoute => "/proxy/network/v2/api/site/{site}/trafficroutes",
        }
    }
}
```

**Verify the WAN assumption while you are here.** `docs/PARITY-AUDIT.md` maps
`list_wan_connections` and `list_wan_dns` to `kind=network` on the reasoning that
a UniFi WAN *is* a network — `networkconf` entries carrying `purpose: "wan"`,
with WAN DNS on the same entries as `wan_dns1` / `wan_dns2`. Confirm that against
the recorded `networkconf` fixture. If the fields are not there, add a `Wan`
variant and update the audit; do not leave the mapping asserted but unchecked.

**Correct the templates against the fixtures Task 4 actually captured.** The paths above are the expected shapes; the recorded responses are the truth. If a fixture came back `.absent`, the template is wrong or the route does not exist on that version — resolve it now, not in Phase 2.

- [ ] **Step 4: Implement one module per kind**

Each is a `Deserialize + Serialize + JsonSchema` struct plus a `parse_*` function that takes `&serde_json::Value` and returns `Result<Vec<T>, UnifiError>`. UniFi's private surfaces wrap payloads in `{"meta": {...}, "data": [...]}` while the Integration API returns `{"data": [...], "offset": ..., "limit": ...}`; write one unwrap helper in `model/mod.rs` and use it from every `parse_*` rather than repeating the shape check.

Derive field names from the fixtures. Do not guess: `python3 -m json.tool` each fixture and read it.

- [ ] **Step 5: Run the tests**

```bash
cargo test -p rustunifimcp-core model::
```

Expected: PASS, all four.

- [ ] **Step 6: Commit**

```bash
git add rustunifimcp-core/src/model rustunifimcp-core/src/lib.rs
git commit -m "feat: resource model and the ResourceKind enum

~130 legacy list_x/get_x pairs collapse into variants behind one documented
envelope. Each variant carries its API surface, which is what lets a
supported-only deployment refuse the undocumented routes structurally."
```

### Task 9: Controller version matrix

**Files:**
- Create: `rustunifimcp-core/src/version.rs`
- Create: `rustunifimcp-core/tests/version_matrix.rs`
- Modify: `rustunifimcp-core/src/lib.rs`

**Interfaces:**
- Consumes: `ResourceKind` (Task 8), `is_absent`/`fixture` (Task 4).
- Produces: `endpoint_available(version: &str, kind: ResourceKind) -> bool`.

**Phase 1 exit criterion:** this matrix must distinguish at least two controller versions. That means Task 4's capture script has to have been run against two — if only one controller exists, capture the second from a controller upgrade, or record the second set by hand from release notes and mark it as such in the test.

- [ ] **Step 1: Write the failing test**

```rust
// rustunifimcp-core/tests/version_matrix.rs
//! Which endpoints exist on which controller version.
//!
//! This is where private-API drift is caught, and it is the reason every
//! endpoint carries a surface tag. A private route that disappears in a
//! controller upgrade should fail here, in CI, rather than in a tool call at
//! 03:00.

use rustunifimcp_core::model::ResourceKind;
use rustunifimcp_core::testing::is_absent;
use rustunifimcp_core::version::endpoint_available;

/// Every version directory under tests/fixtures/.
fn recorded_versions() -> Vec<String> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
    std::fs::read_dir(dir)
        .expect("fixtures directory exists")
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect()
}

#[test]
fn at_least_two_controller_versions_are_recorded() {
    let versions = recorded_versions();
    assert!(
        versions.len() >= 2,
        "the matrix cannot distinguish versions with only {versions:?}; \
         Phase 1's exit criterion is two"
    );
}

#[test]
fn the_matrix_agrees_with_what_was_recorded() {
    for version in recorded_versions() {
        for kind in ResourceKind::ALL {
            let fixture_name = kind_fixture_name(*kind);
            let recorded_absent = is_absent(&version, fixture_name);
            let matrix_says = endpoint_available(&version, *kind);
            assert_eq!(
                !recorded_absent, matrix_says,
                "matrix and fixtures disagree for {kind:?} on {version}: \
                 recorded_absent={recorded_absent}, matrix_available={matrix_says}"
            );
        }
    }
}

/// Map a kind to the fixture basename `capture-fixtures.sh` wrote.
fn kind_fixture_name(kind: ResourceKind) -> &'static str {
    match kind {
        ResourceKind::Station => "clients",
        ResourceKind::Device => "devices",
        ResourceKind::Network => "networkconf",
        ResourceKind::Wlan => "wlanconf",
        ResourceKind::PortProfile => "portconf",
        ResourceKind::DhcpReservation => "user",
        ResourceKind::FirewallGroup => "firewallgroup",
        ResourceKind::RadiusProfile => "radiusprofile",
        ResourceKind::FirewallPolicy => "policies",
        ResourceKind::FirewallZone => "zones",
        ResourceKind::TrafficRoute => "traffic_routes",
    }
}
```

- [ ] **Step 2: Run and watch it fail**

```bash
cargo test -p rustunifimcp-core --test version_matrix
```

Expected: FAIL — `unresolved import `rustunifimcp_core::version``.

- [ ] **Step 3: Implement**

```rust
//! Controller version matrix.
//!
//! The supported Integration API is stable and always present. The private
//! surfaces are not, so their availability is declared per version and
//! asserted against recorded fixtures in `tests/version_matrix.rs`.
//!
//! Adding a controller version means recording its fixtures and adding a row
//! here. A disagreement between the two is a test failure, deliberately.

use crate::ApiSurface;
use crate::model::ResourceKind;

/// Whether a controller version serves the endpoint behind a resource kind.
#[must_use]
pub fn endpoint_available(version: &str, kind: ResourceKind) -> bool {
    if kind.surface() == ApiSurface::Supported {
        return true;
    }
    match (major_minor(version), kind) {
        // Populate from what Task 4 actually recorded. Every row must be
        // justified by a fixture or an .absent marker.
        (_, _) => true,
    }
}

/// Parse `9.0.114` into `(9, 0)`; anything unparseable sorts as `(0, 0)`.
fn major_minor(version: &str) -> (u32, u32) {
    let mut parts = version.split('.');
    let major = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    (major, minor)
}
```

Replace the placeholder match arm with real rows derived from the fixtures. The catch-all `(_, _) => true` is a starting point that makes the test pass only when nothing was recorded absent — **if any `.absent` marker exists, the test will fail until you write the real row**, which is the intent.

- [ ] **Step 4: Run the tests**

```bash
cargo test -p rustunifimcp-core --test version_matrix
```

Expected: PASS, both.

- [ ] **Step 5: Commit**

```bash
git add rustunifimcp-core/src/version.rs rustunifimcp-core/tests/version_matrix.rs rustunifimcp-core/src/lib.rs
git commit -m "test: controller version matrix asserted against recorded fixtures

The matrix and the fixtures must agree; a disagreement fails CI. This is where
private-API drift gets caught, which is the reason endpoints carry surface tags
at all."
```

**Phase 1 exit:** `cargo test -p rustunifimcp-core` passes, every resource kind parses from recorded fixtures, and the version matrix distinguishes at least two controller versions.

---

## Phase 2 — Read-only server

The first runnable binary. Five read primitives plus three administration tools over hardened streamable-HTTP with bearer auth, scopes, and audit.

### Task 10: The write-tool registry and its guard

This comes **first** in Phase 2, before any tool exists, because the failure mode it guards against is silent. `mecmcp-server` enforces "a wildcard token is read-only" against a registry the server passes in as a parameter, and `crates/mecmcp-server/src/authorize.rs:237` pins the consequence in a test of its own: an empty registry turns every wildcard token into a writer.

**Files:**
- Create: `rustunifimcp-core/src/tools/mod.rs`
- Create: `rustunifimcp-core/tests/write_tool_registry.rs`
- Modify: `rustunifimcp-core/src/lib.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `WRITE_TOOLS: &[&str]` and `TOOL_NAMES: &[&str]`, consumed by Tasks 11, 12, 14, 17, 20, 24.

- [ ] **Step 1: Write the failing test**

```rust
// rustunifimcp-core/tests/write_tool_registry.rs
//! Guard for the registry `mecmcp-server` authorizes against.
//!
//! `--tools '*'` grants read-only tools only, and that rule is enforced against
//! a registry this server supplies as a parameter. mecmcp's own
//! `authorize.rs:237` pins the failure mode: an empty registry turns every
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
        assert!(
            TOOL_NAMES.contains(name),
            "{name} is in WRITE_TOOLS but is not a registered tool; \
             a name with no tool behind it guards nothing"
        );
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
```

- [ ] **Step 2: Run and watch it fail**

```bash
cargo test -p rustunifimcp-core --test write_tool_registry
```

Expected: FAIL — `unresolved import `rustunifimcp_core::tools``.

- [ ] **Step 3: Implement the registry**

```rust
//! The MCP tool surface.
//!
//! Roughly 24 tools, against roughly 270 on the server this replaces. The shape
//! follows the mechub family: typed primitives, a change-control lifecycle, and
//! a small number of workflows that earn their names.

pub mod admin;
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
/// slice. `mecmcp-server`'s own `authorize.rs:237` demonstrates that an empty
/// registry turns every wildcard token into a writer, so the list is written
/// out by hand and asserted by name in `tests/write_tool_registry.rs`.
pub const WRITE_TOOLS: &[&str] = &[
    // Phase 3 — operational actions
    "unifi_device_action",
    "unifi_client_action",
    "unifi_backup_action",
    "unifi_run_speed_test",
    // Phase 6 adds the seven change-set tools here.
];
```

Note the deliberate asymmetry: `WRITE_TOOLS` names the four operational tools now, in Phase 2, even though they are not implemented until Phase 3. `TOOL_NAMES` does not. The third test will therefore fail until Task 17 registers them — that is intentional, and Task 17's step 1 is to make it pass.

**Adjust for this:** in step 1's third test, gate it so Phase 2 is green:

```rust
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
```

Task 16 replaces this body with the strict assertion, once all four operational tools are registered.

Add to `lib.rs`:

```rust
pub mod tools;
```

- [ ] **Step 4: Run the tests**

```bash
cargo test -p rustunifimcp-core --test write_tool_registry
```

Expected: PASS, all four.

- [ ] **Step 5: Commit**

```bash
git add rustunifimcp-core/src/tools/mod.rs rustunifimcp-core/tests/write_tool_registry.rs rustunifimcp-core/src/lib.rs
git commit -m "feat: the write-tool registry, guarded by name

mecmcp-server enforces wildcard-is-read-only against a registry this server
passes in. authorize.rs:237 shows what an empty one does: every wildcard token
becomes a writer. The list is hand-written and asserted by name, not by count."
```

### Task 11: The five read primitives

**Files:**
- Create: `rustunifimcp-core/src/tools/read.rs`
- Modify: `rustunifimcp-core/src/tools/mod.rs`

**Interfaces:**
- Consumes: `UnifiClient` (Task 7), `ResourceKind` (Task 8), `WRITE_TOOLS` (Task 10).
- Produces: five `async fn` handlers, each taking `&UnifiClient` and a `schemars`-derived args struct, returning `Result<serde_json::Value, UnifiError>`.

- [ ] **Step 1: Write the failing tests**

```rust
// rustunifimcp-core/src/tools/read.rs
#[cfg(test)]
mod tests {
    use super::{GetResourceArgs, ListResourcesArgs};
    use crate::model::ResourceKind;

    /// Unknown fields must be refused, not dropped. rust-proxmoxmcp shipped
    /// this as a fix (its "refuse unknown fields instead of silently dropping
    /// them" commit): a caller who misspells a filter should be told, not
    /// silently given unfiltered results.
    #[test]
    fn unknown_arguments_are_refused_not_dropped() {
        let raw = r#"{"controller":"home","kind":"network","limitt":5}"#;
        let parsed: Result<ListResourcesArgs, _> = serde_json::from_str(raw);
        assert!(parsed.is_err(), "a misspelled argument must be an error");
    }

    #[test]
    fn every_resource_kind_round_trips_through_the_args_schema() {
        for kind in ResourceKind::ALL {
            let json = serde_json::to_string(kind).expect("serializes");
            let raw = format!(r#"{{"controller":"home","kind":{json}}}"#);
            let parsed: ListResourcesArgs =
                serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{kind:?}: {e}"));
            assert_eq!(parsed.kind, *kind);
        }
    }

    #[test]
    fn get_resource_requires_an_id() {
        let raw = r#"{"controller":"home","kind":"network"}"#;
        let parsed: Result<GetResourceArgs, _> = serde_json::from_str(raw);
        assert!(parsed.is_err(), "get_resource without an id must not parse");
    }
}
```

- [ ] **Step 2: Run and watch them fail**

```bash
cargo test -p rustunifimcp-core tools::read::
```

Expected: FAIL — `cannot find type `ListResourcesArgs``.

- [ ] **Step 3: Implement**

```rust
//! The five read primitives.
//!
//! `unifi_list_resources` and `unifi_get_resource` are where the collapsed
//! surface lives: roughly 130 of the legacy server's tools were `list_x` /
//! `get_x` pairs differing only in the resource addressed, and they are variants
//! of `ResourceKind` here behind one documented envelope.

use crate::client::UnifiClient;
use crate::error::UnifiError;
use crate::model::ResourceKind;
use schemars::JsonSchema;
use serde::Deserialize;

/// Arguments to `unifi_list_resources`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListResourcesArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// Which kind of resource to list.
    pub kind: ResourceKind,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
    /// Maximum items to return.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Offset into the result set.
    #[serde(default)]
    pub offset: Option<u64>,
}

/// Arguments to `unifi_get_resource`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetResourceArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// Which kind of resource to fetch.
    pub kind: ResourceKind,
    /// The resource identifier.
    pub id: String,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
}

/// List resources of one kind.
///
/// # Errors
///
/// Returns [`UnifiError::SurfaceNotPermitted`] if the kind lives on a private
/// surface the controller has not opted into, or [`UnifiError::PrivateEndpointAbsent`]
/// if a private route has been removed by a controller upgrade.
pub async fn list_resources(
    client: &UnifiClient,
    args: &ListResourcesArgs,
) -> Result<serde_json::Value, UnifiError> {
    let page = mecmcp_openapi::page(
        args.offset.unwrap_or(0),
        u64::from(args.limit.unwrap_or(200)),
        mecmcp_openapi::PageLimits::default(),
    )
    .map_err(|error| UnifiError::Malformed(error.to_string()))?;

    client
        .get(
            args.kind.surface(),
            args.kind.path_template(),
            &[("site", args.site.as_deref().unwrap_or(client.default_site()))],
            &[
                ("offset", &page.from.to_string()),
                ("limit", &page.size.to_string()),
            ],
        )
        .await
}
```

Implement `get_resource`, `query_stats`, `search`, and `list_sites` in the same shape. `query_stats` takes a `StatsSubject` (`site | device | station | wlan | flow`) plus a time window and lives on `PrivateV1`; `search` fans across stations, devices, and sites and merges; `list_sites` is `Supported` and takes only a controller.

Add to `tools/mod.rs`'s `TOOL_NAMES` — they are already listed there from Task 10.

- [ ] **Step 4: Run the tests**

```bash
cargo test -p rustunifimcp-core tools::read::
```

Expected: PASS, all three.

- [ ] **Step 5: Commit**

```bash
git add rustunifimcp-core/src/tools/read.rs rustunifimcp-core/src/tools/mod.rs
git commit -m "feat: the five read primitives

deny_unknown_fields on every args struct: a misspelled filter is an error, not
silently unfiltered results -- the defect rust-proxmoxmcp fixed in its own
argument handling."
```

### Task 12: The three administration tools

**Files:**
- Create: `rustunifimcp-core/src/tools/admin.rs`
- Modify: `rustunifimcp-core/src/tools/mod.rs`

**Interfaces:**
- Consumes: `ControllerRegistry` (Task 6), `UnifiClient` (Task 7).
- Produces: `list_controllers`, `add_controller`, `status` handlers.

- [ ] **Step 1: Write the failing tests**

```rust
// rustunifimcp-core/src/tools/admin.rs
#[cfg(test)]
mod tests {
    use super::redacted_controller_view;
    use crate::inventory::Controller;

    /// list_controllers must not disclose credential locations. Naming the file
    /// path tells a caller exactly which file to attack.
    #[test]
    fn the_controller_view_hides_credential_locations() {
        let controller: Controller = serde_json::from_str(
            r#"{
                "endpoint": "https://unifi.example.org",
                "site": "default",
                "api_key_file": "/etc/unifimcp/api.key"
            }"#,
        )
        .expect("parses");

        let view = redacted_controller_view("home", &controller);
        let rendered = serde_json::to_string(&view).expect("serializes");

        assert!(!rendered.contains("/etc/unifimcp/api.key"), "{rendered}");
        assert!(!rendered.contains("api_key_file"), "{rendered}");
        assert!(rendered.contains("unifi.example.org"), "{rendered}");
    }

    /// The view must say whether private surfaces are reachable, because that
    /// is what a caller needs to know before choosing a resource kind.
    #[test]
    fn the_controller_view_states_its_surface_posture() {
        let controller: Controller = serde_json::from_str(
            r#"{
                "endpoint": "https://unifi.example.org",
                "site": "default",
                "api_key_env": "K",
                "allow_private_api": true
            }"#,
        )
        .expect("parses");

        let view = redacted_controller_view("home", &controller);
        let rendered = serde_json::to_string(&view).expect("serializes");
        assert!(rendered.contains("allow_private_api"), "{rendered}");
    }
}
```

- [ ] **Step 2: Run and watch them fail**

```bash
cargo test -p rustunifimcp-core tools::admin::
```

Expected: FAIL — `cannot find function `redacted_controller_view``.

- [ ] **Step 3: Implement**

`redacted_controller_view` returns a `serde_json::Value` carrying name, endpoint, site, `allow_private_api`, `allow_cloud`, and reachability — and nothing about where the credential lives.

`unifimcp_status` reports server version, the pinned `mecmcp` version, transport, whether lab mode is on, tool count, and per-controller reachability with the controller version each reports. It is the tool an operator calls first, so make it answer "is this thing working and what is it talking to" in one response.

`unifi_add_controller` will fail under `ProtectSystem=strict` exactly as `rust-junosmcp`'s `add_device` does — `/etc/unifimcp` is read-only to the service process. **Do not widen the sandbox to make it work.** Implement it to return a clear error naming the hand-edit path (`edit /etc/unifimcp/controllers.json as root, then systemctl kill -s HUP rustunifimcp.service`), and document that in the README. The fleet's documented preference is a narrow sandbox over a working `add_*` tool.

- [ ] **Step 4: Run the tests**

```bash
cargo test -p rustunifimcp-core tools::admin::
```

Expected: PASS, both.

- [ ] **Step 5: Commit**

```bash
git add rustunifimcp-core/src/tools/admin.rs rustunifimcp-core/src/tools/mod.rs
git commit -m "feat: the three administration tools

list_controllers discloses posture, never credential locations. add_controller
returns the hand-edit path rather than prompting a wider sandbox -- the same
trade rust-junosmcp made and documented."
```

### Task 13: The binary — CLI, transport, and server handler

**Files:**
- Modify: `rustunifimcp/Cargo.toml`, `rustunifimcp/src/main.rs`
- Create: `rustunifimcp/src/lib.rs`, `cli.rs`, `http_transport.rs`, `server/mod.rs`

**Interfaces:**
- Consumes: everything from Tasks 6–12.
- Produces: a runnable `rustunifimcp` binary with `serve`, `token add|list|revoke|rotate|set-scope`, and `validate-config`.

- [ ] **Step 1: Read the sibling first**

```bash
cd ~/Projects/rustproxmoxmcp
cat crates/rust-proxmoxmcp/src/cli.rs
cat crates/rust-proxmoxmcp/src/http_transport.rs
ls crates/rust-proxmoxmcp/src/server/
```

The CLI shape is a family contract, not a per-repo choice. `mecmcp` `docs/PACKAGING.md` names the three flags that must be spelled identically everywhere:

| Flag | Meaning |
|---|---|
| `--lab-mode` | Run without two-person control; change sets are approved on creation |
| `--state-file` | Absolute path to the change-set and operation state file |
| `--approval-timeout-secs` | How long an approval stays valid |

Adopt these names. Do not invent better ones.

- [ ] **Step 2: Write the failing test**

```rust
// rustunifimcp/src/cli.rs
#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::Parser;

    /// --lab-mode is CLI-only and must never be readable from a config file.
    /// mecmcp#267 decided this: a relaxed security control should be visible
    /// where someone will see it, and a boolean in a product config file is
    /// strictly less visible than a flag in a unit file, not more.
    #[test]
    fn lab_mode_is_a_flag_and_defaults_off() {
        let cli = Cli::try_parse_from([
            "rustunifimcp",
            "serve",
            "--controllers-file",
            "/etc/unifimcp/controllers.json",
        ])
        .expect("parses");
        assert!(!cli.lab_mode());

        let cli = Cli::try_parse_from([
            "rustunifimcp",
            "serve",
            "--controllers-file",
            "/etc/unifimcp/controllers.json",
            "--lab-mode",
        ])
        .expect("parses");
        assert!(cli.lab_mode());
    }

    /// There must be no way to ask for unverified TLS. If this test ever needs
    /// changing, the deployment is wrong, not the test.
    #[test]
    fn there_is_no_insecure_tls_flag() {
        for flag in [
            "--insecure",
            "--no-verify-tls",
            "--insecure-skip-verify",
            "--tls-no-verify",
        ] {
            let parsed = Cli::try_parse_from([
                "rustunifimcp",
                "serve",
                "--controllers-file",
                "/etc/unifimcp/controllers.json",
                flag,
            ]);
            assert!(parsed.is_err(), "{flag} must not be accepted");
        }
    }
}
```

- [ ] **Step 3: Run and watch it fail**

```bash
cargo test -p rustunifimcp cli::
```

Expected: FAIL — `cannot find type `Cli``.

- [ ] **Step 4: Implement the CLI, transport, and handler**

Mirror `rustproxmoxmcp`'s three files. The server handler's `call_tool` must:

1. recover the caller with `mecmcp_server::authorize::caller_from_extensions`
2. authorize with `authorize_call(caller, tool_name, target, WRITE_TOOLS)` — passing `rustunifimcp_core::tools::WRITE_TOOLS`, never a locally-built slice
3. dispatch
4. bound the result through `mecmcp_server::bounded_text` / `tool_result`

and `list_tools` must return `filter_tools_for_scope(tools, caller)` so a caller never sees a tool they cannot invoke.

On startup, if `--lab-mode` is set, warn — a relaxed security control should be visible where someone will see it.

- [ ] **Step 5: Run the tests and the whole suite**

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release
```

Expected: all pass; a release binary exists.

- [ ] **Step 6: Prove the surface locally over stdio**

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  | ./target/release/rustunifimcp --transport stdio \
      --controllers-file ./packaging/examples/controllers.example.json \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d["result"]["tools"]), "tools"); [print(" ", t["name"]) for t in d["result"]["tools"]]'
```

Expected: 8 tools — the five read primitives and the three admin tools.

- [ ] **Step 7: Commit**

```bash
git add rustunifimcp/
git commit -m "feat: runnable read-only server

CLI adopts the family's flag names from mecmcp docs/PACKAGING.md rather than
inventing better ones. Two tests are guards rather than behaviour: --lab-mode
is CLI-only and defaults off, and no spelling of an insecure-TLS flag parses."
```

### Task 14: Deploy to the rigs — 623 then 622

**Files:**
- Create: `packaging/systemd/rustunifimcp.service`, `.sysusers`, `.tmpfiles`
- Create: `packaging/lxc/install.sh`

**Interfaces:**
- Consumes: the release binary (Task 13).
- Produces: two running rigs, registered as MCP servers.

- [ ] **Step 1: Write the packaging from the sibling's**

```bash
cd ~/Projects/rustproxmoxmcp
cat packaging/systemd/rust-proxmoxmcp.service
cat packaging/lxc/install.sh
```

Copy the hardening block verbatim — `ProtectSystem=strict`, `UMask=0077`, the seccomp filter, the empty `CapabilityBoundingSet`, `ProtectProc=invisible`, and the rest. Two things to carry across deliberately:

- **`UMask=0077` is load-bearing.** `mecmcp`'s fleet-cleanup sprint found audit evidence files landing `0644` on LXC 971 precisely because its unit lacked this line while 950/951/952/960 had it.
- **The `IPAddress*` comment must come across too.** Those directives are accepted by systemd and reported by `systemctl show`, but are **not enforced in an unprivileged LXC** — systemd cannot attach the cgroup BPF program there, and every guest in this fleet is one. Keep the directives, keep the comment, and have the installer probe and print ENFORCED / NOT ENFORCED / NO POLICY / UNKNOWN.

Paths for this server:

```
/etc/unifimcp/controllers.json    0600 root:unifimcp
/etc/unifimcp/api.key             0600 root:unifimcp
/var/lib/unifimcp/tokens.json     0600 unifimcp:unifimcp
/var/lib/unifimcp/audit.jsonl
```

`tokens.json` goes under `/var/lib`, not `/etc` — `/etc/unifimcp` is read-only to the service under `ProtectSystem=strict`, and `mecmcp`'s shared token-path resolver puts the primary there. Getting this wrong is the single most repeated defect in the fleet's backlog (junos#333, sdc#92, mist#42, proxmox#22).

- [ ] **Step 2: Create the two rigs**

```bash
ssh root@pve2.mechub.org
# 623 -- lab mode, the simpler configuration, brought up first
pct create 623 local:vztmpl/debian-13-standard_13.0-1_amd64.tar.zst \
  --hostname test-labmode-unifi \
  --cores 1 --memory 512 --swap 512 \
  --rootfs local-lvm:4 \
  --net0 name=eth0,bridge=vmbr0,firewall=1,ip=192.168.1.243/24,gw=192.168.1.1 \
  --nameserver 192.168.1.1 --searchdomain mechub.org \
  --features nesting=1 --unprivileged 1 --onboot 0 \
  --tags 'disposable;labmode;test' \
  --description 'rustunifimcp disposable rehearsal rig (lab mode). Tests release builds before LXC 981 (production). Safe to destroy.'

# 622 -- two-person
pct create 622 local:vztmpl/debian-13-standard_13.0-1_amd64.tar.zst \
  --hostname test-twoperson-unifi \
  --cores 1 --memory 512 --swap 512 \
  --rootfs local-lvm:4 \
  --net0 name=eth0,bridge=vmbr0,firewall=1,ip=192.168.1.242/24,gw=192.168.1.1 \
  --nameserver 192.168.1.1 --searchdomain mechub.org \
  --features nesting=1 --unprivileged 1 --onboot 0 \
  --tags 'disposable;test;twoperson' \
  --description 'rustunifimcp disposable rehearsal rig (two-person). Tests release builds before LXC 981 (production). Safe to destroy.'

pct start 623 && pct start 622
```

`nesting=1` is not optional — systemd 257 degrades without it, which is why every rig in 610–619 carries it.

- [ ] **Step 3: Add the DNS records**

`test-labmode-unifi.mechub.org → 192.168.1.243` and `test-twoperson-unifi.mechub.org → 192.168.1.242`, wherever the existing `test-labmode-mist.mechub.org` record lives. Verify:

```bash
getent hosts test-labmode-unifi.mechub.org test-twoperson-unifi.mechub.org
```

- [ ] **Step 4: Install and mint a read-only token**

```bash
# on each rig
rustunifimcp token add \
  --tokens-file /var/lib/unifimcp/tokens.json \
  --name readonly \
  --tools '*'
```

`--tools '*'` is read-only by construction. That is the property Task 10 guards, and step 6 proves it end to end.

- [ ] **Step 5: Verify each rig answers**

```bash
curl -sS -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  http://test-labmode-unifi.mechub.org:30033/mcp | python3 -m json.tool | head -40
```

Expected: the eight tools. Then call `unifimcp_status` and confirm it reports the live controller version — that is the first proof the whole stack works against real hardware over verified TLS.

- [ ] **Step 6: Prove the negative**

```bash
# A wildcard token must be refused a write tool. In Phase 2 no write tool is
# registered yet, so assert the shape instead: an unknown tool is refused, and
# tools/list does not contain any name from WRITE_TOOLS.
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"unifi_device_action","arguments":{}}}' \
  http://test-labmode-unifi.mechub.org:30033/mcp
```

Expected: an error, not a result. Record the exact response in the runbook — Task 17 re-runs this once the tool exists, and the two responses must differ in the right way (unknown tool → refused by scope).

- [ ] **Step 7: Register both rigs as MCP servers and commit**

```bash
cd ~/Projects/rustunifimcp
git add packaging/
git commit -m "feat: systemd unit and LXC installer

tokens.json under /var/lib, not /etc: ProtectSystem=strict makes /etc/unifimcp
read-only to the service, and that mismatch is the most repeated defect in the
fleet's backlog. UMask=0077 carried deliberately -- its absence is why 971's
audit evidence landed 0644."
```

**Phase 2 exit:** both rigs answer read queries against the live controller with a bearer token and an audit trail; `tools/list` returns the filtered surface the token permits.

---

## Phase 3 — Operational actions

Four tools. These are operational commands rather than configuration, so they bypass change control — but each is individually scoped and audited, and all four are in `WRITE_TOOLS`.

`unifi_backup_action` carries `trigger | list | download | validate` here. **`restore` is deliberately absent** and lands in Phase 6 as a change set; see Task 26.

### Task 15: Device and station actions

**Files:**
- Create: `rustunifimcp-core/src/tools/ops.rs`
- Modify: `rustunifimcp-core/src/tools/mod.rs`

**Interfaces:**
- Consumes: `UnifiClient` (Task 7), `WRITE_TOOLS` (Task 10).
- Produces: `device_action`, `client_action` handlers and their args enums.

- [ ] **Step 1: Write the failing tests**

```rust
// rustunifimcp-core/src/tools/ops.rs
#[cfg(test)]
mod tests {
    use super::{ClientAction, DeviceAction, DeviceActionArgs};

    #[test]
    fn device_actions_parse_from_their_documented_spellings() {
        for (raw, expected) in [
            ("restart", DeviceAction::Restart),
            ("locate", DeviceAction::Locate),
            ("adopt", DeviceAction::Adopt),
            ("upgrade", DeviceAction::Upgrade),
            ("port_action", DeviceAction::PortAction),
        ] {
            let json = format!(r#""{raw}""#);
            let parsed: DeviceAction = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("{raw}: {e}"));
            assert_eq!(parsed, expected);
        }
    }

    /// An action the server does not implement must be a parse error, not a
    /// request that reaches the controller as an unrecognised command.
    #[test]
    fn an_unknown_device_action_is_refused() {
        let parsed: Result<DeviceAction, _> = serde_json::from_str(r#""factory_reset""#);
        assert!(parsed.is_err());
    }

    #[test]
    fn a_port_action_requires_a_port_index() {
        let raw = r#"{"controller":"home","device":"aa:bb:cc:dd:ee:ff","action":"port_action"}"#;
        let args: DeviceActionArgs = serde_json::from_str(raw).expect("parses");
        assert!(
            args.validate().is_err(),
            "port_action without a port index must be refused before dispatch"
        );
    }

    #[test]
    fn client_actions_parse_from_their_documented_spellings() {
        for raw in ["block", "unblock", "reconnect", "authorize", "limit_bandwidth"] {
            let json = format!(r#""{raw}""#);
            let parsed: Result<ClientAction, _> = serde_json::from_str(&json);
            assert!(parsed.is_ok(), "{raw} must parse");
        }
    }
}
```

- [ ] **Step 2: Run and watch them fail**

```bash
cargo test -p rustunifimcp-core tools::ops::
```

Expected: FAIL — `cannot find type `DeviceAction``.

- [ ] **Step 3: Implement**

```rust
//! Operational actions.
//!
//! These are commands, not configuration, so they do not go through change
//! control. Each is individually scoped and audited, and all four are in
//! [`crate::tools::WRITE_TOOLS`] -- a wildcard token reaches none of them.
//!
//! `unifi_backup_action` deliberately does not carry `restore`. Restoring a
//! controller backup overwrites the entire configuration, which is a larger
//! blast radius than any change set this server will ever carry, so it is a
//! change-set operation instead. See `tools::changeset`.

use schemars::JsonSchema;
use serde::Deserialize;

/// What to do to an adopted device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DeviceAction {
    /// Reboot the device.
    Restart,
    /// Flash the locate LED.
    Locate,
    /// Adopt a pending device into the site.
    Adopt,
    /// Start a firmware upgrade.
    Upgrade,
    /// Act on a single switch port; requires `port_index`.
    PortAction,
}

/// Arguments to `unifi_device_action`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceActionArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// Device MAC address.
    pub device: String,
    /// What to do.
    pub action: DeviceAction,
    /// Which port, for `port_action`.
    #[serde(default)]
    pub port_index: Option<u16>,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
}

impl DeviceActionArgs {
    /// Check the cross-field invariants `serde` cannot express.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::UnifiError::Malformed`] if `port_action` was
    /// requested without a `port_index`.
    pub fn validate(&self) -> Result<(), crate::error::UnifiError> {
        if self.action == DeviceAction::PortAction && self.port_index.is_none() {
            return Err(crate::error::UnifiError::Malformed(
                "action `port_action` requires `port_index`".to_owned(),
            ));
        }
        Ok(())
    }
}
```

Implement `ClientAction` the same way, and both handlers. Every handler calls `validate()` before touching the client.

- [ ] **Step 4: Run the tests**

```bash
cargo test -p rustunifimcp-core tools::ops::
```

Expected: PASS, all four.

- [ ] **Step 5: Commit**

```bash
git add rustunifimcp-core/src/tools/ops.rs rustunifimcp-core/src/tools/mod.rs
git commit -m "feat: device and client operational actions

An unimplemented action is a parse error rather than an unrecognised command
reaching the controller, and cross-field invariants are checked before dispatch
rather than discovered by the API."
```

### Task 16: Backup actions and the speed test

**Files:**
- Modify: `rustunifimcp-core/src/tools/ops.rs`

**Interfaces:**
- Consumes: `UnifiClient` (Task 7), `mecmcp-job`.
- Produces: `BackupAction` (`trigger | list | download | validate`, with no `restore` variant), `BackupActionArgs`, and the `backup_action` and `run_speed_test` handlers. Task 27 imports `BackupActionArgs` to prove `restore` does not parse as an operational action.

**This task answers the open question in the spec:** whether UniFi's asynchronous responses fit `mecmcp_job::poll_until_ready`'s `Probe::Pending` / `Probe::Ready` shape. Find out here, against the live controller, and record the answer.

- [ ] **Step 1: Determine empirically whether these are asynchronous**

```bash
# Against the rig's controller, with the API key.
time curl -sS -X POST -H "X-API-KEY: $UNIFI_API_KEY" \
  https://unifi.mechub.org/proxy/network/api/s/default/cmd/backup \
  -d '{"cmd":"async-backup"}' -H 'Content-Type: application/json'
```

Record whether the response carries a job/task identifier or blocks until done. Do the same for the speed test. **Write the finding into the task's commit message** — the plan asserts nothing here, and the code must follow what the controller actually does.

- [ ] **Step 2: Write the failing test for whichever shape you found**

If asynchronous, test the probe mapping:

```rust
#[cfg(test)]
mod backup_tests {
    use super::probe_backup;
    use mecmcp_job::Probe;

    #[test]
    fn an_in_progress_backup_probes_pending() {
        let raw = serde_json::json!({ "meta": { "rc": "ok" }, "data": [{ "state": "running" }] });
        assert!(matches!(probe_backup(&raw), Ok(Probe::Pending)));
    }

    #[test]
    fn a_finished_backup_probes_ready() {
        let raw = serde_json::json!({
            "meta": { "rc": "ok" },
            "data": [{ "state": "finished", "filename": "backup.unf", "size": 4096 }]
        });
        assert!(matches!(probe_backup(&raw), Ok(Probe::Ready(_))));
    }

    /// mecmcp-job deliberately owns no terminal vocabulary. A controller state
    /// this server does not recognise must be an error, not silently Pending --
    /// silently Pending is how a poll runs to its deadline on a job that failed.
    #[test]
    fn an_unrecognised_state_is_an_error_not_pending() {
        let raw = serde_json::json!({ "meta": { "rc": "ok" }, "data": [{ "state": "wat" }] });
        assert!(probe_backup(&raw).is_err());
    }
}
```

If synchronous, drop `mecmcp-job` from this task, delete it from `rustunifimcp-core/Cargo.toml`, and note in the commit that the crate was evaluated and not needed.

- [ ] **Step 3: Run and watch it fail, then implement, then pass**

```bash
cargo test -p rustunifimcp-core tools::ops::
```

`backup_action` carries `trigger | list | download | validate` only. If someone passes `restore`, it must be a parse error whose message names the change-set path:

```rust
// In BackupAction's docs and in the tool description:
/// `restore` is not available here. Restoring a controller backup overwrites
/// the entire configuration, so it goes through the change-set lifecycle:
/// `unifi_create_change_set` -> `unifi_stage_change` -> `unifi_approve_change_set`
/// -> `unifi_apply_change_set`.
```

- [ ] **Step 4: Update the write-registry test to be strict**

Now that all four operational tools are registered, replace the lenient body from Task 10 step 3:

```rust
#[test]
fn every_write_tool_is_a_registered_tool() {
    for name in WRITE_TOOLS {
        assert!(
            TOOL_NAMES.contains(name),
            "{name} is in WRITE_TOOLS but is not a registered tool; \
             a name with no tool behind it guards nothing"
        );
    }
}
```

Add the four names to `TOOL_NAMES` in `tools/mod.rs`.

- [ ] **Step 5: Run everything**

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: PASS, including the now-strict registry test.

- [ ] **Step 6: Commit**

```bash
git add rustunifimcp-core/src/tools/ops.rs rustunifimcp-core/src/tools/mod.rs rustunifimcp-core/tests/write_tool_registry.rs rustunifimcp-core/Cargo.toml
git commit -m "feat: backup actions and speed test

<Record here what step 1 found: whether UniFi's backup and speed-test
responses are asynchronous, and therefore whether mecmcp-job is used or was
evaluated and dropped.>

backup_action carries no restore: overwriting the whole controller config is a
larger blast radius than any change set, so it goes through approval in Phase 6.
The write-tool registry assertion is now strict."
```

### Task 17: Prove the scope boundary on the rigs

**Files:**
- Modify: `docs/PARITY-AUDIT.md`
- Create: `docs/runbooks/scope-verification.md`

**Interfaces:**
- Consumes: the four ops tools (Tasks 15–16), both rigs (Task 14).
- Produces: recorded evidence that a wildcard token cannot mutate.

**This is the Phase 3 exit criterion and it is a negative result, so it must be observed, not assumed.**

- [ ] **Step 1: Deploy the new build to 623 and 622**

- [ ] **Step 2: Mint two tokens on each rig**

```bash
rustunifimcp token add --tokens-file /var/lib/unifimcp/tokens.json \
  --name readonly --tools '*'

rustunifimcp token add --tokens-file /var/lib/unifimcp/tokens.json \
  --name operator --tools 'unifi_list_resources,unifi_get_resource,unifi_device_action,unifi_client_action'
```

- [ ] **Step 3: Prove the operator token can act**

```bash
curl -sS -H "Authorization: Bearer $OPERATOR_TOKEN" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"unifi_device_action","arguments":{"controller":"home","device":"<a test AP mac>","action":"locate"}}}' \
  http://test-labmode-unifi.mechub.org:30033/mcp
```

Use `locate` rather than `restart` — it flashes an LED and is observable, harmless, and reversible. Confirm the LED actually flashes. Then block and unblock a disposable test client.

- [ ] **Step 4: Prove the wildcard token cannot**

```bash
curl -sS -H "Authorization: Bearer $READONLY_TOKEN" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"unifi_device_action","arguments":{"controller":"home","device":"<same mac>","action":"locate"}}}' \
  http://test-labmode-unifi.mechub.org:30033/mcp
```

Expected: refused. **The LED must not flash.** Watch the device, do not just read the response — a response that says "denied" while the action happened is exactly the failure this test exists to catch.

- [ ] **Step 5: Prove the tool is hidden, not merely refused**

```bash
curl -sS -H "Authorization: Bearer $READONLY_TOKEN" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/list"}' \
  http://test-labmode-unifi.mechub.org:30033/mcp \
  | python3 -c 'import json,sys; names={t["name"] for t in json.load(sys.stdin)["result"]["tools"]}; print(sorted(names)); assert "unifi_device_action" not in names'
```

Expected: the assert passes. A tool a caller cannot invoke should not appear in their list.

- [ ] **Step 6: Record the evidence and commit**

Write `docs/runbooks/scope-verification.md` with the exact commands, the exact responses, and the observation that the LED did not flash. Update `docs/PARITY-AUDIT.md`, moving the ops-related rows from `planned` to `covered`.

```bash
git add docs/runbooks/scope-verification.md docs/PARITY-AUDIT.md
git commit -m "docs: recorded proof that a wildcard token cannot mutate

An operator token flashes the locate LED; a wildcard token does not, and the
tool does not appear in its tools/list at all. Observed on the hardware, not
inferred from the response body."
```

**Phase 3 exit:** an operator token can restart an AP and block a client; a wildcard token provably cannot, with the negative observed on the device.

---

## Phase 4 — Workflows

Five tools, each aggregating many API calls into one answer. These are where the ~24-tool surface earns its keep against ~270: a workflow does in one call what the legacy server needed a dozen for, and the join is server-side rather than orchestrated by a model one tool call at a time.

### Task 18: Site health, topology, and traffic-flow reports

**Files:**
- Create: `rustunifimcp-core/src/tools/workflow.rs`
- Modify: `rustunifimcp-core/src/tools/mod.rs`

**Interfaces:**
- Consumes: `UnifiClient` (Task 7), the model (Task 8), read primitives (Task 11).
- Produces: `site_health_report`, `topology_report`, `traffic_flow_report`.

- [ ] **Step 1: Write the failing tests, fixture-driven**

```rust
// rustunifimcp-core/src/tools/workflow.rs
#[cfg(test)]
mod tests {
    use crate::testing::{DEFAULT_FIXTURE_VERSION, fixture};

    /// The report is a join, and a join that silently drops one side is worse
    /// than no report. Every device in the inventory must appear.
    #[test]
    fn the_health_report_accounts_for_every_device() {
        let devices = fixture(DEFAULT_FIXTURE_VERSION, "devices");
        let health = fixture(DEFAULT_FIXTURE_VERSION, "health");
        let stats = fixture(DEFAULT_FIXTURE_VERSION, "stat_device");

        let report = super::build_site_health(&devices, &health, &stats)
            .expect("report builds from recorded fixtures");

        let device_count = devices["data"].as_array().map_or(0, Vec::len);
        assert_eq!(
            report.devices.len(),
            device_count,
            "the join dropped devices"
        );
    }

    /// A workflow that needs a private surface must say so rather than
    /// returning a partial answer that looks complete.
    #[test]
    fn a_report_missing_a_private_surface_is_marked_partial() {
        let devices = fixture(DEFAULT_FIXTURE_VERSION, "devices");
        let report = super::build_site_health_without_private(&devices)
            .expect("builds");
        assert!(
            report.partial,
            "a report built without the private surfaces must declare itself partial"
        );
        assert!(!report.omitted.is_empty(), "and must name what it omitted");
    }
}
```

- [ ] **Step 2: Run and watch them fail**

```bash
cargo test -p rustunifimcp-core tools::workflow::
```

Expected: FAIL — `cannot find function `build_site_health``.

- [ ] **Step 3: Implement**

Each report struct carries two fields the legacy server had no concept of:

```rust
/// Whether this report is missing data it would normally include.
pub partial: bool,
/// What was omitted and why, one entry per omission.
pub omitted: Vec<String>,
```

A supported-only deployment can build a site health report, but not a complete one — the DPI and flow data live on private surfaces. Saying so is the difference between a smaller answer and a wrong one.

- [ ] **Step 4: Run the tests, then commit**

```bash
cargo test -p rustunifimcp-core tools::workflow::
git add rustunifimcp-core/src/tools/workflow.rs rustunifimcp-core/src/tools/mod.rs
git commit -m "feat: site health, topology and traffic-flow reports

Every report declares whether it is partial and names what it omitted. A
supported-only deployment gets a smaller answer rather than a wrong one."
```

### Task 19: Firewall audit and client troubleshoot

**Files:**
- Modify: `rustunifimcp-core/src/tools/workflow.rs`, `rustunifimcp-core/src/tools/mod.rs`

**Interfaces:**
- Consumes: as Task 18.
- Produces: `firewall_audit`, `client_troubleshoot`.

`unifi_client_troubleshoot` is the one that most justifies the collapsed surface: it correlates a station's association history, signal, DHCP lease, applied firewall policy, and recent flows — a dozen round trips and a join a model should not be orchestrating one call at a time.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod troubleshoot_tests {
    use crate::testing::{DEFAULT_FIXTURE_VERSION, fixture};

    /// The whole point is the correlation. A troubleshoot result that answers
    /// only from the station record is the legacy get_client_details with more
    /// steps.
    #[test]
    fn troubleshoot_correlates_every_source_it_claims_to() {
        let stations = fixture(DEFAULT_FIXTURE_VERSION, "stat_sta");
        let devices = fixture(DEFAULT_FIXTURE_VERSION, "devices");
        let policies = fixture(DEFAULT_FIXTURE_VERSION, "policies");

        let mac = crate::tools::workflow::first_station_mac(&stations)
            .expect("the fixture has at least one station");

        let result = crate::tools::workflow::build_client_troubleshoot(
            &mac, &stations, &devices, &policies,
        )
        .expect("builds");

        assert!(result.association.is_some(), "no association data");
        assert!(result.uplink_device.is_some(), "station not tied to its AP");
        assert!(!result.applied_policies.is_empty(), "no policy correlation");
    }

    /// An audit that finds nothing must be distinguishable from an audit that
    /// did not run.
    #[test]
    fn a_clean_firewall_audit_is_not_an_empty_one() {
        let policies = serde_json::json!({ "data": [] });
        let zones = serde_json::json!({ "data": [] });
        let result = crate::tools::workflow::build_firewall_audit(&policies, &zones)
            .expect("builds");
        assert_eq!(result.policies_examined, 0);
        assert!(result.findings.is_empty());
        assert!(result.ran, "a clean audit still ran");
    }
}
```

- [ ] **Step 2: Run, implement, pass, commit**

```bash
cargo test -p rustunifimcp-core tools::workflow::
git add rustunifimcp-core/src/tools/workflow.rs rustunifimcp-core/src/tools/mod.rs
git commit -m "feat: firewall audit and client troubleshoot

A clean audit and an audit that did not run are different results and are
reported differently. Troubleshoot asserts its correlation rather than
degrading quietly to a station lookup."
```

### Task 20: Verify the workflows on the rigs and close the audit

**Files:**
- Modify: `docs/PARITY-AUDIT.md`

- [ ] **Step 1: Deploy and exercise each workflow against the live controller from both rigs**

- [ ] **Step 2: Compare against the legacy server for the same question**

For each workflow, run the equivalent sequence of legacy tools against 980 and compare the answers. They will not be byte-identical; what matters is that no fact present in the legacy answer is absent from the new one without being listed in `omitted`.

- [ ] **Step 3: Re-run the parity audit and resolve every open gap**

```bash
./scripts/audit-legacy-usage.sh > /tmp/usage.tsv
```

Update `docs/PARITY-AUDIT.md`. **Every row must now be `covered` or `gap (accepted)` with a written reason. A single `gap (open)` blocks Cutover #1.**

- [ ] **Step 4: Commit**

```bash
git add docs/PARITY-AUDIT.md
git commit -m "docs: parity audit closed for cutover #1

Every legacy tool in the audit is covered or is a gap with a written reason.
Change-set-shaped gaps are expected here and close in Phase 6."
```

**Phase 4 exit:** each workflow answers in one call what the legacy server needed a dozen for, verified on both rigs, with the parity audit carrying no open gaps.

---

## Phase 5 — Cutover #1 → 981

981 goes live with read, ops, workflows, and admin. **980 keeps serving configuration writes** until Phase 7.

### Task 21: Create and provision LXC 981

**Files:**
- Create: `docs/runbooks/981-provisioning.md`

- [ ] **Step 1: Create the guest**

```bash
ssh root@pve2.mechub.org
pct create 981 local:vztmpl/debian-13-standard_13.0-1_amd64.tar.zst \
  --hostname prod-unifimcp \
  --cores 2 --memory 1024 --swap 512 \
  --rootfs local-lvm:8 \
  --net0 name=eth0,bridge=vmbr0,firewall=1,ip=192.168.1.216/24,gw=192.168.1.1 \
  --nameserver 192.168.1.1 --searchdomain mechub.org \
  --features nesting=1 --unprivileged 1 --onboot 1 \
  --description 'rustunifimcp production. Replaces the dependency on LXC 980 (enuno/unifi-mcp-server). Snapshot before every release install.'
pct start 981
```

**No `protected` tag yet.** It is applied in Task 28, after Cutover #2 — tagging it now would make the guardrail block the rebuilds Phases 6–7 need.

- [ ] **Step 2: Add DNS and issue the server certificate**

`prod-unifimcp.mechub.org → 192.168.1.216`, then:

```bash
ssh root@pve2.mechub.org
certbot certonly --dns-<provider> -d prod-unifimcp.mechub.org
```

Write the deploy hook `/etc/letsencrypt/renewal-hooks/deploy/prod-unifimcp-lxc981`, modelled on `prod-proxmoxmcp-lxc971`. **Its `VMID` default must be 981** — the fleet has already been bitten by a hook whose VMID drifted from its guest.

- [ ] **Step 3: Install, configure, and snapshot**

```bash
# after install, before first start
ssh root@pve2.mechub.org 'pct snapshot 981 baseline-post-install --description "rustunifimcp first production install"'
```

Every subsequent release install takes a snapshot first. There is no standby host; the snapshot chain is the only complete revert, because backups do not carry snapshots — the fleet learned that when 609's 15-deep chain did not survive a vzdump/restore into 950.

- [ ] **Step 4: Verify over TLS with a real token**

```bash
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"unifimcp_status","arguments":{}}}' \
  https://prod-unifimcp.mechub.org:30033/mcp | python3 -m json.tool
```

Expected: status reports the server version, the pinned mecmcp version, two-person mode **not** lab mode, and the live controller version. No `-k` anywhere.

- [ ] **Step 5: Confirm lab mode is off in production**

```bash
ssh root@pve2.mechub.org 'pct exec 981 -- systemctl cat rustunifimcp.service | grep -c -- --lab-mode'
```

Expected: `0`. If it prints anything else, the unit was copied from a rig — fix it before proceeding.

- [ ] **Step 6: Write the runbook and commit**

### Task 22: Write the migration guide

**Files:**
- Create: `docs/MIGRATING-FROM-UNIFI-MCP.md`

Model it on `rustproxmoxmcp/docs/MIGRATING-FROM-PROXMOX-MCP.md` — read that first. Its section structure is the contract:

- **The behavioural difference that matters** — for UniFi: the legacy server writes configuration on a single unauthenticated call; this one requires a bearer token and, from Phase 6, a governed change set.
- **Tool mapping** — four subsections: *same name, same meaning* · *reached through the change-set flow instead of directly* · *no equivalent, by decision* · *here but not there*
- **Before you cut over**
- **Arguments the new tools take differently**
- **Options the same-named tool no longer takes**
- **Two behaviours that will surprise a 980 caller**

For the last section, the two are:

1. **TLS verification cannot be disabled.** The legacy server ran with `UNIFI_LOCAL_VERIFY_SSL=false`. There is no equivalent flag, by design, and a controller with a self-signed certificate must be given a real one or a PEM trust anchor in `controllers.json`.
2. **A wildcard token is read-only.** `--tools '*'` grants no mutating tool. Every write tool must be named explicitly in the token's scope.

- [ ] **Step 1: Write it, populating the mapping table from `docs/PARITY-AUDIT.md`**
- [ ] **Step 2: Commit**

### Task 23: Cut over

- [ ] **Step 1: Register 981 as an MCP server**

```json
"prod-unifi": { "type": "http", "url": "https://prod-unifimcp.mechub.org:30033/mcp" }
```

- [ ] **Step 2: Rename the legacy registration**

Rename `unifi-mcp` to `unifi-mcp-legacy` in `~/.claude.json`. During Phases 5–7 two servers are registered, and the names must make it unambiguous which one a call reaches.

- [ ] **Step 3: Run the parity audit's `covered` rows against 981**

Every one. Record failures; do not proceed past a failure.

- [ ] **Step 4: Announce the narrowed dependency**

Update `README.md`'s status: 981 serves reads, ops, and workflows; 980 is retained only for configuration writes and backup restore, both landing in Phase 6.

- [ ] **Step 5: Commit**

```bash
git add README.md docs/
git commit -m "docs: cutover #1 -- 981 serves reads, ops and workflows

980's dependency surface is narrowed to configuration writes and backup
restore. The guest is untouched; it is protected and not ours to modify."
```

**Phase 5 exit:** 981 serves the audit's read, ops, and workflow rows under bearer auth over TLS, with every gap named.

---

## Phase 6 — Change control

The seven change-set tools over UniFi's non-atomic REST semantics. This is the part of the family design that does not port, and the tests here matter more than in the sibling servers precisely because apply is not atomic.

**Written before Phase 3 has run.** Task 16 may find that UniFi's asynchronous shape differs from what Task 25 assumes; if so, adjust Task 25 rather than forcing the controller into the plan's assumption.

### Task 24: The transaction and its atomicity declaration

**Files:**
- Create: `rustunifimcp-core/src/changeset/mod.rs`
- Create: `rustunifimcp-core/src/tools/changeset.rs` — **in this task, holding only the `DESCRIPTIONS` constant.** Task 27 adds the handlers to the same file.
- Modify: `rustunifimcp-core/src/lib.rs`, `rustunifimcp-core/src/tools/mod.rs`

**Interfaces:**
- Consumes: `mecmcp-changeset`, `UnifiClient` (Task 7), the Atomicity capability from Task 1.
- Produces:
  - `UnifiTransaction` implementing `DeviceTransaction`, with `UnifiTransaction::atomicity() -> Atomicity`
  - `tools::changeset::DESCRIPTIONS: &[(&str, &str)]` — `(tool name, description)` for all seven change-set tools, written here so the honesty tests below can run before the handlers exist. Task 27 registers handlers against these same names.

- [ ] **Step 1: Check whether Task 1's issue landed**

```bash
gh issue view <NNN> --repo fastrevmd-lab/mecmcp
```

If `Atomicity` shipped in a `mecmcp` release, bump the pin across all five files that carry it and declare the capability. If it did not, implement the declaration locally as a `rustunifimcp` type with a comment pointing at the issue, and **do not** work around its absence by describing UniFi change sets as though they were atomic.

- [ ] **Step 2: Write the failing test**

```rust
// rustunifimcp-core/src/changeset/mod.rs
#[cfg(test)]
mod tests {
    use super::UnifiTransaction;

    /// UniFi promises none of the three. This test exists so that a future
    /// refactor cannot quietly make the server claim otherwise.
    #[test]
    fn unifi_declares_no_atomicity_guarantees() {
        let atomicity = UnifiTransaction::atomicity();
        assert!(!atomicity.atomic_apply);
        assert!(!atomicity.dry_run_validation);
        assert!(!atomicity.guaranteed_rollback);
    }

    /// The design forbids the word outright, because an operator approving a
    /// UniFi change set is not getting commit-confirmed semantics and the model
    /// relaying the request must be able to say so.
    #[test]
    fn no_change_set_tool_description_claims_atomicity() {
        for (name, description) in crate::tools::changeset::DESCRIPTIONS {
            let lowered = description.to_lowercase();
            assert!(
                !lowered.contains("atomic"),
                "{name} description contains 'atomic': {description}"
            );
            assert!(
                !lowered.contains("all-or-nothing"),
                "{name} description implies atomicity: {description}"
            );
        }
    }

    /// And the descriptions must say the true thing, not merely avoid the
    /// false one.
    #[test]
    fn the_apply_description_states_that_partial_failure_is_reachable() {
        let apply = crate::tools::changeset::DESCRIPTIONS
            .iter()
            .find(|(name, _)| *name == "unifi_apply_change_set")
            .expect("apply is registered");
        let lowered = apply.1.to_lowercase();
        assert!(
            lowered.contains("partial"),
            "apply must state that partial failure is a reachable outcome: {}",
            apply.1
        );
    }
}
```

- [ ] **Step 3: Run, implement, pass**

```bash
cargo test -p rustunifimcp-core changeset::
```

The apply description must read approximately:

> Applies the staged changes as a sequence of independent REST calls against live
> configuration. UniFi has no candidate configuration and no commit, so a partial
> failure is a reachable outcome and is recorded as `partial`. Rollback replays a
> stored pre-image and is best-effort; it can itself fail.

- [ ] **Step 4: Commit**

### Task 25: Pre-image, diff, validate

**Files:**
- Create: `rustunifimcp-core/src/changeset/preimage.rs`, `diff.rs`, `validate.rs`

**Interfaces:**
- Consumes: `UnifiClient`, `ResourceKind`, `UnifiTransaction`.
- Produces:
  - `Preimage`, with `Preimage::from_fixture(&serde_json::Value) -> Self` for tests and `capture_preimage(&UnifiClient, &[StagedMutation]) -> Result<Preimage, UnifiError>` for real use
  - `StagedMutation`, with `create(kind, body)`, `update(kind, id, body)`, `delete(kind, id)` and `preview(&self) -> String`. Task 27 adds `StagedMutation::restore(backup_id)`.
  - `diff_against_preimage(&Preimage, &[StagedMutation]) -> Result<Diff, UnifiError>`, where `Diff { computed: bool, changes: Vec<Change> }`
  - `validate_locally(&Preimage, &[StagedMutation]) -> Result<(), UnifiError>` and `check_references(&serde_json::Value, &[StagedMutation]) -> Result<(), UnifiError>`

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use crate::testing::{DEFAULT_FIXTURE_VERSION, fixture};

    /// The pre-image is the only thing standing between a partial apply and an
    /// unrecoverable one. If a staged mutation touches a resource the pre-image
    /// does not cover, the change set must be refused before apply.
    #[test]
    fn a_mutation_outside_the_preimage_is_refused() {
        let preimage = super::Preimage::from_fixture(
            &fixture(DEFAULT_FIXTURE_VERSION, "networkconf"),
        );
        let staged = super::StagedMutation::update("firewall_policy", "abc123", serde_json::json!({}));
        assert!(
            super::validate_locally(&preimage, &[staged]).is_err(),
            "a mutation with no pre-image coverage must not reach apply"
        );
    }

    /// Referential checks are local because no controller-side dry run exists.
    #[test]
    fn a_policy_referencing_an_absent_zone_is_refused() {
        let zones = fixture(DEFAULT_FIXTURE_VERSION, "zones");
        let staged = super::StagedMutation::create(
            "firewall_policy",
            serde_json::json!({ "source": { "zone_id": "does-not-exist" } }),
        );
        assert!(super::check_references(&zones, &[staged]).is_err());
    }

    /// An empty diff is not the same as a diff that was never computed.
    #[test]
    fn a_no_op_change_set_is_distinguishable_from_an_uncomputed_one() {
        let preimage = super::Preimage::from_fixture(
            &fixture(DEFAULT_FIXTURE_VERSION, "networkconf"),
        );
        let diff = super::diff_against_preimage(&preimage, &[]).expect("diffs");
        assert!(diff.computed);
        assert!(diff.changes.is_empty());
    }
}
```

- [ ] **Step 2: Run, implement, pass, commit**

### Task 26: Sequential apply, verify, and best-effort rollback

**Files:**
- Create: `rustunifimcp-core/src/changeset/apply.rs`, `rollback.rs`
- Create: `rustunifimcp-core/tests/changeset_lifecycle.rs`

**Interfaces:**
- Consumes: everything in Tasks 24–25.
- Produces:
  - `apply_sequentially(&UnifiClient, &Preimage, &[StagedMutation]) -> Outcome`
  - `Outcome { state: State, succeeded: Vec<StagedMutation>, failed: Vec<StagedMutation>, attempted_and_failed: Vec<StagedMutation>, never_attempted: Vec<StagedMutation>, rollback_failures: Vec<String> }`
  - `State { Applied, Partial, PartialRollbackFailed, RefusedStale }`
  - `verify_applied`, `rollback_to_preimage`

The test file defines its own `run_change_set(&MockController, Vec<StagedMutation>) -> Outcome` and `five_mutations() -> Vec<StagedMutation>` helpers alongside the `mock` module of step 2. Those are test scaffolding, not crate API.

**This is the highest-risk code in the project.** Partial failure is a reachable state, rollback can itself fail, and both paths must be tested against a mock controller rather than reasoned about.

- [ ] **Step 1: Write the lifecycle tests**

```rust
// rustunifimcp-core/tests/changeset_lifecycle.rs
//! The change-set state machine, including the paths that only exist because
//! UniFi cannot apply atomically.
//!
//! These matter more here than in the sibling servers. Junos and PAN-OS either
//! commit or do not; UniFi can leave three of five mutations applied, and the
//! server has to say so accurately.

mod mock;
use mock::MockController;

#[tokio::test]
async fn a_clean_apply_reports_applied() {
    let controller = MockController::new().succeed_all();
    let outcome = run_change_set(&controller, five_mutations()).await;
    assert_eq!(outcome.state, State::Applied);
    assert_eq!(outcome.succeeded.len(), 5);
    assert!(outcome.failed.is_empty());
}

#[tokio::test]
async fn a_failure_midway_reports_partial_and_names_both_sides() {
    let controller = MockController::new().fail_at(3);
    let outcome = run_change_set(&controller, five_mutations()).await;

    assert_eq!(outcome.state, State::Partial);
    assert_eq!(outcome.succeeded.len(), 2, "the first two landed");
    assert_eq!(outcome.failed.len(), 3, "the third failed and two never ran");
    // The distinction matters to whoever cleans up.
    assert_eq!(outcome.attempted_and_failed.len(), 1);
    assert_eq!(outcome.never_attempted.len(), 2);
}

#[tokio::test]
async fn a_partial_apply_attempts_rollback_of_what_landed() {
    let controller = MockController::new().fail_at(3);
    let outcome = run_change_set(&controller, five_mutations()).await;
    assert_eq!(controller.rollback_calls(), 2, "only what landed is rolled back");
}

/// The path the sibling servers never have to consider.
#[tokio::test]
async fn a_failed_rollback_is_recorded_not_swallowed() {
    let controller = MockController::new().fail_at(3).fail_rollback_at(1);
    let outcome = run_change_set(&controller, five_mutations()).await;

    assert_eq!(outcome.state, State::PartialRollbackFailed);
    assert!(
        !outcome.rollback_failures.is_empty(),
        "a rollback that failed must be reported; this is the state an operator \
         has to be woken for"
    );
}

/// Applying against a controller whose state moved since approval must be
/// refused -- the pre-image is what the approval was bound to.
#[tokio::test]
async fn apply_refuses_when_the_preimage_no_longer_matches() {
    let controller = MockController::new().drift_before_apply();
    let outcome = run_change_set(&controller, five_mutations()).await;
    assert_eq!(outcome.state, State::RefusedStale);
    assert_eq!(controller.write_calls(), 0, "nothing was written");
}
```

- [ ] **Step 2: Run and watch them fail, then build the mock controller**

The mock is a plain in-memory struct with `succeed_all`, `fail_at(n)`, `fail_rollback_at(n)`, `drift_before_apply`, and call counters. It does not need to be an HTTP server.

- [ ] **Step 3: Implement apply and rollback until all five pass**

```bash
cargo test -p rustunifimcp-core --test changeset_lifecycle
```

Note the distinction the second test enforces: `attempted_and_failed` and `never_attempted` are different situations for whoever cleans up, and collapsing them into one `failed` list loses the information that matters most at 03:00.

- [ ] **Step 4: Commit**

```bash
git add rustunifimcp-core/src/changeset/ rustunifimcp-core/tests/changeset_lifecycle.rs
git commit -m "feat: sequential apply, verify, and best-effort rollback

Five lifecycle tests, three of which have no analogue in the sibling servers
because Junos and PAN-OS either commit or do not: partial apply, rollback that
itself fails, and a pre-image that no longer matches at apply time. A mutation
that was attempted and failed is tracked separately from one that never ran."
```

### Task 27: The seven tools, and restore

**Files:**
- Create: `rustunifimcp-core/src/tools/changeset.rs`
- Modify: `rustunifimcp-core/src/tools/mod.rs`, `rustunifimcp-core/tests/write_tool_registry.rs`

**Interfaces:**
- Consumes: Tasks 24–26.
- Produces: the seven change-set tools plus `restore` as a staged operation.

- [ ] **Step 1: Extend the write-registry test first**

```rust
    let mut expected = vec![
        "unifi_backup_action",
        "unifi_client_action",
        "unifi_device_action",
        "unifi_run_speed_test",
        "unifi_create_change_set",
        "unifi_stage_change",
        "unifi_diff_change_set",
        "unifi_validate_change_set",
        "unifi_approve_change_set",
        "unifi_apply_change_set",
        "unifi_get_change_set",
    ];
    expected.sort_unstable();
```

Run it; it fails. That failure is the task's definition of done.

- [ ] **Step 2: Implement the seven tools and register them in both lists**

- [ ] **Step 3: Add restore as a staged operation with its own test**

```rust
#[cfg(test)]
mod restore_tests {
    /// Restore overwrites the entire controller configuration. It is not an
    /// operational action, and there must be no path to it that skips approval.
    #[test]
    fn restore_is_not_reachable_through_backup_action() {
        let raw = r#"{"controller":"home","action":"restore","backup_id":"x"}"#;
        let parsed: Result<crate::tools::ops::BackupActionArgs, _> =
            serde_json::from_str(raw);
        assert!(parsed.is_err(), "restore must not parse as an operational action");
    }

    #[test]
    fn a_staged_restore_declares_its_blast_radius() {
        let staged = crate::changeset::StagedMutation::restore("backup-2026-08-26");
        let rendered = staged.preview();
        let lowered = rendered.to_lowercase();
        assert!(lowered.contains("entire"), "{rendered}");
        assert!(lowered.contains("cannot be undone by rollback"), "{rendered}");
    }
}
```

A restore has no meaningful pre-image — the pre-image would be the whole controller. Say that in the preview rather than capturing something partial and implying it is a safety net.

- [ ] **Step 4: Prove two-person control on 622**

```bash
# Create and stage on 622 (two-person).
# Then attempt apply with the SAME token that created it.
```

Expected: refused. A second principal's approval is required, and the creating token is not it. Then approve with a second token and apply. Record both in `docs/runbooks/scope-verification.md`.

- [ ] **Step 5: Prove lab mode waives it on 623 — and records the waiver**

```bash
curl -sS ... unifi_get_change_set ... | python3 -c '
import json,sys
d = json.load(sys.stdin)
cs = d["result"]["structuredContent"]
assert cs["approver"] is None, cs
assert cs["approval_waiver"] == "lab-mode", cs
print("waiver recorded correctly")'
```

Both fields are required. `approver: null` alone means *both* "nobody has approved this yet" and "approved without review", and an operator or SIEM has to tell those apart. The waiver must never be encoded as a sentinel string inside `approver`.

- [ ] **Step 6: Run everything and commit**

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
git add rustunifimcp-core/src/tools/changeset.rs rustunifimcp-core/src/tools/mod.rs rustunifimcp-core/tests/write_tool_registry.rs
git commit -m "feat: the seven change-set tools, and restore among them

restore does not parse as an operational action -- there is no path to
overwriting the whole controller config that skips approval. Lab mode records
approver: null alongside approval_waiver: lab-mode, because approver: null
alone cannot distinguish 'not yet reviewed' from 'reviewed by nobody'."
```

**Phase 6 exit:** a firewall-policy change is planned, approved by a second principal on 622, applied, and verified; a deliberately induced partial failure is recorded as partial and rolled back, with the rollback's own failure mode tested.

---

## Phase 7 — Cutover #2

### Task 28: Drop the dependency on 980

**Files:**
- Modify: `README.md`, `docs/PARITY-AUDIT.md`, `docs/MIGRATING-FROM-UNIFI-MCP.md`

- [ ] **Step 1: Snapshot 981, then deploy change control**

```bash
ssh root@pve2.mechub.org 'pct snapshot 981 pre-changeset --description "before phase 6 release"'
```

- [ ] **Step 2: Close the parity audit completely**

Re-run `scripts/audit-legacy-usage.sh`. Every row must be `covered` or `gap (accepted)`. The change-set-shaped gaps left open at Cutover #1 close here.

- [ ] **Step 3: Verify the last legacy-only capability on 981**

Configuration writes and backup restore, both through the change-set flow, on production with two-person control. Do the restore verification against a disposable site or a lab controller — **not** the live one.

- [ ] **Step 4: Unregister the legacy server**

Remove `unifi-mcp-legacy` from `~/.claude.json`. This is the actual cutover: the dependency is gone.

- [ ] **Step 5: Tag 981 protected**

```bash
ssh root@pve2.mechub.org 'pct set 981 --tags "protected"'
ssh root@pve2.mechub.org 'pvesh get /cluster/resources --type vm --output-format json' \
  | python3 -c 'import json,sys; print([(g["vmid"],g.get("tags")) for g in json.load(sys.stdin) if g.get("vmid") in (980,981)])'
```

- [ ] **Step 6: Leave 980 alone**

980 stays running and untouched. It is tagged `notmechub;protected` and is not ours to modify. Retirement here means we no longer depend on it. Note in the README that the guest remains as a rollback path and that stopping or destroying it is a separate decision for its owner.

- [ ] **Step 7: Final commit**

```bash
git add README.md docs/
git commit -m "docs: cutover #2 -- the dependency on LXC 980 is dropped

981 serves the full surface under two-person control. The legacy registration
is removed. 980 itself is untouched: it is protected, it remains as a rollback
path, and acting on the guest was never part of retiring the dependency."
```

**Phase 7 exit:** `~/.claude.json` has no `unifi-mcp-legacy` entry; 981 is tagged `protected`; `docs/PARITY-AUDIT.md` has no open gaps; 980 is running and unmodified.

---

## Appendix: verification commands

Run before every commit:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

Run before every deploy to 981:

```bash
# On a rig first. No release reaches production without this.
cargo build --release
# install on 623, then 622, then verify both answer
```

Run the codex gate per commit, per the repo's review convention:

```bash
codex exec review --commit <sha>
```

Review the diff, never the working tree. `--uncommitted` re-reads the whole dirty tree and a wide `--base` span exceeds the review budget. **No verdict is not a pass** — if the run produces no final `agent_message`, exits non-zero, or is killed, say the gate did not run.
