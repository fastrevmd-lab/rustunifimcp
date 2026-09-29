# CLAUDE.md

Guidance for Claude Code working in this repository.

## Deployment: `rustunifimcp`'s own production runs two-person control, not `--lab-mode`

This project's production instance (LXC 981 `prod-unifimcp`, see `README.md`) runs
**without** `--lab-mode`, under two-person control: the token that stages a change
set cannot also approve it, and approval requires a distinct `actor_type: human`
token. `--lab-mode` **waives that second-principal requirement** — it is for
single-operator rigs and test instances only (see `docs/HOW-TO-SETUP-LXC.md`, LXC
623 `test-labmode-unifi`), never for a production deployment whose whole point is
governed, audited change control.

**Do not add `--lab-mode` to a production instance.** Doing so silently waives the
approval gate this server exists to enforce, and the symptom is easy to miss:
`unifimcp_status` still reports `tool_count`/`write_tool_count` unchanged, and the
only visible difference is `lab_mode: true` and self-approval succeeding where it
should be refused.

If you are instead standing up a **single-operator lab rig** that intentionally
wants `--lab-mode`, the flag should live in a **dedicated drop-in** so an
`install.sh` unit rewrite cannot silently drop it:

```
/etc/systemd/system/rustunifimcp.service.d/labmode.conf
```

That drop-in re-declares the full `ExecStart` (blank line first to clear the shipped
one) with `--lab-mode` appended, and sets `Environment=UNIFIMCP_LAB_MODE_MARKER=1` as
a greppable marker.

**After changing it, restart the service and confirm with the `unifimcp_status` tool
that `lab_mode` matches what you intended.** Two things that will mislead you if you
skip that:

- The shipped unit sets `ProtectSystem=strict`, so verify the service actually came
  back rather than assuming the drop-in parsed.
- MCP negotiates its tool list at connect time. Enabling or disabling lab mode does
  **not** change what an already-connected client sees — the client must reconnect.
  A session that skips this will draw the wrong conclusion about whether the flag
  took effect.

## Verifying entitlement quickly

`unifimcp_status` returns `tool_count` and `write_tool_count` regardless of mode.
`tool_count: 21, write_tool_count: 10, lab_mode: false` means the writes exist and are
gated behind two-person approval, not missing — that distinction is the fastest way
to tell a config problem from a capability gap. `lab_mode: true` on a production
instance is itself the problem: see the section above.

## Upgrading past the change-set store swap

The change-set state file changed shape when this server adopted
`mecmcp-changeset`'s coordinator. The server writes `/var/lib/unifimcp/changesets.json`,
and a binary from before the swap wrote a bare `{"<id>": {...}}` map; the coordinator
writes `{"version": n, "state": {...}}`.

**The new binary refuses to start on the old file** and names the change sets in it.
That is deliberate — not a bug to work around. Move the file aside and re-plan. The
approvals cannot come across: an approval now binds to the digest of the preview its
approver read, and the old records have no preview, so synthesising one would mint an
approval over text nobody saw.

Two things that will look like unrelated faults:

- The coordinator reads the file through the workspace's hardened reader, so a group- or
  world-readable file is a startup failure. The message carries the `chmod`. The old
  store wrote 0600 but never required it, so a file touched by hand may not be.
- Change-set ids are now 64 hex characters. A saved `cs-<uuid>` from before the swap is
  refused by the id validator, not merely "not found".

## Related

Packaging and the installer live in `packaging/`. TLS is terminated by the server
itself (`--tls-cert` / `--tls-key` from `/etc/unifimcp/tls/`), not by a proxy, so a
certbot renewal has to land inside the container.

## `--tools "*"` means READ-ONLY, not "all tools"

This is the single most misleading thing about deploying this server, and it cost a
session on 2026-08-30.

`rustunifimcp token add --tools` documents `*` as *"or '*' for read-only tools only"*.
A token minted with `--tools "*"` is granted the 11 read tools and **none of the 10
writes**, even though `token list` displays its TOOLS column as `*`, which reads as
fully permissive. The server then advertises 11 tools over `tools/list` and a caller
sees a read-only server with no error explaining the gap.

**To grant write tools, name every one explicitly** in a comma-separated list. There is
no wildcard that includes them.

Do not mistake this for a lab-mode problem. `--lab-mode` does **not** gate tool
exposure: in `server/mod.rs` it only decides the `approver` / `approval_waiver` fields
recorded on a change set, and the `write_tool_count` in `unifimcp_status` is a static
`WRITE_TOOLS.len()`, not a count of what is exposed. Both flags are needed on a
single-operator deployment, for different reasons — the token scope decides what is
*advertised*, lab mode decides whether an approval can proceed without a second person.
Two-person control is also enforced on the token itself (MEC-503): a token combining
`unifi_stage_change` and `unifi_approve_change_set` is refused at issuance unless minted
with `--allow-self-approval`, and refused at call time unless the server runs with
`--lab-mode`. A single-operator lab deployment needs both: the flag at issuance and
`--lab-mode` on the server.

Diagnosing it: probe `tools/list` directly rather than trusting the client. A client
caches its tool list at connect time, so a `/mcp` reconnect that still shows 11 tools is
ambiguous between a stale client and a real server-side gate; the wire answer is not.
