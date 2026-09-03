# CLAUDE.md

Guidance for Claude Code working in this repository.

## Deployment: LXC 981 `prod-unifimcp` must always run with `--lab-mode`

The production instance is **LXC 981 `prod-unifimcp` on pve2**, `192.168.1.216`,
serving `https://prod-unifimcp.mechub.org:30033/mcp`. It is tagged `protected`.

**`--lab-mode` is required on this deployment and must never be dropped.** Without it
the server exposes only its 12 read tools; the 12 write tools stay gated behind a
second-principal approval that does not exist in a single-operator homelab. The
symptom is silent — `unifimcp_status` reports `lab_mode: false` and the write tools
simply are not advertised, so a caller sees a read-only server with no error
explaining why.

This was found on 2026-08-30: 981 was the **only** 900-band MCP container without it.
Its siblings 950 `prod-junosmcp`, 951 `prod-sdcmcp`, 952 `prod-mistmcp`,
960 `prod-panosmcp` and 971 `prod-proxmoxmcp` all had lab mode on. The whole 900 band
is meant to run in lab mode.

The flag lives in a **dedicated drop-in**, matching how 950 does it, so that an
`install.sh` unit rewrite cannot silently drop it:

```
/etc/systemd/system/rustunifimcp.service.d/labmode.conf
```

That drop-in re-declares the full `ExecStart` (blank line first to clear the shipped
one) with `--lab-mode` appended, and sets `Environment=UNIFIMCP_LAB_MODE_MARKER=1` as
a greppable marker.

**After changing it, restart the service and confirm with the `unifimcp_status` tool
that `lab_mode` is `true`.** Two things that will mislead you if you skip that:

- The shipped unit sets `ProtectSystem=strict`, so verify the service actually came
  back rather than assuming the drop-in parsed.
- MCP negotiates its tool list at connect time. After enabling lab mode the write
  tools do **not** appear in an already-connected client — the client must reconnect.
  A session that skips this will conclude the flag did not work.

## Verifying entitlement quickly

`unifimcp_status` returns `tool_count` and `write_tool_count` regardless of mode.
`tool_count: 24, write_tool_count: 12, lab_mode: false` means the writes exist and are
gated, not missing — that distinction is the fastest way to tell a config problem from
a capability gap.

## Upgrading 981 past the change-set store swap

The change-set state file changed shape when this server adopted
`mecmcp-changeset`'s coordinator. 981 writes `/var/lib/unifimcp/changesets.json`, and a
binary from before the swap wrote a bare `{"<id>": {...}}` map; the coordinator writes
`{"version": n, "state": {...}}`.

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
A token minted with `--tools "*"` is granted the 12 read tools and **none of the 12
writes**, even though `token list` displays its TOOLS column as `*`, which reads as
fully permissive. The server then advertises 12 tools over `tools/list` and a caller
sees a read-only server with no error explaining the gap.

**To grant write tools, name every one explicitly** in a comma-separated list. There is
no wildcard that includes them.

Do not mistake this for a lab-mode problem. `--lab-mode` does **not** gate tool
exposure: in `server/mod.rs` it only decides the `approver` / `approval_waiver` fields
recorded on a change set, and the `write_tool_count` in `unifimcp_status` is a static
`WRITE_TOOLS.len()`, not a count of what is exposed. Both flags are needed on a
single-operator deployment, for different reasons — the token scope decides what is
*advertised*, lab mode decides whether an approval can proceed without a second person.

Diagnosing it: probe `tools/list` directly rather than trusting the client. A client
caches its tool list at connect time, so a `/mcp` reconnect that still shows 12 tools is
ambiguous between a stale client and a real server-side gate; the wire answer is not.
