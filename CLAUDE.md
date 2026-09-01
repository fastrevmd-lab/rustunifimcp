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

## Related

Packaging and the installer live in `packaging/`. TLS is terminated by the server
itself (`--tls-cert` / `--tls-key` from `/etc/unifimcp/tls/`), not by a proxy, so a
certbot renewal has to land inside the container.
