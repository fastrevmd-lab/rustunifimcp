# How to set up a rustunifimcp LXC from scratch

Builds one Proxmox LXC running `rustunifimcp`, in either **lab mode** or
**two-person** mode. Written from a rebuild performed on 2026-09-07, not from
memory: every command here was run.

Two rigs are normally built as a pair, because they test different things:

| mode | approvals | use it for |
|---|---|---|
| **lab mode** (`--lab-mode`) | waived on creation, recorded as `approval_waiver=lab-mode` | ordinary tool work, reads, single-operator change sets |
| **two-person** (no flag) | a second principal must approve before apply | anything that must prove the approval gate holds |

Never point a lab-mode server at production controllers. It says so itself at
startup, in a `WARN`.

## 0. Before you start

You need:

- A Proxmox node, a container template, and a free VMID and IP.
- **The credentials the server will use.** A bearer token for the UniFi
  controller, a `controllers.json` inventory describing which controller(s)
  this server fronts, and MCP bearer tokens for client authentication.
  Building the container is the easy part; these are the part you cannot
  regenerate. If you are rebuilding an existing rig, back them up first — see
  [Rebuilding](#rebuilding-an-existing-rig).

Check the template is present:

```bash
pveam list local | grep debian-13
# local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst
```

## 1. Get a binary that will actually run

**Do not `cargo build --release` on your workstation and copy the binary in.**
glibc is forward-incompatible: a binary linked against a newer glibc will not
start on an older one, and it fails at service start with a loader error *after*
the old binary has been replaced — an outage, not a build failure.

Take the binary from the release image, which CI builds against the right glibc:

```bash
docker create --name ux ghcr.io/fastrevmd-lab/rustunifimcp:0.3.2
docker cp ux:/usr/local/bin/rustunifimcp ./rustunifimcp
docker rm ux
```

No docker? `skopeo copy docker://ghcr.io/fastrevmd-lab/rustunifimcp:0.3.2 dir:/tmp/img`
then find the layer containing `usr/local/bin/rustunifimcp` and untar it.

## 2. Assemble the install package

**This repo has no package-building script.** It is hand-assembled — a gap
compared to `rustjunosmcp`, which ships `scripts/package-lxc.sh` with
`JMCP_PACKAGE_SKIP_BUILD=1`.

The package is a tarball with this layout, with the binary at the root:

```
rustunifimcp
packaging/systemd/rustunifimcp.service
packaging/systemd/rustunifimcp.sysusers
packaging/systemd/rustunifimcp.tmpfiles
packaging/examples/controllers.example.json
packaging/lxc/install.sh
```

Build it with:

```bash
cd /path/to/rustunifimcp
mkdir -p /tmp/pkg-stage
cp rustunifimcp /tmp/pkg-stage/
cp -r packaging /tmp/pkg-stage/
tar czf rustunifimcp_0.3.2.tar.gz -C /tmp/pkg-stage .
```

The files land at the extraction root. The installer is `#!/bin/sh` and may not
be executable in the archive, so invoke it as `sh packaging/lxc/install.sh`.

## 3. Create the container

`nesting=1` is **required**. systemd 257 degrades badly in an unprivileged LXC
without it.

```bash
pct create 622 local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst \
    --hostname test-twoperson-unifi \
    --cores 1 --memory 512 --swap 512 \
    --rootfs local-lvm:4 \
    --unprivileged 1 --features nesting=1 \
    --net0 name=eth0,bridge=vmbr0,firewall=1,gw=192.0.2.1,ip=192.0.2.10/24,type=veth \
    --onboot 0 --ostype debian \
    --tags "disposable;test;twoperson"

pct start 622
```

512 MB and one core is enough. The tags matter: `disposable` is what marks a
guest as safe to destroy, and the fleet's own safety rules key on it.

## 4. Install

```bash
pct push 622 rustunifimcp_0.3.2.tar.gz /tmp/pkg.tar.gz
pct exec 622 -- bash -lc 'cd /tmp && tar xzf pkg.tar.gz && sh packaging/lxc/install.sh'
```

`install.sh` creates the `unifimcp` service user, installs the binary and the
unit, and stops there. **The service will not start yet** — it has no
credentials, and it says so.

## 5. Configuration and credentials

Place the controller inventory, the controller API key, and the MCP token store:

```bash
pct push 622 controllers.json   /etc/unifimcp/controllers.json
pct push 622 api.key             /etc/unifimcp/api.key
pct push 622 tokens.json         /var/lib/unifimcp/tokens.json
```

Then fix ownership and modes. **Do this for every credential file at once.** The
server refuses to start on any file that is group- or world-readable, and it
checks them one at a time — so getting this wrong costs you one restart per file:

```bash
pct exec 622 -- bash -lc '
    chown -R unifimcp:unifimcp /etc/unifimcp
    chmod 0600 /etc/unifimcp/controllers.json
    chmod 0600 /etc/unifimcp/api.key
    chown unifimcp:unifimcp /var/lib/unifimcp/tokens.json
    chmod 0600 /var/lib/unifimcp/tokens.json
'
```

## 6. The site drop-in — THIS IS CRITICAL

**The shipped unit is a TEMPLATE.** It contains `@UNIFIMCP_BIND_HOST@`-style
placeholders that `install.sh` substitutes at install time. Two consequences,
both learned the hard way:

1. **Never drop the raw shipped unit onto a configured guest.** Doing exactly
   that on 2026-09-05 killed a rig with `Fatal: invalid socket address syntax`,
   because the literal `@UNIFIMCP_BIND_HOST@` reached the server as a bind address.
   Verify after install with:
   ```bash
   systemctl cat rustunifimcp.service | grep -c '@[A-Z_]*@'
   ```
   which must be **`0`**.

2. **Never restore an old backup unit wholesale either.** Units predating
   v0.3.2 have no `SystemCallErrorNumber`, so restoring one silently reverts
   the SIGSYS fix — the service still runs and looks healthy, and a denied
   syscall kills it mid-request. Keep the newly installed v0.3.2 unit and put
   site configuration in a drop-in.

`install.sh` does **not** create the drop-in directory:

```bash
pct exec 622 -- mkdir -p /etc/systemd/system/rustunifimcp.service.d
```

`/etc/systemd/system/rustunifimcp.service.d/override.conf`:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/rustunifimcp \
    --controller-mapping /etc/unifimcp/controllers.json \
    --controller-token-file /etc/unifimcp/api.key \
    --transport streamable-http \
    --host 0.0.0.0 \
    --port 30033 \
    --tokens-file /var/lib/unifimcp/tokens.json \
    --allow-insecure-bind \
    --allowed-host 192.0.2.10 \
    --allowed-host test-twoperson-unifi:30033 \
    --allowed-origin https://console.example.org \
    --audit-format json \
    --audit-log-file /var/lib/unifimcp/audit.jsonl \
    --audit-journald
```

The empty `ExecStart=` is required: it clears the shipped one before setting a
new one. **Otherwise both accumulate.**

**Lab mode versus two-person** is the same file with `--lab-mode` added. That
single flag is the whole difference. Note that the shipped template defaults to
**TLS** (`--tls-cert`/`--tls-key` and `https://` origins) while the lab rigs
run plain HTTP with `--allow-insecure-bind` — that mismatch is precisely why
the drop-in exists rather than editing the base unit.

Point `--allowed-host` at that rig's own address — it must track whatever
clients actually dial, or requests are refused with 421.

**`--allowed-origin` is different:** it lists trusted **browser application
origins** that call this server (the `Origin:` header), not the server address
itself. A browser console hosted at `https://console.example.org` sends
`Origin: https://console.example.org`, so that is the value to allow. The two
lists are configured independently and usually contain different values.
**Non-browser clients** (curl, CLI MCP clients) send no `Origin` header and are
unaffected by the allowlist.

An off-loopback listener (`--host 0.0.0.0` or a LAN address) requires at least
one `--allowed-origin` to start, even if no browser clients will call it — use
an example value like `https://console.example.org` to satisfy the requirement.

Then:

```bash
pct exec 622 -- systemctl daemon-reload
pct exec 622 -- systemctl enable --now rustunifimcp.service
```

## 7. Mint a token

```bash
pct exec 622 -- runuser -u unifimcp -- /usr/local/bin/rustunifimcp token add \
    --tokens-file /var/lib/unifimcp/tokens.json \
    --name my-client --controllers '*' --tools '*'
```

The secret is printed **once** and stored hashed. Two things worth knowing:

- A running server holds its token store in memory. A newly minted or revoked
  token does nothing until the server is signalled:
  `systemctl kill -s HUP rustunifimcp.service`. The CLI warns you about this.
- `--tools '*'` is a wildcard that resolves to *read-only tools only*. Write
  tools must be named explicitly, so a wildcard token calling
  `create_unifi_change_set` gets `insufficient_scope`. That is deliberate.

## 8. Verify

Check the four things that actually matter:

```bash
# 1. it is running the version you think
pct exec 622 -- /usr/local/bin/rustunifimcp --version

# 2. the seccomp posture comes from the SHIPPED unit, not a local patch
pct exec 622 -- systemctl show rustunifimcp.service -p SystemCallErrorNumber --value   # 1 (EPERM)
pct exec 622 -- grep -l SystemCallErrorNumber /etc/systemd/system/rustunifimcp.service

# 3. the filter is actually installed, read from the kernel rather than systemd
pid=$(pct exec 622 -- systemctl show -p MainPID --value rustunifimcp.service)
pct exec 622 -- grep -E '^Seccomp' /proc/$pid/status                                    # Seccomp: 2

# 4. it is serving, and refusing unauthenticated callers
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://192.0.2.10:30033/mcp \
     -H 'content-type: application/json' -d '{}'                                        # 401
```

`401` is the success case here: the transport is up and authentication is being
enforced. A `000` means nothing is listening on that address or port.

Checking `SystemCallErrorNumber` matters. On 2026-09-05 a denied `chown`
(kernel audit `sig=31 syscall=92`) killed this server mid-request during a
change-set approval write — the client saw an empty reply, systemd restarted
it, and the approval was lost. v0.3.2 is the release that adds the directive,
and this check is how an operator proves it is present. Without it, a denied
syscall raises SIGSYS and kills the process mid-request instead of returning
`EPERM`.

The installer reports `egress filter: NOT ENFORCED` in unprivileged LXC.
Expected and true — mention it here so nobody reads it as a fault.
`IPAddressDeny=any` is accepted, reported by `systemctl show`, and not enforced
in unprivileged containers.

Reading `Seccomp:` from `/proc/<pid>/status` is how you know the filter is in
force, because a directive can be present in a unit and enforce nothing.

## 9. Stop the rig

Test rigs in this fleet are stopped by default; started only when needed,
stopped again at completion:

```bash
pct shutdown 622  # shutdown, not stop — stop kills mid-write, shutdown flushes change-set state
```

## Rebuilding an existing rig

Back the credentials out **before** destroying anything. `pct mount` reads a
stopped container's filesystem without starting it:

```bash
pct mount 622
cp -a /var/lib/lxc/622/rootfs/etc/unifimcp        /root/backup-622/
cp -a /var/lib/lxc/622/rootfs/var/lib/unifimcp    /root/backup-622/
cp -a /var/lib/lxc/622/rootfs/etc/systemd/system/rustunifimcp.service.d /root/backup-622/
pct config 622 > /root/backup-622/pct-config.txt
pct unmount 622
```

`pct-config.txt` is worth keeping: it is the network, resources and tags you will
want to reproduce.

Restoring `tokens.json` rather than minting fresh tokens keeps existing clients
working — the secrets are hashed and cannot be recovered, so re-minting means
reconfiguring every client that talks to this rig.

**Restore only the credentials and the drop-in, never the old base unit.** Units
predating v0.3.2 have no `SystemCallErrorNumber`, so restoring one silently
reverts the SIGSYS fix.

## Troubleshooting

**`mode 0644 is group- or world-accessible (owner uid 999, this process uid 999); run: chmod 600 /etc/unifimcp/controllers.json`**
A credential file is too permissive. The message names the file and the exact
fix. It is checked per file, so fix them all at once (step 5) or you will meet
this again for the next one.

**`failed to create file: /etc/systemd/system/rustunifimcp.service.d/override.conf: No such file or directory`**
The drop-in directory does not exist yet. `install.sh` does not create it,
because a drop-in is a site decision. `mkdir -p` it first.

**Service active but every call returns 421** — `--allowed-host` does not match
the address clients dial. Add the exact host and port they use.

**Browser client calls return 403 with `"Origin '<origin>' is not allowed"`** —
the calling browser page's origin is not in the `--allowed-origin` list. Add the
origin of the browser application making the call (e.g.,
`https://console.example.org`). Non-browser clients (curl, CLI) send no `Origin`
header and are unaffected.

**Service fails to start with `"requires at least one --allowed-origin"`** — an
off-loopback listener (`--host 0.0.0.0` or a LAN address) has no
`--allowed-origin`. Add at least one browser application origin (e.g.,
`https://console.example.org`), even if no browser clients will call it.

**`Fatal: invalid socket address syntax`** — the shipped unit's placeholders
were not substituted. Verify `systemctl cat rustunifimcp.service | grep -c '@[A-Z_]*@'`
is `0`. If not, the unit is still templated. Re-run `install.sh` or manually
substitute the placeholders.
