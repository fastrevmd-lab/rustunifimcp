# Runbook — UniFi controller certificate

Why this exists: `mecmcp-http` provides **no way to disable TLS verification**
(verified at the pinned tag `v0.20.0` — `danger_accept_invalid` appears nowhere
in the crate family, and `HttpClientConfig` documents "There is **no** API to
disable certificate verification"). The legacy server on LXC 980 runs with
`UNIFI_LOCAL_VERIFY_SSL=false`; `rustunifimcp` has no equivalent and will not be
given one.

So the controller needs a certificate that actually verifies. Until it has one,
**no `rustunifimcp` call to it can succeed** — including the first fixture
capture in Task 4.

## The controller

| | |
|---|---|
| Hardware | UniFi Cloud Key Gen2 Plus (`UCK-G2-Plus`, API `shortname: UCKP`) |
| Name | `UCK G2 Plus <console-name>` |
| MAC | `<console-mac>` |
| Address | `192.168.1.30` — `unifi.mechub.org` already resolves here |
| Front end | nginx, UniFi OS |

## Before state — captured 2026-08-27T01:40:52Z

This is the revert evidence. Keep it.

```
$ echo | openssl s_client -connect 192.168.1.30:443 -servername unifi.mechub.org \
    | openssl x509 -noout -subject -issuer -dates -ext subjectAltName -fingerprint -sha256

subject=CN=unifi.local
issuer=CN=unifi.local
notBefore=Jan  4 05:13:03 2026 GMT
notAfter=Apr  8 05:13:03 2028 GMT
X509v3 Subject Alternative Name:
    DNS:unifi.local, DNS:localhost, DNS:[::1], IP Address:127.0.0.1, IP Address:FE80:0:0:0:0:0:0:1
sha256 Fingerprint=E1:4E:E6:C7:43:DC:28:83:10:D4:79:AD:F8:99:6C:B3:4B:82:7A:ED:50:02:F8:EB:88:A3:07:C4:CF:07:E8:E7
```

Self-signed, and its SAN covers neither `192.168.1.30` nor `unifi.mechub.org`.
Adding it as a trust anchor would therefore *still* fail the name check — which
is why the certificate is replaced rather than pinned.

## DONE — 2026-08-27

Installed and verified. `https://unifi.mechub.org/` returns 200 with full chain
verification (`ssl_verify_result=0`), and the API answers over it:

```
subject=CN=unifi.mechub.org
issuer=C=US, O=Let's Encrypt, CN=YR2
notAfter=Nov 25 01:21:09 2026 GMT
```

All 9 adopted devices stayed ONLINE across both `unifi-core` restarts. The
console is a Cloud Key Gen2 Plus and a separate **Gateway Max** does the
routing, so the console is not in the data path — a restart is a management-
plane blip, not a network outage.

Backups retained on the device at `/data/unifi-core/config/`:
`unifi-core.{crt,key}.pre-acme-20260827T021715Z` (pre-install) and
`...-20260827T135936Z` (taken by the hook on its verification run).

**Certificate type note:** issued RSA-2048 rather than the fleet's usual ECDSA,
matching the key the console already shipped with, to avoid any chance of the
UniFi OS nginx rejecting it. Revisit only with a reason.

### The hook, and how it was tested

`/etc/letsencrypt/renewal-hooks/deploy/unifi-controller`, mode 0755, alongside
the five `prod-*mcp` hooks. It stages beside the live files, checks the hostname
and that cert and key are a pair *before* swapping, backs up, installs,
restarts, verifies with no `-k`, and rolls back if verification fails.

Three paths were exercised, not assumed:

| Test | Result |
|---|---|
| Unreachable console (the firmware-wipe case) | exit 1, named reason naming the fix |
| A different lineage (`prod-proxmoxmcp`) | exit 0, nothing touched |
| Real lineage, end to end | exit 0, "installed and verified", 9/9 devices ONLINE |

### Original blocker, for the record — SSH was disabled

```
$ ssh root@192.168.1.30
ssh: connect to host 192.168.1.30 port 22: Connection refused
```

UniFi OS ships with SSH off. Installing a certificate on this hardware means
writing `/data/unifi-core/config/unifi-core.crt` and `unifi-core.key`, then
restarting `unifi-core`. There is no supported API upload path on a Cloud Key.

**A one-time upload through the UniFi UI does not resolve this.** Let's Encrypt
renews every 90 days and the deploy hook must run non-interactively, so SSH is
required regardless of how the first install happens.

**Resolved:** SSH enabled in the UniFi OS UI. That screen offers only a password
on this firmware, so pve2's root key was installed with `ssh-copy-id
root@192.168.1.30` and the hook authenticates by key.

**Known maintenance step:** a UniFi OS firmware update can clear
`/root/.ssh/authorized_keys`. The hook fails loudly with the fix in its message
when that happens — re-run `ssh-copy-id root@192.168.1.30` from pve2.

## What is already ready

- `certbot` on pve2, authenticator `dns-cloudflare`, credentials
  `/etc/letsencrypt/cloudflare.ini`, ECDSA keys, ACME v02.
- `unifi.mechub.org` already resolves to `192.168.1.30` in Cloudflare DNS, so no
  new record is needed for the controller itself.
- Five sibling deploy hooks to model on, newest is
  `/etc/letsencrypt/renewal-hooks/deploy/prod-proxmoxmcp-lxc971`.

Issuance is unblocked. Only installation is blocked.

## Procedure (once SSH is on)

1. **Back up.** Take a UniFi controller backup through the UI, and copy the
   existing `unifi-core.crt` / `unifi-core.key` aside on the device. Do not skip
   this — the revert path depends on it.
2. **Issue:**
   ```sh
   ssh root@pve2.mechub.org
   certbot certonly --dns-cloudflare \
     --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
     --dns-cloudflare-propagation-seconds 30 \
     --key-type ecdsa -d unifi.mechub.org
   ```
3. **Install** `fullchain.pem` → `/data/unifi-core/config/unifi-core.crt` and
   `privkey.pem` → `/data/unifi-core/config/unifi-core.key` (0600), then
   `systemctl restart unifi-core`.
4. **Write the deploy hook** at
   `/etc/letsencrypt/renewal-hooks/deploy/unifi-controller`, `chmod 0755`,
   modelled on `prod-proxmoxmcp-lxc971`. Carry over its three good habits: gate
   on `RENEWED_LINEAGE` so it ignores other renewals, verify the cert matches the
   hostname with `openssl x509 -checkhost`, and refuse a cert/key that are not a
   pair by comparing public-key digests. It pushes over SSH rather than
   `pct exec`, since the target is an appliance, not an LXC.
5. **Verify — the gate.** No `-k` anywhere:
   ```sh
   echo | openssl s_client -connect unifi.mechub.org:443 -servername unifi.mechub.org \
     | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
   curl -sS -o /dev/null -w '%{http_code}\n' https://unifi.mechub.org/
   ```
   Expect `subject=CN=unifi.mechub.org`, a real issuer, `DNS:unifi.mechub.org`
   in the SAN, and `200`. A TLS error here means the phase is not done — do not
   proceed to Task 4.
6. **Confirm the API key still works over the new certificate:**
   ```sh
   curl -sS -H "X-API-KEY: $UNIFI_API_KEY" \
     https://unifi.mechub.org/proxy/network/integration/v1/sites | head -c 400
   ```
7. **Prove the hook fires:**
   `certbot renew --force-renewal --cert-name unifi.mechub.org`, then repeat
   step 5.

## Revert

Restore the saved `unifi-core.crt` / `unifi-core.key`, `systemctl restart
unifi-core`, and confirm the SHA-256 fingerprint matches the before state above.

## Why a hook rather than a one-off install

UniFi regenerates its self-signed certificate on some firmware upgrades. Without
a hook, a controller upgrade silently reverts this work and every
`rustunifimcp` call starts failing TLS verification with no obvious cause.
