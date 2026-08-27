# UniFi Controller Fixtures

This directory contains JSON fixtures captured from live UniFi controllers for
testing endpoint compatibility across controller versions.

## Directory Structure

Each subdirectory is named by controller version (e.g., `10.5.67/`), containing
JSON responses from the capture endpoints defined in
`scripts/capture-fixtures.sh`.

## Capturing a New Controller Version

Run `scripts/capture-fixtures.sh` with environment variables:

```sh
UNIFI_API_KEY="..." CONTROLLER="https://..." ./scripts/capture-fixtures.sh
```

The script captures all endpoints into `tests/fixtures/<version>/` and
**automatically verifies the output is scrubbed** before completing.

## Scrubbing Requirements

Fixture files **must not contain**:

1. **Credential-shaped values** — fields matching `pass`, `psk`, `secret`,
   `token`, `key`, `cred`, `auth`, `hash`, `salt`, `priv`, or `cert` (case-
   insensitive) must hold only accepted placeholders: values containing
   `REDACT`, `EXAMPLE`, matching `^[A0]+=?$`, or starting with `SHA256:0000`.

2. **High-entropy values** — any base64-like string 32+ characters
   (`[A-Za-z0-9+/]{32,}={0,2}`) that is not a structural UniFi identifier
   (`_id`, `site_id`, `device_id`, etc.) or an accepted placeholder.

3. **Public IP addresses** — IPv4 and IPv6 addresses that are globally
   routable, except:
   - Documentation ranges: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
     `2001:db8::/32`
   - Well-known public resolvers: Cloudflare (`1.1.1.1`, `1.0.0.1`, `1.0.0.2`,
     `2606:4700::/32`), Google (`8.8.8.8`, `8.8.4.4`), Quad9 (`9.9.9.9`)
   - Any IP address inside `policies.json` (contains legitimate firewall rules
     for public CDN/DNS ranges)

4. **Non-zero geographic coordinates** — `lat`, `latitude`, `lng`, or
   `longitude` fields with values other than `0.0`.

5. **Denied identifiers** — any substring match (case-insensitive) against
   entries in `scripts/fixture-denylist.txt`. **Before capturing a new
   controller version**, add any personal or site-specific identifiers to this
   file.

## Verification Gate

`scripts/verify-fixtures-scrubbed.sh <fixture-dir>` scans all JSON files in the
directory and exits non-zero if it finds any of the above violations.

The gate reports:
- File path and field path for each violation
- Redacted locators (field name, value length, never the value itself)
- Summary on success: files scanned, values checked, violations found

An empty fixture directory is an error — the gate must scan actual files to
report success.

## Adding a New Controller Version Safely

1. **Update the denylist first** — append any personal or site-specific
   identifiers (SSID names, surnames, site names) to
   `scripts/fixture-denylist.txt`.

2. **Run the capture** — `scripts/capture-fixtures.sh` will invoke the
   verification gate automatically at the end.

3. **If the gate fails** — the script exits non-zero and prints each violation.
   Scrub the offending fields manually and re-run the gate until it passes.

4. **Commit only after the gate passes** — a passing gate is not proof the
   fixtures are safe (the denylist could be incomplete), but a failing gate is
   proof they are not.

## Manual Scrubbing

If you need to scrub fixtures manually:

1. Replace credential values with `"REDACTED"` or `"AAAA"`.
2. Replace public IPs with documentation range addresses.
3. Set geographic coordinates to `0.0`.
4. Replace personal identifiers with generic placeholders like `"home"`,
   `"user1"`, `"device-a"`.

Then re-run the gate to verify:

```sh
./scripts/verify-fixtures-scrubbed.sh rustunifimcp-core/tests/fixtures/10.5.67
```

## Why This Matters

Fixture scrubbing failures discovered across four fix rounds:

- **Round 1**: MACs, `x_passphrase`
- **Round 2**: Real SSIDs, surname, WAN IPv4 hidden in CIDR notation
- **Round 3**: Owner's Comcast IPv6 prefix (201 occurrences), family names (43),
  **home GPS coordinates**
- **Round 4**: **Live cryptographic material** — WireGuard private key,
  RADIUS shared secret, device inform keys, guest tokens (58 values, 5 files)

The root cause was checking only hand-picked field names rather than
enumerating what was actually present. This gate makes the check mechanical.
