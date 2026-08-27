#!/usr/bin/env python3
"""Verify that fixture files contain no sensitive data.

Scans JSON fixtures for credential-shaped fields, high-entropy values,
public IP addresses, non-zero coordinates, MAC addresses, and identifiers
from a denylist.

Exit codes:
    0  all fixtures clean
    1  sensitive data found or fixture directory empty
    2  usage error
"""

import hashlib
import ipaddress
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

# Credential-shaped field name patterns (case-insensitive)
CREDENTIAL_PATTERN = re.compile(
    r'(?:pass|psk|secret|token|key|cred|auth|hash|salt|priv|cert)',
    re.IGNORECASE
)

# High-entropy value pattern: base64-like strings 32+ chars
HIGH_ENTROPY_PATTERN = re.compile(r'^[A-Za-z0-9+/]{32,}={0,2}$')

# MAC address pattern (various formats including bare 12-hex)
MAC_PATTERN = re.compile(
    r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$|'  # aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff
    r'^([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4})$|'     # aabb.ccdd.eeff
    r'^[0-9A-Fa-f]{12}$'                             # aabbccddeeff (bare)
)

# Accepted credential placeholder patterns
PLACEHOLDER_PATTERNS = [
    re.compile(r'REDACT', re.IGNORECASE),
    re.compile(r'EXAMPLE', re.IGNORECASE),
    re.compile(r'^[A0]+=?$'),
    re.compile(r'^SHA256:0000'),
]

# UniFi structural identifiers (allow high-entropy exceptions)
STRUCTURAL_ID_KEYS = {
    '_id', 'site_id', 'device_id', 'anon_client_id',
    'network_id', 'user_id', 'usergroup_id', 'group_id',
    'wlan_id', 'wlangroup_id', 'mac', 'oui',
}

# Fields exempt from MAC validation (bare 12-hex that aren't MACs)
# Device serial numbers happen to be 12 hex chars, same format as bare MACs
MAC_EXEMPTION_KEYS = {'serial'}

# Documentation IP ranges to allow
DOC_IPV4_RANGES = [
    ipaddress.ip_network('192.0.2.0/24'),
    ipaddress.ip_network('198.51.100.0/24'),
    ipaddress.ip_network('203.0.113.0/24'),
]
DOC_IPV6_RANGES = [
    ipaddress.ip_network('2001:db8::/32'),
]

# Well-known public resolvers to allow
ALLOWED_PUBLIC_IPS = {
    '1.1.1.1', '1.1.1.2', '1.0.0.1', '1.0.0.2',  # Cloudflare
    '8.8.8.8', '8.8.4.4',                        # Google
    '9.9.9.9',                                   # Quad9
}
ALLOWED_PUBLIC_PREFIXES = [
    ipaddress.ip_network('2606:4700::/32'),  # Cloudflare
]

# Special structural networks to allow (default routes, etc.)
STRUCTURAL_NETWORKS = {
    '::/0',      # IPv6 default route
    '0.0.0.0/0', # IPv4 default route
}

# MAC address ranges to allow (documentation/synthetic)
ALLOWED_MAC_PREFIXES = [
    '02:00:',  # Locally administered
    '00:00:5e:',  # Documentation range
]

# Geographic coordinate field names
GEO_COORD_KEYS = {'lat', 'latitude', 'lng', 'longitude'}

# DHCPv6 suffix-only field names (contain IPv6 host parts, not full addresses)
DHCPV6_SUFFIX_KEYS = {
    'dhcpdv6_start', 'dhcpdv6_stop',
    'ipv6_pd_start', 'ipv6_pd_stop',
}


def is_placeholder(value: str) -> bool:
    """Check if value matches an accepted credential placeholder."""
    return any(p.search(value) for p in PLACEHOLDER_PATTERNS)


def is_allowed_mac(mac: str) -> bool:
    """Check if MAC address is in allowed synthetic ranges.

    Handles colon, dash, dot-separated, and bare 12-hex formats.
    """
    # Normalize to colon-separated uppercase format
    if len(mac) == 12 and ':' not in mac and '-' not in mac and '.' not in mac:
        # Bare 12-hex format - insert colons
        mac_normalized = ':'.join(mac[i:i+2].upper() for i in range(0, 12, 2))
    else:
        # Convert dash/dot to colon
        mac_normalized = mac.upper().replace('-', ':')
        if '.' in mac_normalized:
            # Cisco format: aabb.ccdd.eeff -> AA:BB:CC:DD:EE:FF
            mac_normalized = mac_normalized.replace('.', '')
            mac_normalized = ':'.join(mac_normalized[i:i+2] for i in range(0, 12, 2))

    return any(mac_normalized.startswith(prefix.upper()) for prefix in ALLOWED_MAC_PREFIXES)


def is_allowed_public_ip(addr_str: str) -> bool:
    """Check if IP is in allowed documentation or resolver ranges."""
    try:
        addr = ipaddress.ip_address(addr_str)

        # Check exact matches
        if addr_str in ALLOWED_PUBLIC_IPS:
            return True

        # Check documentation ranges
        if addr.version == 4:
            for net in DOC_IPV4_RANGES:
                if addr in net:
                    return True
        else:
            for net in DOC_IPV6_RANGES:
                if addr in net:
                    return True

        # Check allowed prefixes
        for net in ALLOWED_PUBLIC_PREFIXES:
            if addr in net:
                return True

        return False
    except ValueError:
        return False


def is_allowed_network(net_str: str, net_obj: Any) -> bool:
    """Check if a network is in allowed ranges or is structural.

    Returns True if the network overlaps with documentation ranges or is structural.
    """
    # Check structural networks (default routes)
    if net_str in STRUCTURAL_NETWORKS:
        return True

    # For networks that overlap with documentation ranges, allow them
    if isinstance(net_obj, ipaddress.IPv4Network):
        for doc_net in DOC_IPV4_RANGES:
            if net_obj.overlaps(doc_net):
                return True
    elif isinstance(net_obj, ipaddress.IPv6Network):
        for doc_net in DOC_IPV6_RANGES:
            if net_obj.overlaps(doc_net):
                return True

    # Check if the network address itself is allowed
    return is_allowed_public_ip(str(net_obj.network_address))


def hash_value(value: str) -> str:
    """Return short hash of a value for diagnostics."""
    return hashlib.sha256(value.encode()).hexdigest()[:8]


def extract_ips_from_value(value: Any) -> List[Tuple[str, Any]]:
    """Extract all IP addresses/networks from a value.

    Returns list of (original_value, parsed_ip_or_network) tuples.
    """
    if not isinstance(value, str):
        return []

    results = []

    # Try as direct IP
    try:
        addr = ipaddress.ip_address(value)
        results.append((value, addr))
    except ValueError:
        pass

    # Try as CIDR network
    if not results:
        try:
            network = ipaddress.ip_network(value, strict=False)
            results.append((value, network))
        except ValueError:
            pass

    return results


def check_fixture(
    filepath: Path,
    denylist: Set[str],
    in_policies: bool = False
) -> List[str]:
    """Check one fixture file for sensitive data.

    Returns list of violation messages (empty if clean).
    """
    violations = []

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        violations.append(f'{filepath}: JSON decode error: {e}')
        return violations

    def walk(obj: Any, path: str = '') -> None:
        """Recursively walk JSON structure checking each value."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                new_path = f'{path}.{key}' if path else key

                # Check 1: Credential-shaped field names
                if CREDENTIAL_PATTERN.search(key):
                    if isinstance(value, str) and value and not is_placeholder(value):
                        violations.append(
                            f'{filepath}:{new_path} — credential-shaped field '
                            f'(len={len(value)}, hash={hash_value(value)})'
                        )

                # Check 2: High-entropy values
                if isinstance(value, str):
                    if HIGH_ENTROPY_PATTERN.match(value):
                        # Allow structural identifiers
                        if key not in STRUCTURAL_ID_KEYS and not is_placeholder(value):
                            violations.append(
                                f'{filepath}:{new_path} — high-entropy value '
                                f'(len={len(value)}, hash={hash_value(value)})'
                            )

                # Check 3: Public IPs (skip policies.json and DHCPv6 suffixes)
                if not in_policies and isinstance(value, str):
                    # Skip DHCPv6 suffix fields (contain host parts, not full IPs)
                    if key not in DHCPV6_SUFFIX_KEYS:
                        for original_val, parsed in extract_ips_from_value(value):
                            # Check if it's an IP address or network
                            if isinstance(parsed, ipaddress.IPv4Address) or isinstance(parsed, ipaddress.IPv6Address):
                                # It's an address
                                if parsed.is_global and not is_allowed_public_ip(str(parsed)):
                                    violations.append(
                                        f'{filepath}:{new_path} — public IP '
                                        f'(len={len(original_val)}, hash={hash_value(original_val)})'
                                    )
                            elif isinstance(parsed, ipaddress.IPv4Network) or isinstance(parsed, ipaddress.IPv6Network):
                                # It's a network - check if the network is global
                                if parsed.is_global and not is_allowed_network(original_val, parsed):
                                    violations.append(
                                        f'{filepath}:{new_path} — public IP network '
                                        f'(len={len(original_val)}, hash={hash_value(original_val)})'
                                    )

                # Check 4: Non-zero coordinates
                if key.lower() in GEO_COORD_KEYS:
                    if isinstance(value, (int, float)) and value != 0.0:
                        violations.append(
                            f'{filepath}:{new_path} — non-zero coordinate '
                            f'(hash={hash_value(str(value))})'
                        )

                # Check 5: MAC addresses (check ALL values, only allow synthetic ranges)
                # Note: 'mac' is in STRUCTURAL_ID_KEYS for high-entropy exemption,
                # but MAC validation applies to all fields including 'mac' itself.
                # MAC_EXEMPTION_KEYS handles bare 12-hex values that aren't MACs (e.g., serial numbers)
                if isinstance(value, str) and MAC_PATTERN.match(value):
                    if key not in MAC_EXEMPTION_KEYS and not is_allowed_mac(value):
                        violations.append(
                            f'{filepath}:{new_path} — MAC address '
                            f'(len={len(value)}, hash={hash_value(value)})'
                        )

                # Check 6: Denylist matches
                if isinstance(value, str):
                    for denied in denylist:
                        if denied in value.lower():
                            violations.append(
                                f'{filepath}:{new_path} — denylist match '
                                f'(len={len(value)}, hash={hash_value(value)})'
                            )

                walk(value, new_path)

        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                new_path = f'{path}[{i}]'
                walk(item, new_path)

    walk(data)
    return violations


def load_denylist(denylist_path: Path, allow_missing: bool = False) -> Set[str]:
    """Load identifier denylist from file.

    If the denylist is missing and allow_missing is False, exits with error.
    If allow_missing is True, prints a loud warning and returns empty set.
    """
    if not denylist_path.exists():
        if allow_missing:
            # Explicit opt-out: warn loudly but continue
            print('=' * 70, file=sys.stderr)
            print('WARNING: Denylist checking is DISABLED', file=sys.stderr)
            print(f'  Missing: {denylist_path}', file=sys.stderr)
            print('  Running with --allow-missing-denylist', file=sys.stderr)
            print('  Other checks (credentials, IPs, coordinates, MACs) still active', file=sys.stderr)
            print('=' * 70, file=sys.stderr)
            print(file=sys.stderr)
            return set()
        else:
            # Fail closed
            example_path = denylist_path.parent / 'fixture-denylist.example.txt'
            print('ERROR: Denylist file is missing', file=sys.stderr)
            print(f'  Expected: {denylist_path}', file=sys.stderr)
            print(file=sys.stderr)
            print('  To create it:', file=sys.stderr)
            print(f'    cp {example_path} {denylist_path}', file=sys.stderr)
            print('    # Then add your site-specific identifiers', file=sys.stderr)
            print(file=sys.stderr)
            print('  To run without denylist checking (CI/test environments):', file=sys.stderr)
            print('    export ALLOW_MISSING_DENYLIST=1', file=sys.stderr)
            print('    # or pass --allow-missing-denylist', file=sys.stderr)
            print(file=sys.stderr)
            sys.exit(1)

    denylist = set()
    with open(denylist_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            # Skip comments and empty lines
            if line and not line.startswith('#'):
                denylist.add(line.lower())

    return denylist


def main() -> int:
    """Run fixture verification."""
    # Check for --allow-missing-denylist flag or env var
    allow_missing = (
        '--allow-missing-denylist' in sys.argv
        or os.environ.get('ALLOW_MISSING_DENYLIST') == '1'
    )
    
    # Remove flag from argv so it doesn't interfere with positional arg parsing
    args = [a for a in sys.argv[1:] if a != '--allow-missing-denylist']

    if len(args) < 1:
        print('Usage: verify-fixtures-scrubbed.py [--allow-missing-denylist] <fixture-dir>', file=sys.stderr)
        return 2

    fixture_dir = Path(args[0])
    if not fixture_dir.is_dir():
        print(f'Error: {fixture_dir} is not a directory', file=sys.stderr)
        return 2

    # Load denylist
    script_dir = Path(__file__).parent
    denylist_path = script_dir / 'fixture-denylist.txt'
    denylist = load_denylist(denylist_path, allow_missing)

    # Find all JSON fixtures
    fixtures = sorted(fixture_dir.glob('*.json'))
    if not fixtures:
        print(f'Error: no fixture files found in {fixture_dir}', file=sys.stderr)
        return 1

    # Check each fixture
    all_violations = []
    files_checked = 0
    values_checked = 0

    for fixture_path in fixtures:
        # policies.json gets special handling (skip public IP check)
        in_policies = fixture_path.name == 'policies.json'

        violations = check_fixture(fixture_path, denylist, in_policies)
        all_violations.extend(violations)
        files_checked += 1

        # Count values in this file
        with open(fixture_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

            def count_values(obj: Any) -> int:
                if isinstance(obj, dict):
                    return sum(count_values(v) + 1 for v in obj.values())
                elif isinstance(obj, list):
                    return sum(count_values(item) for item in obj)
                else:
                    return 1

            values_checked += count_values(data)

    # Report results
    if all_violations:
        print('SENSITIVE DATA FOUND:', file=sys.stderr)
        for v in all_violations:
            print(f'  {v}', file=sys.stderr)
        print(file=sys.stderr)
        print(
            f'Found {len(all_violations)} violation(s) across '
            f'{files_checked} file(s)',
            file=sys.stderr
        )
        return 1

    # Success
    print(
        f'Fixture scrub check passed: {files_checked} files, '
        f'~{values_checked} values checked, 0 violations'
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())
