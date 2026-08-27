#!/usr/bin/env python3
"""Verify that fixture files contain no sensitive data.

Scans JSON fixtures for credential-shaped fields, high-entropy values,
public IP addresses, non-zero coordinates, and identifiers from a denylist.

Exit codes:
    0  all fixtures clean
    1  sensitive data found or fixture directory empty
    2  usage error
"""

import ipaddress
import json
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


def extract_ips_from_value(value: Any) -> List[Tuple[str, str]]:
    """Extract all IP addresses from a value (string, CIDR, etc).

    Returns list of (original_value, normalized_ip) tuples.
    """
    if not isinstance(value, str):
        return []

    ips = []

    # Try as direct IP
    try:
        addr = ipaddress.ip_address(value)
        ips.append((value, str(addr)))
    except ValueError:
        pass

    # Try as CIDR - report both the original and the parsed address
    if not ips:
        try:
            network = ipaddress.ip_network(value, strict=False)
            # For CIDR, we want to check if the network contains public IPs
            # Report the original value for clarity
            ips.append((value, str(network.network_address)))
        except ValueError:
            pass

    return ips


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
                            f'(len={len(value)})'
                        )

                # Check 2: High-entropy values
                if isinstance(value, str):
                    if HIGH_ENTROPY_PATTERN.match(value):
                        # Allow structural identifiers
                        if key not in STRUCTURAL_ID_KEYS and not is_placeholder(value):
                            violations.append(
                                f'{filepath}:{new_path} — high-entropy value '
                                f'(len={len(value)})'
                            )

                # Check 3: Public IPs (skip policies.json and DHCPv6 suffixes)
                if not in_policies and isinstance(value, str):
                    # Skip DHCPv6 suffix fields (contain host parts, not full IPs)
                    if key not in DHCPV6_SUFFIX_KEYS:
                        for original_val, ip_str in extract_ips_from_value(value):
                            try:
                                addr = ipaddress.ip_address(ip_str)
                                if addr.is_global and not is_allowed_public_ip(ip_str):
                                    violations.append(
                                        f'{filepath}:{new_path} — public IP {original_val}'
                                    )
                            except ValueError:
                                pass

                # Check 4: Non-zero coordinates
                if key.lower() in GEO_COORD_KEYS:
                    if isinstance(value, (int, float)) and value != 0.0:
                        violations.append(
                            f'{filepath}:{new_path} — non-zero coordinate {value}'
                        )

                # Check 5: Denylist matches
                if isinstance(value, str):
                    for denied in denylist:
                        if denied in value.lower():
                            violations.append(
                                f'{filepath}:{new_path} — denylist match '
                                f'"{denied}" (len={len(value)})'
                            )

                walk(value, new_path)

        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                new_path = f'{path}[{i}]'
                walk(item, new_path)

    walk(data)
    return violations


def load_denylist(denylist_path: Path) -> Set[str]:
    """Load identifier denylist from file."""
    if not denylist_path.exists():
        return set()

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
    if len(sys.argv) < 2:
        print('Usage: verify-fixtures-scrubbed.py <fixture-dir>', file=sys.stderr)
        return 2

    fixture_dir = Path(sys.argv[1])
    if not fixture_dir.is_dir():
        print(f'Error: {fixture_dir} is not a directory', file=sys.stderr)
        return 2

    # Load denylist
    script_dir = Path(__file__).parent
    denylist_path = script_dir / 'fixture-denylist.txt'
    denylist = load_denylist(denylist_path)

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
