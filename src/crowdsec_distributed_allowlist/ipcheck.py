"""Public IPv4 address validation.

Only globally routable unicast IPv4 addresses are accepted. Everything
else is rejected, including:

- private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- loopback (127.0.0.0/8)
- link-local (169.254.0.0/16)
- multicast (224.0.0.0/4)
- reserved (240.0.0.0/4)
- unspecified (0.0.0.0/32)
- broadcast (255.255.255.255/32)
- CGNAT (100.64.0.0/10) -- checked explicitly regardless of Python version

IPv6 addresses are always rejected. CIDR notation, hostnames, and
non-string inputs are rejected.
"""

from __future__ import annotations

import ipaddress
from typing import Optional

# CGNAT range checked explicitly because some Python versions (e.g. some
# 3.11 patch levels) classified 100.64.0.0/10 as global.
_CGNAT_NETWORK = ipaddress.IPv4Network("100.64.0.0/10")

# Well-known non-public ranges in descending order of specificity.
# (These are also covered by is_global, but explicit checks are explicit.)
_NON_PUBLIC_NETWORKS: list[ipaddress.IPv4Network] = [
    ipaddress.IPv4Network("255.255.255.255/32"),  # broadcast
    ipaddress.IPv4Network("169.254.0.0/16"),       # link-local
    ipaddress.IPv4Network("127.0.0.0/8"),          # loopback
    ipaddress.IPv4Network("10.0.0.0/8"),           # private A
    ipaddress.IPv4Network("172.16.0.0/12"),        # private B
    ipaddress.IPv4Network("192.168.0.0/16"),       # private C
    ipaddress.IPv4Network("224.0.0.0/4"),          # multicast
    ipaddress.IPv4Network("240.0.0.0/4"),          # reserved
]


def is_public_ipv4(value: str) -> bool:
    """Return ``True`` if *value* is a globally routable unicast IPv4 address."""
    return _rejection_reason(value) is None


def _rejection_reason(value: str) -> Optional[str]:
    """Return a human-readable rejection reason, or ``None`` if accepted."""
    if not isinstance(value, str):
        return "input must be a string"

    # Require a bare IP, not CIDR notation.
    if "/" in value:
        return "CIDR notation not accepted"

    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return "not a valid IP address"

    # IPv6 is always rejected.
    if not isinstance(addr, ipaddress.IPv4Address):
        return "IPv6 not supported"

    # Explicit CGNAT check (regardless of Python version).
    if addr in _CGNAT_NETWORK:
        return "CGNAT address (100.64.0.0/10)"

    # Check well-known non-public ranges.
    for net in _NON_PUBLIC_NETWORKS:
        if addr in net:
            return f"non-public address ({net})"

    # is_global covers remaining edge cases (unspecified, documentation
    # ranges, etc.).
    if not addr.is_global:
        return "address is not globally routable"

    return None
