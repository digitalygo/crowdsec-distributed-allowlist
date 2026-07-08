"""Token generation, hashing, and verification for agent authentication.

Security design
---------------
Bearer tokens transmitted over mesh VPN such as NetBird (encrypted peer-to-peer).
A captured token allows an attacker to claim a different IP for the
compromised agent. This is a documented accepted risk for v1; HMAC-based
per-message signing is noted as a future enhancement.

Tokens are 256-bit random values (``secrets.token_urlsafe(32)``) prefixed
with ``cda_`` to aid secret scanning. At rest on the server, only the
PBKDF2-SHA256 hash is stored (100 000 iterations). The iteration count is
defense in depth; the real barrier is the 256-bit random token.

Timing safety
-------------
``verify_token`` uses ``hmac.compare_digest`` for constant-time comparison.
When an unknown agent sends a heartbeat the server verifies against
``DUMMY_HASH`` so that the timing surface does not reveal whether an agent
name is registered. ``verify_token`` never raises on malformed input;
malformed hashes return ``False``.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Optional

TOKEN_PREFIX = "cda_"
TOKEN_ENTROPY_BYTES = 32
HASH_ITERATIONS = 100000
HASH_DELIMITER = "$"
HASH_PREFIX = "pbkdf2_sha256"

# A synthetic hash value used when an agent is not found in config so that
# verification runs in constant time regardless of agent existence.
DUMMY_HASH = (
    "pbkdf2_sha256$100000$"
    "00000000000000000000000000000000"
    "$"
    "0000000000000000000000000000000000000000000000000000000000000000"
)


def generate_token() -> str:
    """Return a fresh agent token: ``cda_`` prefix + 32 url-safe random bytes."""
    return TOKEN_PREFIX + secrets.token_urlsafe(TOKEN_ENTROPY_BYTES)


def hash_token(token: str, iterations: int = HASH_ITERATIONS) -> str:
    """Hash *token* with PBKDF2-SHA256 using *iterations* rounds.

    Returns a string in the format
    ``pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>``.

    The salt is 16 random bytes (128 bits). The hash output is 32 bytes
    (SHA-256).
    """
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", token.encode(), salt, iterations)
    return f"{HASH_PREFIX}{HASH_DELIMITER}{iterations}{HASH_DELIMITER}{salt.hex()}{HASH_DELIMITER}{dk.hex()}"


def _parse_hash(token_hash: str) -> Optional[tuple[int, bytes, bytes]]:
    """Parse a hash string into (iterations, salt, expected_dk).

    Returns ``None`` when the hash cannot be parsed (wrong prefix, wrong
    number of parts, non-numeric iterations).
    """
    if not token_hash.startswith(HASH_PREFIX + HASH_DELIMITER):
        return None
    parts = token_hash.split(HASH_DELIMITER)
    if len(parts) != 4:
        return None
    try:
        iterations = int(parts[1])
    except (ValueError, TypeError):
        return None
    try:
        salt = bytes.fromhex(parts[2])
        expected = bytes.fromhex(parts[3])
    except (ValueError, TypeError):
        return None
    return iterations, salt, expected


def is_valid_hash_format(token_hash: str) -> bool:
    """Return ``True`` if *token_hash* is a well-formed PBKDF2-SHA256 hash.

    Validates prefix, field count, numeric iterations in a safe range,
    salt length (16 bytes), and digest length (32 bytes).  Designed for
    startup config validation before the server binds a socket.
    """
    if not isinstance(token_hash, str):
        return False
    parsed = _parse_hash(token_hash)
    if parsed is None:
        return False
    iterations, salt, expected = parsed
    if not (10000 <= iterations <= 10000000):
        return False
    if len(salt) != 16:
        return False
    if len(expected) != 32:
        return False
    return True


def verify_token(token: str, token_hash: str) -> bool:
    """Return ``True`` if *token* matches *token_hash*.

    Comparison uses ``hmac.compare_digest`` for constant-time safety.
    Never raises an exception: malformed hashes or unexpected types
    return ``False``.
    """
    if not isinstance(token, str) or not isinstance(token_hash, str):
        return False
    parsed = _parse_hash(token_hash)
    if parsed is None:
        return False
    iterations, salt, expected = parsed
    try:
        dk = hashlib.pbkdf2_hmac("sha256", token.encode(), salt, iterations)
    except (ValueError, OverflowError):
        return False
    return hmac.compare_digest(dk, expected)
