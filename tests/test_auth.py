"""Tests for auth.py -- token generate, hash, verify, DUMMY_HASH."""

from __future__ import annotations

import hashlib
import hmac
import unittest

from crowdsec_distributed_allowlist.auth import (
    DUMMY_HASH,
    generate_token,
    hash_token,
    is_valid_hash_format,
    verify_token,
)


class TestAuth(unittest.TestCase):
    """Roundtrip and edge-case tests for auth functions."""

    def test_generate_token_format(self) -> None:
        token = generate_token()
        self.assertTrue(token.startswith("cda_"))
        # 43 chars: cda_ (4) + token_urlsafe(32) without padding = 43
        # token_urlsafe(32) = 32 bytes = 43 base64 chars without padding
        self.assertGreaterEqual(len(token), 43)

    def test_hash_token_format(self) -> None:
        token = generate_token()
        h = hash_token(token)
        parts = h.split("$")
        self.assertEqual(len(parts), 4)
        self.assertEqual(parts[0], "pbkdf2_sha256")
        self.assertEqual(parts[1], "100000")
        # salt_hex: 32 hex chars (16 bytes)
        self.assertEqual(len(parts[2]), 32)
        # hash_hex: 64 hex chars (32 bytes)
        self.assertEqual(len(parts[3]), 64)

    def test_roundtrip_verify_success(self) -> None:
        token = generate_token()
        h = hash_token(token)
        self.assertTrue(verify_token(token, h))

    def test_wrong_token_fails(self) -> None:
        token = generate_token()
        h = hash_token(token)
        wrong = generate_token()
        self.assertFalse(verify_token(wrong, h))

    def test_malformed_hash_returns_false(self) -> None:
        token = generate_token()
        self.assertFalse(verify_token(token, "garbage"))
        self.assertFalse(verify_token(token, "pbkdf2_sha256$abc$salt$hash"))
        self.assertFalse(verify_token(token, "pbkdf2_sha256$100000$tooshort$hash"))
        self.assertFalse(verify_token(token, ""))

    def test_verify_none_inputs(self) -> None:
        token = generate_token()
        self.assertFalse(verify_token(token, None))  # type: ignore[arg-type]
        self.assertFalse(verify_token(None, DUMMY_HASH))  # type: ignore[arg-type]

    def test_dummy_hash_is_not_verifyable(self) -> None:
        """DUMMY_HASH should not accidentally verify a real token."""
        token = generate_token()
        self.assertFalse(verify_token(token, DUMMY_HASH))

    def test_constant_format_across_calls(self) -> None:
        """hash_token with same token yields different hashes (random salt)."""
        token = generate_token()
        h1 = hash_token(token)
        h2 = hash_token(token)
        self.assertNotEqual(h1, h2)
        # Both should verify.
        self.assertTrue(verify_token(token, h1))
        self.assertTrue(verify_token(token, h2))


class TestIsValidHashFormat(unittest.TestCase):
    """Startup hash format validation that runs before binding the socket."""

    # -- valid inputs --------------------------------------------------------

    def test_accepts_real_hash_token_output(self) -> None:
        h = hash_token(generate_token())
        self.assertTrue(is_valid_hash_format(h))

    def test_accepts_examples_placeholder(self) -> None:
        # Matches the placeholder in examples/server-config.json
        placeholder = "pbkdf2_sha256$100000$00112233445566778899aabbccddeeff$00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        self.assertTrue(is_valid_hash_format(placeholder))

    def test_accepts_dummy_hash(self) -> None:
        self.assertTrue(is_valid_hash_format(DUMMY_HASH))

    # -- prefix / field-count rejections ------------------------------------

    def test_rejects_wrong_prefix(self) -> None:
        self.assertFalse(is_valid_hash_format("sha256$100000$00112233445566778899aabbccddeeff$00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"))

    def test_rejects_wrong_field_count(self) -> None:
        # Only 3 fields.
        self.assertFalse(is_valid_hash_format("pbkdf2_sha256$100000$00112233445566778899aabbccddeeff"))

    def test_rejects_five_fields(self) -> None:
        self.assertFalse(is_valid_hash_format("pbkdf2_sha256$100000$00112233445566778899aabbccddeeff$00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff$extra"))

    # -- salt hex rejections ------------------------------------------------

    def test_rejects_bad_hex_salt(self) -> None:
        self.assertFalse(is_valid_hash_format("pbkdf2_sha256$100000$zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz$00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"))

    def test_rejects_wrong_salt_length(self) -> None:
        # 16 hex chars = 8 bytes (should be 32 hex = 16 bytes).
        self.assertFalse(is_valid_hash_format("pbkdf2_sha256$100000$0011223344556677$00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"))

    # -- digest hex rejections ----------------------------------------------

    def test_rejects_bad_hex_digest(self) -> None:
        self.assertFalse(is_valid_hash_format("pbkdf2_sha256$100000$00112233445566778899aabbccddeeff$zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"))

    def test_rejects_wrong_digest_length(self) -> None:
        # 32 hex chars = 16 bytes (should be 64 hex = 32 bytes).
        self.assertFalse(is_valid_hash_format("pbkdf2_sha256$100000$00112233445566778899aabbccddeeff$00112233445566778899aabbccddeeff"))

    # -- iterations rejections ----------------------------------------------

    def test_rejects_non_numeric_iterations(self) -> None:
        self.assertFalse(is_valid_hash_format("pbkdf2_sha256$abc$00112233445566778899aabbccddeeff$00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"))

    def test_rejects_iterations_too_low(self) -> None:
        self.assertFalse(is_valid_hash_format("pbkdf2_sha256$5000$00112233445566778899aabbccddeeff$00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"))

    def test_rejects_iterations_too_high(self) -> None:
        self.assertFalse(is_valid_hash_format("pbkdf2_sha256$20000000$00112233445566778899aabbccddeeff$00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"))

    def test_rejects_zero_iterations(self) -> None:
        self.assertFalse(is_valid_hash_format("pbkdf2_sha256$0$00112233445566778899aabbccddeeff$00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"))

    def test_rejects_negative_iterations(self) -> None:
        self.assertFalse(is_valid_hash_format("pbkdf2_sha256$-1$00112233445566778899aabbccddeeff$00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"))

    # -- edge cases ---------------------------------------------------------

    def test_rejects_empty_string(self) -> None:
        self.assertFalse(is_valid_hash_format(""))

    def test_rejects_garbage(self) -> None:
        self.assertFalse(is_valid_hash_format("garbage"))

    def test_rejects_wrong_type(self) -> None:
        self.assertFalse(is_valid_hash_format(None))  # type: ignore[arg-type]
        self.assertFalse(is_valid_hash_format(123))    # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
