"""Tests for ipcheck.py -- public IPv4 validation."""

from __future__ import annotations

import unittest

from crowdsec_distributed_allowlist.ipcheck import is_public_ipv4


class TestIpcheck(unittest.TestCase):
    """Validation of is_public_ipv4 across accepted and rejected inputs."""

    # ---- accepted ---------------------------------------------------------

    def test_accepts_valid_public_ipv4(self) -> None:
        self.assertTrue(is_public_ipv4("8.8.8.8"))
        self.assertTrue(is_public_ipv4("1.1.1.1"))
        self.assertTrue(is_public_ipv4("93.45.12.34"))
        self.assertTrue(is_public_ipv4("185.199.108.153"))

    # ---- reject private ---------------------------------------------------

    def test_rejects_private_class_a(self) -> None:
        self.assertFalse(is_public_ipv4("10.0.0.1"))
        self.assertFalse(is_public_ipv4("10.255.255.255"))

    def test_rejects_private_class_b(self) -> None:
        self.assertFalse(is_public_ipv4("172.16.0.1"))
        self.assertFalse(is_public_ipv4("172.31.255.255"))

    def test_rejects_private_class_c(self) -> None:
        self.assertFalse(is_public_ipv4("192.168.0.1"))
        self.assertFalse(is_public_ipv4("192.168.255.255"))

    # ---- reject loopback --------------------------------------------------

    def test_rejects_loopback(self) -> None:
        self.assertFalse(is_public_ipv4("127.0.0.1"))
        self.assertFalse(is_public_ipv4("127.255.255.255"))

    # ---- reject link-local ------------------------------------------------

    def test_rejects_link_local(self) -> None:
        self.assertFalse(is_public_ipv4("169.254.0.1"))
        self.assertFalse(is_public_ipv4("169.254.255.255"))

    # ---- reject multicast -------------------------------------------------

    def test_rejects_multicast(self) -> None:
        self.assertFalse(is_public_ipv4("224.0.0.1"))
        self.assertFalse(is_public_ipv4("239.255.255.255"))

    # ---- reject reserved --------------------------------------------------

    def test_rejects_reserved(self) -> None:
        self.assertFalse(is_public_ipv4("240.0.0.1"))
        self.assertFalse(is_public_ipv4("255.255.255.254"))

    # ---- reject unspecified / broadcast -----------------------------------

    def test_rejects_unspecified(self) -> None:
        self.assertFalse(is_public_ipv4("0.0.0.0"))

    def test_rejects_broadcast(self) -> None:
        self.assertFalse(is_public_ipv4("255.255.255.255"))

    # ---- reject CGNAT -----------------------------------------------------

    def test_rejects_cgnat(self) -> None:
        self.assertFalse(is_public_ipv4("100.64.0.0"))
        self.assertFalse(is_public_ipv4("100.64.0.1"))
        self.assertFalse(is_public_ipv4("100.127.255.255"))
        self.assertFalse(is_public_ipv4("100.100.100.100"))

    # ---- reject IPv6 ------------------------------------------------------

    def test_rejects_ipv6(self) -> None:
        self.assertFalse(is_public_ipv4("::1"))
        self.assertFalse(is_public_ipv4("2001:db8::1"))
        self.assertFalse(is_public_ipv4("fe80::1"))

    # ---- reject garbage ---------------------------------------------------

    def test_rejects_garbage(self) -> None:
        self.assertFalse(is_public_ipv4("not-an-ip"))
        self.assertFalse(is_public_ipv4(""))
        self.assertFalse(is_public_ipv4("123.456.789.0"))
        self.assertFalse(is_public_ipv4("192.168.1"))

    # ---- reject CIDR ------------------------------------------------------

    def test_rejects_cidr(self) -> None:
        self.assertFalse(is_public_ipv4("8.8.8.8/32"))
        self.assertFalse(is_public_ipv4("10.0.0.0/8"))

    # ---- reject non-string ------------------------------------------------

    def test_rejects_non_string(self) -> None:
        self.assertFalse(is_public_ipv4(None))  # type: ignore[arg-type]
        self.assertFalse(is_public_ipv4(12345))  # type: ignore[arg-type]
        self.assertFalse(is_public_ipv4(["8.8.8.8"]))  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
