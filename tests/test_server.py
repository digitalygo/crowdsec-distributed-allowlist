"""Tests for server.py -- ServerApp heartbeat processing.

All tests exercise ``ServerApp.handle_heartbeat`` directly (no sockets).
A mock crowdsec runner is injected.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from crowdsec_distributed_allowlist.auth import DUMMY_HASH, hash_token
from crowdsec_distributed_allowlist.server import ServerApp, _extract_bearer, _HeartbeatHandler, validate_config


# ---------------------------------------------------------------------------
# mock crowdsec runner
# ---------------------------------------------------------------------------


class FakeCrowdsecRunner:
    """Records calls and returns configurable success/failure."""

    def __init__(self, add_success: bool = True) -> None:
        self.add_success = add_success
        self.add_calls: List[Tuple[str, str, str, str]] = []
        self.remove_calls: List[Tuple[str, str]] = []
        self.delete_calls: List[str] = []

    def add_ip(self, allowlist: str, ip: str, ttl: str, agent_name: str) -> bool:
        self.add_calls.append((allowlist, ip, ttl, agent_name))
        return self.add_success

    def remove_ip(self, allowlist: str, ip: str) -> bool:
        self.remove_calls.append((allowlist, ip))
        return True

    def delete_decisions(self, ip: str) -> bool:
        self.delete_calls.append(ip)
        return True


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _make_token_hash() -> str:
    return hash_token("test-token-value")


def _minimal_config(token_hash: str) -> dict:
    return {
        "crowdsec": {
            "container": "crowdsec",
            "allowlist": "dynamic-safe-offices",
            "ttl": "36h",
            "refresh_interval_seconds": 3600,
            "docker_bin": "docker",
            "timeout_seconds": 60,
        },
        "agents": {
            "office-milano": {"token_hash": token_hash, "enabled": True},
        },
    }


class TestServerApp(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self._state_path = os.path.join(self._tmp, "state.json")
        self._token_hash = _make_token_hash()
        self._config = _minimal_config(self._token_hash)

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self._tmp, ignore_errors=True)

    def _app(self, runner: Optional[FakeCrowdsecRunner] = None) -> ServerApp:
        if runner is None:
            runner = FakeCrowdsecRunner()
        return ServerApp(self._config, self._state_path, runner)  # type: ignore[arg-type]

    def _hb(
        self,
        app: ServerApp,
        agent: str = "office-milano",
        ip: str = "8.8.8.8",
        token: str = "test-token-value",
    ) -> Tuple[int, Dict[str, Any]]:
        body = json.dumps({"agent": agent, "public_ipv4": ip}).encode()
        return app.handle_heartbeat(f"Bearer {token}", body, client_addr="127.0.0.1")

    # ------------------------------------------------------------------
    # auth failures (401)
    # ------------------------------------------------------------------

    def test_missing_bearer_returns_401(self) -> None:
        app = self._app()
        body = json.dumps({"agent": "x", "public_ipv4": "8.8.8.8"}).encode()
        status, resp = app.handle_heartbeat("", body)
        self.assertEqual(status, 401)
        self.assertFalse(resp["ok"])

    def test_unknown_agent_returns_401(self) -> None:
        app = self._app()
        status, resp = self._hb(app, agent="unknown-agent")
        self.assertEqual(status, 401)
        self.assertFalse(resp["ok"])

    def test_wrong_token_returns_401(self) -> None:
        app = self._app()
        status, resp = self._hb(app, token="wrong-token")
        self.assertEqual(status, 401)
        self.assertFalse(resp["ok"])

    # ------------------------------------------------------------------
    # disabled agent (403)
    # ------------------------------------------------------------------

    def test_disabled_agent_returns_403(self) -> None:
        config = _minimal_config(self._token_hash)
        config["agents"]["office-milano"]["enabled"] = False
        runner = FakeCrowdsecRunner()
        app = ServerApp(config, self._state_path, runner)  # type: ignore[arg-type]

        status, resp = self._hb(app)
        self.assertEqual(status, 403)
        self.assertEqual(resp["error"], "agent disabled")

    def test_disabled_agent_wrong_token_returns_401(self) -> None:
        # Token verification must happen BEFORE the disabled check.
        # A wrong token on a disabled agent must return 401 (not 403)
        # to prevent unauthenticated probing of agent names.
        config = _minimal_config(self._token_hash)
        config["agents"]["office-milano"]["enabled"] = False
        runner = FakeCrowdsecRunner()
        app = ServerApp(config, self._state_path, runner)  # type: ignore[arg-type]

        status, resp = self._hb(app, token="wrong-token")
        self.assertEqual(status, 401)
        self.assertIn("unauthorized", resp["error"])

    # ------------------------------------------------------------------
    # bad payload (400)
    # ------------------------------------------------------------------

    def test_non_json_body_returns_400(self) -> None:
        app = self._app()
        status, resp = app.handle_heartbeat("Bearer x", b"not json")
        self.assertEqual(status, 400)

    def test_missing_agent_field_returns_400(self) -> None:
        app = self._app()
        body = json.dumps({"public_ipv4": "8.8.8.8"}).encode()
        status, resp = app.handle_heartbeat("Bearer test-token-value", body)
        self.assertEqual(status, 400)

    def test_missing_ip_field_returns_400(self) -> None:
        app = self._app()
        body = json.dumps({"agent": "office-milano"}).encode()
        status, resp = app.handle_heartbeat("Bearer test-token-value", body)
        self.assertEqual(status, 400)

    def test_invalid_agent_name_returns_400(self) -> None:
        app = self._app()
        body = json.dumps({"agent": "!bad$name", "public_ipv4": "8.8.8.8"}).encode()
        status, resp = app.handle_heartbeat("Bearer test-token-value", body)
        self.assertEqual(status, 400)

    def test_invalid_ip_returns_400(self) -> None:
        app = self._app()
        status, resp = self._hb(app, ip="192.168.1.1")
        self.assertEqual(status, 400)
        self.assertIn("IPv4", resp["error"])

    # ------------------------------------------------------------------
    # success: first heartbeat (changed)
    # ------------------------------------------------------------------

    def test_first_heartbeat_changed_true(self) -> None:
        runner = FakeCrowdsecRunner()
        app = self._app(runner)

        status, resp = self._hb(app, ip="93.45.12.34")
        self.assertEqual(status, 200)
        self.assertTrue(resp["changed"])
        self.assertFalse(resp["refreshed"])
        self.assertEqual(resp["public_ipv4"], "93.45.12.34")

        # Remove should NOT be called (no old IP).
        self.assertEqual(len(runner.remove_calls), 0)
        # Add must be called exactly once.
        self.assertEqual(len(runner.add_calls), 1)
        self.assertEqual(runner.add_calls[0][1], "93.45.12.34")
        # Delete decisions called after add.
        self.assertEqual(runner.delete_calls, ["93.45.12.34"])

    # ------------------------------------------------------------------
    # success: IP change triggers remove-old/add-new/delete in order
    # ------------------------------------------------------------------

    def test_changed_ip_triggers_remove_add_delete_order(self) -> None:
        # Pre-populate state with old IP.
        old_state = {
            "agents": {
                "office-milano": {
                    "public_ipv4": "1.1.1.1",
                    "last_seen": "2026-01-01T00:00:00+00:00",
                    "last_refresh": "2026-01-01T00:00:00+00:00",
                }
            }
        }
        with open(self._state_path, "w") as fh:
            json.dump(old_state, fh)

        runner = FakeCrowdsecRunner()
        app = ServerApp(self._config, self._state_path, runner)  # type: ignore[arg-type]

        status, resp = self._hb(app, ip="2.2.2.2")
        self.assertEqual(status, 200)
        self.assertTrue(resp["changed"])

        # Assert call order: remove(old) -> add(new) -> delete(new).
        self.assertEqual(len(runner.remove_calls), 1)
        self.assertEqual(runner.remove_calls[0], ("dynamic-safe-offices", "1.1.1.1"))

        self.assertEqual(len(runner.add_calls), 1)
        self.assertEqual(runner.add_calls[0][1], "2.2.2.2")

        self.assertEqual(runner.delete_calls, ["2.2.2.2"])

        # State must now have the new IP.
        with open(self._state_path) as fh:
            saved = json.load(fh)
        self.assertEqual(saved["agents"]["office-milano"]["public_ipv4"], "2.2.2.2")

    # ------------------------------------------------------------------
    # add failure returns 500, does NOT update recorded IP
    # ------------------------------------------------------------------

    def test_add_failure_returns_500_no_state_update(self) -> None:
        old_state = {
            "agents": {
                "office-milano": {
                    "public_ipv4": "1.1.1.1",
                    "last_seen": "2026-01-01T00:00:00+00:00",
                    "last_refresh": "2026-01-01T00:00:00+00:00",
                }
            }
        }
        with open(self._state_path, "w") as fh:
            json.dump(old_state, fh)

        runner = FakeCrowdsecRunner(add_success=False)
        app = ServerApp(self._config, self._state_path, runner)  # type: ignore[arg-type]

        status, resp = self._hb(app, ip="2.2.2.2")
        self.assertEqual(status, 500)
        self.assertEqual(resp["error"], "crowdsec update failed")

        # remove(old) was attempted (non-fatal, ran before add).
        self.assertEqual(len(runner.remove_calls), 1)
        # add was attempted and failed.
        self.assertEqual(len(runner.add_calls), 1)
        # delete should NOT be called (add was fatal, we returned early).
        self.assertEqual(len(runner.delete_calls), 0)

        # State must still have the OLD IP (not updated).
        with open(self._state_path) as fh:
            saved = json.load(fh)
        self.assertEqual(saved["agents"]["office-milano"]["public_ipv4"], "1.1.1.1")

    # ------------------------------------------------------------------
    # no-op: same IP, within refresh window
    # ------------------------------------------------------------------

    def test_same_ip_no_change_no_refresh(self) -> None:
        now = datetime.now(timezone.utc)
        prev_state = {
            "agents": {
                "office-milano": {
                    "public_ipv4": "8.8.8.8",
                    "last_seen": (now - timedelta(seconds=300)).isoformat(),
                    "last_refresh": now.isoformat(),
                }
            }
        }
        with open(self._state_path, "w") as fh:
            json.dump(prev_state, fh)

        runner = FakeCrowdsecRunner()
        app = ServerApp(self._config, self._state_path, runner)  # type: ignore[arg-type]

        status, resp = self._hb(app, ip="8.8.8.8")
        self.assertEqual(status, 200)
        self.assertFalse(resp["changed"])
        self.assertFalse(resp["refreshed"])

        # No cscli operations.
        self.assertEqual(len(runner.add_calls), 0)
        self.assertEqual(len(runner.remove_calls), 0)

        # last_seen must be updated.
        with open(self._state_path) as fh:
            saved = json.load(fh)
        self.assertNotEqual(
            saved["agents"]["office-milano"]["last_seen"],
            prev_state["agents"]["office-milano"]["last_seen"],
        )

    # ------------------------------------------------------------------
    # refresh: same IP, outside refresh window
    # ------------------------------------------------------------------

    def test_refresh_triggers_remove_then_add(self) -> None:
        now = datetime.now(timezone.utc)
        prev_state = {
            "agents": {
                "office-milano": {
                    "public_ipv4": "8.8.8.8",
                    "last_seen": (now - timedelta(seconds=5000)).isoformat(),
                    "last_refresh": (now - timedelta(seconds=5000)).isoformat(),
                }
            }
        }
        with open(self._state_path, "w") as fh:
            json.dump(prev_state, fh)

        runner = FakeCrowdsecRunner()
        app = ServerApp(self._config, self._state_path, runner)  # type: ignore[arg-type]

        status, resp = self._hb(app, ip="8.8.8.8")
        self.assertEqual(status, 200)
        self.assertFalse(resp["changed"])
        self.assertTrue(resp["refreshed"])

        # Refresh = remove then add.
        self.assertEqual(len(runner.remove_calls), 1)
        self.assertEqual(runner.remove_calls[0][1], "8.8.8.8")
        self.assertEqual(len(runner.add_calls), 1)
        self.assertEqual(runner.add_calls[0][1], "8.8.8.8")

    # ------------------------------------------------------------------
    # refresh failure returns 500, keeps old last_refresh
    # ------------------------------------------------------------------

    def test_refresh_failure_returns_500_keeps_old_refresh(self) -> None:
        now = datetime.now(timezone.utc)
        old_refresh = (now - timedelta(seconds=5000)).isoformat()
        prev_state = {
            "agents": {
                "office-milano": {
                    "public_ipv4": "8.8.8.8",
                    "last_seen": old_refresh,
                    "last_refresh": old_refresh,
                }
            }
        }
        with open(self._state_path, "w") as fh:
            json.dump(prev_state, fh)

        runner = FakeCrowdsecRunner(add_success=False)
        app = ServerApp(self._config, self._state_path, runner)  # type: ignore[arg-type]

        status, resp = self._hb(app, ip="8.8.8.8")
        self.assertEqual(status, 500)

        # remove was called, add failed.
        self.assertEqual(len(runner.remove_calls), 1)
        self.assertEqual(len(runner.add_calls), 1)

        # State should keep old last_refresh.
        with open(self._state_path) as fh:
            saved = json.load(fh)
        self.assertEqual(saved["agents"]["office-milano"]["last_refresh"], old_refresh)

    # ------------------------------------------------------------------
    # state persistence
    # ------------------------------------------------------------------

    def test_state_persists_across_requests(self) -> None:
        runner = FakeCrowdsecRunner()
        app = ServerApp(self._config, self._state_path, runner)  # type: ignore[arg-type]

        # First heartbeat.
        status, resp = self._hb(app, ip="1.2.3.4")
        self.assertEqual(status, 200)
        self.assertTrue(resp["changed"])

        # Reset calls.
        runner.add_calls.clear()

        # Second heartbeat, same IP, no change.
        status, resp = self._hb(app, ip="1.2.3.4")
        self.assertEqual(status, 200)
        self.assertFalse(resp["changed"])
        self.assertFalse(resp["refreshed"])
        # No cscli calls.
        self.assertEqual(len(runner.add_calls), 0)

    # ------------------------------------------------------------------
    # poisoned state: invalid old_ip does NOT reach remove_ip
    # ------------------------------------------------------------------

    def test_poisoned_state_non_string_ip_skips_remove(self) -> None:
        """State with non-string public_ipv4 must not call remove_ip."""
        old_state = {
            "agents": {
                "office-milano": {
                    "public_ipv4": 12345,
                    "last_seen": "2026-01-01T00:00:00+00:00",
                    "last_refresh": "2026-01-01T00:00:00+00:00",
                }
            }
        }
        with open(self._state_path, "w") as fh:
            json.dump(old_state, fh)

        runner = FakeCrowdsecRunner()
        app = ServerApp(self._config, self._state_path, runner)  # type: ignore[arg-type]
        status, resp = self._hb(app, ip="8.8.8.8")
        self.assertEqual(status, 200)
        self.assertTrue(resp["changed"])

        # remove_ip must NOT have been called (old_ip is int, not str).
        self.assertEqual(len(runner.remove_calls), 0)
        # add_ip must have been called with the valid new IP.
        self.assertEqual(len(runner.add_calls), 1)
        self.assertEqual(runner.add_calls[0][1], "8.8.8.8")

    def test_poisoned_state_non_public_ip_skips_remove(self) -> None:
        """State with non-public public_ipv4 must not call remove_ip."""
        old_state = {
            "agents": {
                "office-milano": {
                    "public_ipv4": "192.168.1.1",
                    "last_seen": "2026-01-01T00:00:00+00:00",
                    "last_refresh": "2026-01-01T00:00:00+00:00",
                }
            }
        }
        with open(self._state_path, "w") as fh:
            json.dump(old_state, fh)

        runner = FakeCrowdsecRunner()
        app = ServerApp(self._config, self._state_path, runner)  # type: ignore[arg-type]
        status, resp = self._hb(app, ip="8.8.8.8")
        self.assertEqual(status, 200)
        self.assertTrue(resp["changed"])

        # remove_ip must NOT have been called (old_ip is private).
        self.assertEqual(len(runner.remove_calls), 0)
        # add_ip must have been called with the valid new IP.
        self.assertEqual(len(runner.add_calls), 1)
        self.assertEqual(runner.add_calls[0][1], "8.8.8.8")


class TestExtractBearer(unittest.TestCase):
    def test_valid_bearer(self) -> None:
        self.assertEqual(_extract_bearer("Bearer abc123"), "abc123")

    def test_case_insensitive(self) -> None:
        self.assertEqual(_extract_bearer("bearer abc123"), "abc123")

    def test_missing_prefix(self) -> None:
        self.assertIsNone(_extract_bearer("abc123"))
        self.assertIsNone(_extract_bearer(""))

    def test_none(self) -> None:
        self.assertIsNone(_extract_bearer(None))

    def test_empty_token(self) -> None:
        self.assertIsNone(_extract_bearer("Bearer "))


class TestValidateConfig(unittest.TestCase):
    """validate_config: defaults, required fields, and each rejection case."""

    def _base(self) -> dict:
        return {
            "crowdsec": {
                "allowlist": "dynamic-safe-offices",
            },
            "agents": {
                "office-milano": {
                    "token_hash": "pbkdf2_sha256$100000$00112233445566778899aabbccddeeff$00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                }
            },
        }

    # ── defaults ──────────────────────────────────────────────────────

    def test_applies_all_defaults(self) -> None:
        cfg = validate_config(self._base())
        self.assertEqual(cfg["listen"]["host"], "0.0.0.0")
        self.assertEqual(cfg["listen"]["port"], 8787)
        self.assertEqual(cfg["crowdsec"]["container"], "crowdsec")
        self.assertEqual(cfg["crowdsec"]["ttl"], "36h")
        self.assertEqual(cfg["crowdsec"]["refresh_interval_seconds"], 3600)
        self.assertEqual(cfg["crowdsec"]["docker_bin"], "docker")
        self.assertEqual(cfg["crowdsec"]["timeout_seconds"], 60)

    def test_does_not_overwrite_explicit_values(self) -> None:
        cfg = self._base()
        cfg["listen"] = {"host": "127.0.0.1", "port": 9999}
        cfg["crowdsec"]["ttl"] = "12h"
        validated = validate_config(cfg)
        self.assertEqual(validated["listen"]["host"], "127.0.0.1")
        self.assertEqual(validated["listen"]["port"], 9999)
        self.assertEqual(validated["crowdsec"]["ttl"], "12h")

    def test_listen_not_dict_raises(self) -> None:
        cfg = self._base()
        cfg["listen"] = "bad"
        with self.assertRaises(ValueError) as ctx:
            validate_config(cfg)
        self.assertIn("listen must be an object", str(ctx.exception))

    # ── crowdsec section ──────────────────────────────────────────────

    def test_missing_crowdsec_raises(self) -> None:
        cfg = {"agents": self._base()["agents"]}
        with self.assertRaises(ValueError) as ctx:
            validate_config(cfg)
        self.assertIn("crowdsec", str(ctx.exception))

    def test_crowdsec_not_dict_raises(self) -> None:
        cfg = self._base()
        cfg["crowdsec"] = []
        with self.assertRaises(ValueError) as ctx:
            validate_config(cfg)
        self.assertIn("crowdsec", str(ctx.exception))

    def test_missing_allowlist_raises(self) -> None:
        cfg = self._base()
        del cfg["crowdsec"]["allowlist"]
        with self.assertRaises(ValueError) as ctx:
            validate_config(cfg)
        self.assertIn("allowlist", str(ctx.exception))

    def test_empty_allowlist_raises(self) -> None:
        cfg = self._base()
        cfg["crowdsec"]["allowlist"] = ""
        with self.assertRaises(ValueError) as ctx:
            validate_config(cfg)
        self.assertIn("allowlist", str(ctx.exception))

    def test_none_allowlist_raises(self) -> None:
        cfg = self._base()
        cfg["crowdsec"]["allowlist"] = None
        with self.assertRaises(ValueError) as ctx:
            validate_config(cfg)
        self.assertIn("allowlist", str(ctx.exception))

    # ── agents section ────────────────────────────────────────────────

    def test_missing_agents_raises(self) -> None:
        cfg = self._base()
        del cfg["agents"]
        with self.assertRaises(ValueError) as ctx:
            validate_config(cfg)
        self.assertIn("agents", str(ctx.exception))

    def test_agents_not_dict_raises(self) -> None:
        cfg = self._base()
        cfg["agents"] = "bad"
        with self.assertRaises(ValueError) as ctx:
            validate_config(cfg)
        self.assertIn("agents", str(ctx.exception))

    def test_empty_agents_raises(self) -> None:
        cfg = self._base()
        cfg["agents"] = {}
        with self.assertRaises(ValueError) as ctx:
            validate_config(cfg)
        self.assertIn("agents", str(ctx.exception))

    def test_invalid_agent_name_raises(self) -> None:
        cfg = self._base()
        cfg["agents"]["!bad$name"] = cfg["agents"].pop("office-milano")
        with self.assertRaises(ValueError) as ctx:
            validate_config(cfg)
        self.assertIn("!bad$name", str(ctx.exception))

    def test_agent_value_not_dict_raises(self) -> None:
        cfg = self._base()
        cfg["agents"]["office-milano"] = "just-a-string"
        with self.assertRaises(ValueError) as ctx:
            validate_config(cfg)
        self.assertIn("office-milano", str(ctx.exception))
        self.assertIn("object", str(ctx.exception))

    def test_missing_token_hash_raises(self) -> None:
        cfg = self._base()
        del cfg["agents"]["office-milano"]["token_hash"]
        with self.assertRaises(ValueError) as ctx:
            validate_config(cfg)
        self.assertIn("token_hash", str(ctx.exception))

    def test_token_hash_wrong_prefix_raises(self) -> None:
        cfg = self._base()
        cfg["agents"]["office-milano"]["token_hash"] = "sha256$abc"
        with self.assertRaises(ValueError) as ctx:
            validate_config(cfg)
        self.assertIn("token_hash", str(ctx.exception))

    def test_token_hash_not_string_raises(self) -> None:
        cfg = self._base()
        cfg["agents"]["office-milano"]["token_hash"] = 123
        with self.assertRaises(ValueError) as ctx:
            validate_config(cfg)
        self.assertIn("token_hash", str(ctx.exception))

    # ── token_hash: deep format validation (is_valid_hash_format) ───────

    def test_token_hash_bad_hex_salt_raises(self) -> None:
        cfg = self._base()
        cfg["agents"]["office-milano"]["token_hash"] = (
            "pbkdf2_sha256$100000$zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz$"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        )
        with self.assertRaises(ValueError) as ctx:
            validate_config(cfg)
        self.assertIn("token_hash", str(ctx.exception))

    def test_token_hash_wrong_salt_length_raises(self) -> None:
        cfg = self._base()
        # 16 hex chars = 8 bytes; must be 32 hex = 16 bytes.
        cfg["agents"]["office-milano"]["token_hash"] = (
            "pbkdf2_sha256$100000$0011223344556677$"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        )
        with self.assertRaises(ValueError) as ctx:
            validate_config(cfg)
        self.assertIn("token_hash", str(ctx.exception))

    def test_token_hash_wrong_digest_length_raises(self) -> None:
        cfg = self._base()
        # 32 hex chars = 16 bytes; must be 64 hex = 32 bytes.
        cfg["agents"]["office-milano"]["token_hash"] = (
            "pbkdf2_sha256$100000$00112233445566778899aabbccddeeff$"
            "00112233445566778899aabbccddeeff"
        )
        with self.assertRaises(ValueError) as ctx:
            validate_config(cfg)
        self.assertIn("token_hash", str(ctx.exception))

    def test_token_hash_non_numeric_iterations_raises(self) -> None:
        cfg = self._base()
        cfg["agents"]["office-milano"]["token_hash"] = (
            "pbkdf2_sha256$abc$00112233445566778899aabbccddeeff$"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        )
        with self.assertRaises(ValueError) as ctx:
            validate_config(cfg)
        self.assertIn("token_hash", str(ctx.exception))

    def test_token_hash_iterations_out_of_range_low_raises(self) -> None:
        cfg = self._base()
        cfg["agents"]["office-milano"]["token_hash"] = (
            "pbkdf2_sha256$500$00112233445566778899aabbccddeeff$"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        )
        with self.assertRaises(ValueError) as ctx:
            validate_config(cfg)
        self.assertIn("token_hash", str(ctx.exception))

    def test_token_hash_iterations_out_of_range_high_raises(self) -> None:
        cfg = self._base()
        cfg["agents"]["office-milano"]["token_hash"] = (
            "pbkdf2_sha256$20000000$00112233445566778899aabbccddeeff$"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        )
        with self.assertRaises(ValueError) as ctx:
            validate_config(cfg)
        self.assertIn("token_hash", str(ctx.exception))

    def test_token_hash_wrong_field_count_raises(self) -> None:
        cfg = self._base()
        cfg["agents"]["office-milano"]["token_hash"] = (
            "pbkdf2_sha256$100000$00112233445566778899aabbccddeeff"
        )
        with self.assertRaises(ValueError) as ctx:
            validate_config(cfg)
        self.assertIn("token_hash", str(ctx.exception))

    def test_token_hash_accepts_real_generated_hash(self) -> None:
        cfg = self._base()
        cfg["agents"]["office-milano"]["token_hash"] = _make_token_hash()
        # Must not raise.
        validate_config(cfg)

    def test_token_hash_accepts_examples_placeholder(self) -> None:
        # The placeholder from examples/server-config.json must pass.
        validate_config(self._base())


class TestServerVersionHeader(unittest.TestCase):
    """Verify the Server response header does not leak Python version."""

    def test_server_version_attrs_suppress_python_banner(self) -> None:
        self.assertEqual(
            _HeartbeatHandler.server_version,
            "crowdsec-distributed-allowlist",
        )
        self.assertEqual(_HeartbeatHandler.sys_version, "")

    def test_version_string_contains_no_python(self) -> None:
        vs = (
            _HeartbeatHandler.server_version
            + " "
            + _HeartbeatHandler.sys_version
        )
        self.assertNotIn("Python", vs)
        self.assertNotIn("python", vs)
        self.assertIn("crowdsec-distributed-allowlist", vs)


if __name__ == "__main__":
    unittest.main()
