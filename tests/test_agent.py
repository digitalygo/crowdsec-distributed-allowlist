"""Tests for agent.py -- config precedence, discovery, heartbeat."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from crowdsec_distributed_allowlist.agent import (
    build_agent_config,
    discover_ip,
    send_heartbeat,
)


class TestAgentConfig(unittest.TestCase):
    """Config precedence: CLI > env > file > defaults."""

    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self._config_path = os.path.join(self._tmp, "agent.json")

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write_config(self, data: dict) -> None:
        with open(self._config_path, "w") as fh:
            json.dump(data, fh)

    def test_defaults_only_fails_on_missing_required(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            build_agent_config()
        self.assertEqual(ctx.exception.code, 2)

    def test_minimal_valid_config(self) -> None:
        config = build_agent_config(
            server_url="http://s:8787/v1/heartbeat",
            agent="test-agent",
            token="cda_test123",
        )
        self.assertEqual(config["server_url"], "http://s:8787/v1/heartbeat")
        self.assertEqual(config["agent"], "test-agent")
        self.assertEqual(config["token"], "cda_test123")
        self.assertEqual(config["interval"], 300)
        self.assertEqual(config["timeout"], 10)


    def test_file_layer(self) -> None:
        self._write_config({
            "server_url": "http://server:8787/v1/heartbeat",
            "agent": "file-agent",
            "token": "file-token",
            "interval": 60,
        })
        config = build_agent_config(config_path=self._config_path)
        self.assertEqual(config["agent"], "file-agent")
        self.assertEqual(config["interval"], 60)

    def test_env_overrides_file(self) -> None:
        self._write_config({
            "server_url": "http://server:8787/v1/heartbeat",
            "agent": "file-agent",
            "token": "file-token",
            "interval": 60,
        })
        with patch.dict(os.environ, {"CDA_INTERVAL": "120", "CDA_AGENT": "env-agent"}):
            config = build_agent_config(config_path=self._config_path)
        self.assertEqual(config["agent"], "env-agent")
        self.assertEqual(config["interval"], 120)

    def test_cli_overrides_env(self) -> None:
        self._write_config({
            "server_url": "http://server:8787/v1/heartbeat",
            "agent": "file-agent",
            "token": "file-token",
        })
        with patch.dict(os.environ, {"CDA_AGENT": "env-agent"}):
            config = build_agent_config(
                config_path=self._config_path,
                agent="cli-agent",
            )
        self.assertEqual(config["agent"], "cli-agent")

    def test_env_ip_providers_comma_separated(self) -> None:
        with patch.dict(os.environ, {"CDA_IP_PROVIDERS": "https://a.com, https://b.com"}):
            config = build_agent_config(
                server_url="http://s/v1/hb",
                agent="a",
                token="t",
            )
        self.assertEqual(config["ip_providers"], ["https://a.com", "https://b.com"])

    def test_cli_providers_comma_separated(self) -> None:
        config = build_agent_config(
            server_url="http://s/v1/hb",
            agent="a",
            token="t",
            providers="https://x.com, https://y.com",
        )
        self.assertEqual(config["ip_providers"], ["https://x.com", "https://y.com"])

    def test_missing_required_exits_2(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            build_agent_config(server_url="http://s", agent="a")  # no token
        self.assertEqual(ctx.exception.code, 2)


class TestDiscovery(unittest.TestCase):
    """Test discover_ip with mocked urlopen."""

    def _mock_urlopen(self, body: str, status: int = 200):
        """Yield a context-manager-like object that returns *body*."""

        class FakeResponse:
            def __init__(self, body: str, status: int):
                self._body = io.BytesIO(body.encode("utf-8"))
                self.status = status

            def read(self):
                return self._body.read()

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        def _opener(req, timeout=None):
            return FakeResponse(body, status)

        return _opener

    def test_discover_first_provider_wins(self) -> None:
        with patch("urllib.request.urlopen", self._mock_urlopen("8.8.8.8\n")):
            ip = discover_ip(["https://a.com", "https://b.com"], timeout=5)
        self.assertEqual(ip, "8.8.8.8")

    def test_discover_fallback_to_second(self) -> None:
        call_count = [0]

        def _opener(req, timeout=None):
            call_count[0] += 1
            if call_count[0] == 1:
                raise OSError("fail")
            return self._mock_urlopen("1.2.3.4\n")(req, timeout)

        with patch("urllib.request.urlopen", _opener):
            ip = discover_ip(["https://a.com", "https://b.com"], timeout=5)
        self.assertEqual(ip, "1.2.3.4")

    def test_discover_rejects_private_ip(self) -> None:
        # First provider returns private IP, second returns public.
        call_count = [0]

        def _opener(req, timeout=None):
            call_count[0] += 1
            if call_count[0] == 1:
                return self._mock_urlopen("192.168.1.1\n")(req, timeout)
            return self._mock_urlopen("8.8.8.8\n")(req, timeout)

        with patch("urllib.request.urlopen", _opener):
            ip = discover_ip(["https://a.com", "https://b.com"], timeout=5)
        self.assertEqual(ip, "8.8.8.8")

    def test_discover_all_fail_returns_none(self) -> None:
        def _opener(req, timeout=None):
            raise OSError("fail")

        with patch("urllib.request.urlopen", _opener):
            ip = discover_ip(["https://a.com"], timeout=5)
        self.assertIsNone(ip)


class TestHeartbeat(unittest.TestCase):
    """Test send_heartbeat with mocked urlopen."""

    def _mock_urlopen(self, status: int, body: dict, raise_error: bool = False):
        """Return a mock opener function."""

        class FakeResponse:
            def __init__(self, status: int, body_bytes: bytes):
                self.status = status
                self._body = io.BytesIO(body_bytes)

            def read(self):
                return self._body.read()

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        def _opener(req, timeout=None):
            if raise_error:
                raise OSError("connection refused")
            body_bytes = json.dumps(body).encode("utf-8")
            resp = FakeResponse(status, body_bytes)
            return resp

        return _opener

    def test_heartbeat_success(self) -> None:
        with patch("urllib.request.urlopen", self._mock_urlopen(200, {"ok": True, "changed": True})):
            status, body = send_heartbeat(
                "http://s/v1/heartbeat", "agent1", "8.8.8.8", "cda_token", 10
            )
        self.assertEqual(status, 200)
        self.assertTrue(body["changed"])

    def test_heartbeat_auth_failure(self) -> None:
        with patch("urllib.request.urlopen", self._mock_urlopen(401, {"ok": False, "error": "unauthorized"})):
            status, body = send_heartbeat(
                "http://s/v1/heartbeat", "agent1", "8.8.8.8", "cda_token", 10
            )
        self.assertEqual(status, 401)
        self.assertEqual(body["error"], "unauthorized")

    def test_heartbeat_network_error(self) -> None:
        with patch("urllib.request.urlopen", self._mock_urlopen(200, {}, raise_error=True)):
            status, body = send_heartbeat(
                "http://s/v1/heartbeat", "agent1", "8.8.8.8", "cda_token", 10
            )
        self.assertIsNone(status)
        self.assertFalse(body["ok"])


if __name__ == "__main__":
    unittest.main()
