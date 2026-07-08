"""Tests for crowdsec.py -- argv building and execution."""

from __future__ import annotations

import subprocess
import unittest
from typing import Optional

from crowdsec_distributed_allowlist.crowdsec import (
    CrowdsecRunner,
    build_add_argv,
    build_delete_decisions_argv,
    build_remove_argv,
)


class TestBuildArgv(unittest.TestCase):
    """Pure functions: assert exact argv arrays, no subprocess executed."""

    def test_build_add_argv(self) -> None:
        argv = build_add_argv(
            docker_bin="docker",
            container="crowdsec",
            allowlist="dynamic-safe-offices",
            ip="93.45.12.34",
            ttl="36h",
            agent_name="office-milano",
        )
        expected = [
            "docker",
            "exec",
            "crowdsec",
            "cscli",
            "allowlists",
            "add",
            "dynamic-safe-offices",
            "93.45.12.34",
            "-e",
            "36h",
            "-d",
            "agent:office-milano",
        ]
        self.assertEqual(argv, expected)

    def test_build_remove_argv(self) -> None:
        argv = build_remove_argv(
            docker_bin="docker",
            container="crowdsec",
            allowlist="dynamic-safe-offices",
            ip="93.45.12.34",
        )
        expected = [
            "docker",
            "exec",
            "crowdsec",
            "cscli",
            "allowlists",
            "remove",
            "dynamic-safe-offices",
            "93.45.12.34",
        ]
        self.assertEqual(argv, expected)

    def test_build_delete_decisions_argv(self) -> None:
        argv = build_delete_decisions_argv(
            docker_bin="/usr/bin/docker",
            container="crowdsec-prod",
            ip="1.2.3.4",
        )
        expected = [
            "/usr/bin/docker",
            "exec",
            "crowdsec-prod",
            "cscli",
            "decisions",
            "delete",
            "--ip",
            "1.2.3.4",
        ]
        self.assertEqual(argv, expected)


class FakeCompletedProcess:
    """Minimal stand-in for subprocess.CompletedProcess."""

    def __init__(
        self,
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TestCrowdsecRunner(unittest.TestCase):
    """Test CrowdsecRunner with an injected run_fn."""

    _config = {
        "docker_bin": "docker",
        "container": "crowdsec",
        "timeout_seconds": 60,
    }

    def _runner(
        self,
        responses: Optional[dict[tuple, FakeCompletedProcess]] = None,
    ) -> CrowdsecRunner:
        responses = responses or {}

        def _fake_run(argv, **_kw) -> FakeCompletedProcess:
            call_key = tuple(argv)
            if call_key in responses:
                return responses[call_key]
            return FakeCompletedProcess(returncode=0)

        return CrowdsecRunner(self._config, run_fn=_fake_run)

    def test_add_ip_success(self) -> None:
        runner = self._runner()
        self.assertTrue(runner.add_ip("mylist", "8.8.8.8", "36h", "agent1"))

    def test_add_ip_failure(self) -> None:
        argv = build_add_argv("docker", "crowdsec", "mylist", "8.8.8.8", "36h", "agent1")
        runner = self._runner({tuple(argv): FakeCompletedProcess(returncode=1, stderr="oops")})
        self.assertFalse(runner.add_ip("mylist", "8.8.8.8", "36h", "agent1"))

    def test_remove_ip_non_fatal(self) -> None:
        """Remove should return True even on non-zero exit (non-fatal)."""
        argv = build_remove_argv("docker", "crowdsec", "mylist", "8.8.8.8")
        runner = self._runner({tuple(argv): FakeCompletedProcess(returncode=1)})
        self.assertTrue(runner.remove_ip("mylist", "8.8.8.8"))

    def test_delete_decisions_non_fatal(self) -> None:
        argv = build_delete_decisions_argv("docker", "crowdsec", "8.8.8.8")
        runner = self._runner({tuple(argv): FakeCompletedProcess(returncode=1)})
        self.assertTrue(runner.delete_decisions("8.8.8.8"))

    def test_file_not_found_error(self) -> None:
        """When docker binary is missing, all operations return False."""

        def _fake_run(argv, **_kw):
            raise FileNotFoundError("docker")

        runner = CrowdsecRunner(self._config, run_fn=_fake_run)
        self.assertFalse(runner.add_ip("mylist", "8.8.8.8", "36h", "agent1"))
        self.assertFalse(runner.remove_ip("mylist", "8.8.8.8"))
        self.assertFalse(runner.delete_decisions("8.8.8.8"))

    def test_timeout_expired(self) -> None:
        def _fake_run(argv, timeout=None, **_kw):
            raise subprocess.TimeoutExpired(argv, timeout or 60)

        runner = CrowdsecRunner(self._config, run_fn=_fake_run)
        self.assertFalse(runner.add_ip("mylist", "8.8.8.8", "36h", "agent1"))


if __name__ == "__main__":
    unittest.main()
