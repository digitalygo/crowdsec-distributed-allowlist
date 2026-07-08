"""cscli subprocess invocations via ``docker exec``.

All commands are built as explicit argv arrays and executed via
``subprocess.run(argv, …, shell=False)``. Never string interpolation into
a shell. All inputs passing through argv are pre-validated upstream
(IP addresses by ipcheck, agent names by regex, allowlist/ttl/container
names from trusted operator config).

Testing
-------
The command-building functions (``build_add_argv``, etc.) are pure: they
return argv lists and do not execute anything. Tests assert exact argv
arrays without mocking subprocess. The ``CrowdsecRunner`` class wraps
execution and accepts an injectable ``_run_fn`` for tests.
"""

from __future__ import annotations

import logging
import subprocess
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# Type alias for a subprocess-run-compatible callable.
RunFunc = Callable[..., subprocess.CompletedProcess]


def build_add_argv(
    docker_bin: str,
    container: str,
    allowlist: str,
    ip: str,
    ttl: str,
    agent_name: str,
) -> list[str]:
    """Build argv for ``cscli allowlists add``."""
    return [
        docker_bin,
        "exec",
        container,
        "cscli",
        "allowlists",
        "add",
        allowlist,
        ip,
        "-e",
        ttl,
        "-d",
        f"agent:{agent_name}",
    ]


def build_remove_argv(
    docker_bin: str,
    container: str,
    allowlist: str,
    ip: str,
) -> list[str]:
    """Build argv for ``cscli allowlists remove``."""
    return [
        docker_bin,
        "exec",
        container,
        "cscli",
        "allowlists",
        "remove",
        allowlist,
        ip,
    ]


def build_delete_decisions_argv(
    docker_bin: str,
    container: str,
    ip: str,
) -> list[str]:
    """Build argv for ``cscli decisions delete --ip``."""
    return [
        docker_bin,
        "exec",
        container,
        "cscli",
        "decisions",
        "delete",
        "--ip",
        ip,
    ]


class CrowdsecRunner:
    """Execute cscli commands via ``docker exec``.

    Parameters
    ----------
    config:
        The ``crowdsec`` section from the server config, with keys
        ``docker_bin``, ``container``, ``timeout_seconds``.
    run_fn:
        Inject a different subprocess runner for testing (defaults to
        ``subprocess.run``).
    """

    def __init__(
        self,
        config: dict,
        run_fn: Optional[RunFunc] = None,
    ) -> None:
        self._docker_bin: str = config["docker_bin"]
        self._container: str = config["container"]
        self._timeout: int = config["timeout_seconds"]
        self._run_fn: RunFunc = run_fn or subprocess.run  # type: ignore[assignment]

    def add_ip(
        self,
        allowlist: str,
        ip: str,
        ttl: str,
        agent_name: str,
    ) -> bool:
        """Add *ip* to *allowlist*. Returns ``True`` on success (exit 0)."""
        argv = build_add_argv(
            self._docker_bin,
            self._container,
            allowlist,
            ip,
            ttl,
            agent_name,
        )
        return self._exec(argv, fatal=True)

    def remove_ip(self, allowlist: str, ip: str) -> bool:
        """Remove *ip* from *allowlist*. Returns ``True`` on success."""
        argv = build_remove_argv(
            self._docker_bin,
            self._container,
            allowlist,
            ip,
        )
        return self._exec(argv, fatal=False)

    def delete_decisions(self, ip: str) -> bool:
        """Delete all decisions for *ip*. Returns ``True`` on success."""
        argv = build_delete_decisions_argv(
            self._docker_bin,
            self._container,
            ip,
        )
        return self._exec(argv, fatal=False)

    # ------------------------------------------------------------------

    def _exec(self, argv: list[str], fatal: bool) -> bool:
        """Run *argv*, logging appropriately. Fatal=False means failures
        are logged but not treated as errors that abort processing."""
        try:
            result: subprocess.CompletedProcess = self._run_fn(
                argv,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )
        except FileNotFoundError:
            logger.error(
                "docker binary not found: %s (argv=%s)",
                self._docker_bin,
                argv,
            )
            return False
        except subprocess.TimeoutExpired:
            logger.error("cscli command timed out after %ds: %s", self._timeout, argv)
            return False

        stdout_trimmed = result.stdout.strip()[:500] if result.stdout else ""
        stderr_trimmed = result.stderr.strip()[:500] if result.stderr else ""

        if result.returncode == 0:
            logger.debug("cscli ok rc=0 argv=%s out=%s", argv, stdout_trimmed)
            return True
        else:
            level = logging.INFO if fatal else logging.DEBUG
            logger.log(
                level,
                "cscli rc=%d argv=%s out=%s err=%s",
                result.returncode,
                argv,
                stdout_trimmed,
                stderr_trimmed,
            )
            return not fatal  # non-fatal failures are "ok" for the caller
