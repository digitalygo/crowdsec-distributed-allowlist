"""Heartbeat agent: discover public IPv4 and report it to the server.

The agent runs on a remote site (typically a Raspberry Pi behind a mesh
VPN). Because the server can only see the mesh IP, the agent must
self-discover its public (WAN) IPv4 address via external providers.

Architecture
------------
- Config precedence: CLI flag > env var > config file > defaults.
- IP discovery: try providers in order, first valid public IPv4 wins.
- Heartbeat: POST JSON payload with Bearer auth.
- Loop mode: sleep between rounds, never die on exceptions.
- ``--once``: single round, exit 0 on HTTP 200, else exit 1.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Optional

from crowdsec_distributed_allowlist import __version__  # type: ignore[attr-defined]
from crowdsec_distributed_allowlist.ipcheck import is_public_ipv4

logger = logging.getLogger(__name__)

USER_AGENT = f"crowdsec-distributed-allowlist/{__version__}"

_DEFAULT_PROVIDERS = [
    "https://api.ipify.org",
    "https://checkip.amazonaws.com",
    "https://ifconfig.me/ip",
]

# Map of CDA_* environment variables to agent config keys.
_ENV_MAP: dict[str, str] = {
    "CDA_SERVER_URL": "server_url",
    "CDA_AGENT": "agent",
    "CDA_TOKEN": "token",
    "CDA_INTERVAL": "interval",
    "CDA_TIMEOUT": "timeout",
    "CDA_IP_PROVIDERS": "ip_providers",
    "CDA_LOG_LEVEL": "log_level",
}

_INT_KEYS = {"interval", "timeout"}


# ---------------------------------------------------------------------------
# config loading
# ---------------------------------------------------------------------------


def _load_config_from_file(path: str) -> dict:
    """Load agent config from a JSON file."""
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _merge_env(config: dict) -> dict:
    """Overlay environment variables onto *config*."""
    for env_var, key in _ENV_MAP.items():
        val = os.environ.get(env_var)
        if val is not None:
            if key == "ip_providers":
                config[key] = [p.strip() for p in val.split(",")]
            elif key in _INT_KEYS:
                try:
                    config[key] = int(val)
                except ValueError:
                    logger.warning("env %s=%s is not an integer, ignoring", env_var, val)
            else:
                config[key] = val
    return config


def build_agent_config(
    config_path: Optional[str] = None,
    server_url: Optional[str] = None,
    agent: Optional[str] = None,
    token: Optional[str] = None,
    interval: Optional[int] = None,
    timeout: Optional[int] = None,
    providers: Optional[str] = None,
) -> dict:
    """Merge all config sources and return the resolved config dict.

    Raises ``SystemExit(2)`` when a required key is missing after merge.
    """
    config: dict = {
        "interval": 300,
        "timeout": 10,
        "ip_providers": list(_DEFAULT_PROVIDERS),
        "log_level": "INFO",
    }

    # File layer.
    if config_path:
        file_cfg = _load_config_from_file(config_path)
        for k, v in file_cfg.items():
            if v is not None:
                config[k] = v

    # Env layer.
    config = _merge_env(config)

    # CLI layer.
    cli_overrides: dict = {}
    if server_url is not None:
        cli_overrides["server_url"] = server_url
    if agent is not None:
        cli_overrides["agent"] = agent
    if token is not None:
        cli_overrides["token"] = token
    if interval is not None:
        cli_overrides["interval"] = interval
    if timeout is not None:
        cli_overrides["timeout"] = timeout
    if providers is not None:
        cli_overrides["ip_providers"] = [p.strip() for p in providers.split(",")]
    config.update(cli_overrides)

    # Validate required keys.
    for key in ("server_url", "agent", "token"):
        if not config.get(key):
            print(
                f"error: missing required config '{key}' (set via CLI, env, or config file)",
                file=sys.stderr,
            )
            sys.exit(2)

    return config


# ---------------------------------------------------------------------------
# IP discovery
# ---------------------------------------------------------------------------


def discover_ip(providers: list[str], timeout: int) -> Optional[str]:
    """Try *providers* in order. Return the first valid public IPv4 string,
    or ``None`` if all fail.

    Discovery uses HTTPS by default (providers are URLs). The request
    includes a ``User-Agent`` header identifying this project and version.
    """
    for url in providers:
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": USER_AGENT},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # type: ignore[attr-defined]
                body = resp.read().decode("utf-8").strip()
                if is_public_ipv4(body):
                    logger.debug("discovered public IPv4 %s via %s", body, url)
                    return body
                else:
                    logger.debug("provider %s returned non-public IP: %s", url, body)
        except Exception:
            logger.debug("discovery provider %s failed", url, exc_info=True)
    return None


# ---------------------------------------------------------------------------
# heartbeat
# ---------------------------------------------------------------------------


def send_heartbeat(
    server_url: str,
    agent_name: str,
    public_ipv4: str,
    token: str,
    timeout: int,
) -> tuple[Optional[int], dict]:
    """POST the heartbeat payload. Returns (http_status, response_dict).

    http_status is ``None`` on network-level failures.
    """
    payload = json.dumps({"agent": agent_name, "public_ipv4": public_ipv4}).encode("utf-8")
    req = urllib.request.Request(
        server_url,
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # type: ignore[attr-defined]
            body_data = json.loads(resp.read().decode("utf-8"))
            return resp.status, body_data
    except urllib.error.HTTPError as exc:
        status = exc.code
        try:
            body_data = json.loads(exc.read().decode("utf-8"))
        except Exception:
            body_data = {"ok": False, "error": f"HTTP {status} (unparseable body)"}
        return status, body_data
    except Exception as exc:
        return None, {"ok": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# agent main loop
# ---------------------------------------------------------------------------


def run_agent(
    config_path: Optional[str] = None,
    server_url: Optional[str] = None,
    agent: Optional[str] = None,
    token: Optional[str] = None,
    interval: Optional[int] = None,
    timeout: Optional[int] = None,
    providers: Optional[str] = None,
    once: bool = False,
) -> None:
    """Entry point for the agent subcommand.

    Parameters match the CLI flag names. See ``build_agent_config`` for
    precedence rules.
    """
    config = build_agent_config(
        config_path=config_path,
        server_url=server_url,
        agent=agent,
        token=token,
        interval=interval,
        timeout=timeout,
        providers=providers,
    )

    server_url_str: str = config["server_url"]
    agent_name: str = config["agent"]
    token_str: str = config["token"]
    interval_sec: int = config["interval"]
    timeout_sec: int = config["timeout"]
    ip_providers: list[str] = config["ip_providers"]

    logger.info("agent %s starting, server=%s, interval=%ds", agent_name, server_url_str, interval_sec)

    while True:
        ip = discover_ip(ip_providers, timeout_sec)
        if ip is None:
            logger.error("IP discovery failed for all providers")
            if once:
                sys.exit(1)
            time.sleep(interval_sec)
            continue

        logger.info("discovered public IPv4: %s", ip)

        status, body = send_heartbeat(server_url_str, agent_name, ip, token_str, timeout_sec)

        if status == 200:
            changed = body.get("changed", False)
            refreshed = body.get("refreshed", False)
            if changed:
                logger.info("heartbeat ok: IP changed -> %s (allowlist=%s)", ip, body.get("allowlist"))
            elif refreshed:
                logger.info("heartbeat ok: TTL refreshed for %s", ip)
            else:
                logger.info("heartbeat ok: no change for %s", ip)
            if once:
                sys.exit(0)
        else:
            error_msg = body.get("error", "unknown error") if isinstance(body, dict) else str(body)
            logger.warning(
                "heartbeat failed: status=%s error=%s",
                status if status is not None else "network-error",
                error_msg,
            )
            if once:
                sys.exit(1)

        time.sleep(interval_sec)
