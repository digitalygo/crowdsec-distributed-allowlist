"""HTTP server exposing the heartbeat API.

Architecture
------------
- ``ThreadingHTTPServer`` with a thin ``BaseHTTPRequestHandler`` subclass.
- Application logic lives in ``ServerApp`` so that tests can exercise
  heartbeat processing without starting a socket.
- ``log_message`` is overridden to route through the ``logging`` module.
- All unhandled exceptions in handlers are caught and returned as 500 JSON
  without leaking internals; the traceback is logged server-side.
- Maximum request body size is 8192 bytes.
- Content-Type is NOT strictly enforced: the handler attempts JSON parse
  and rejects on failure.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple

from crowdsec_distributed_allowlist.auth import DUMMY_HASH, is_valid_hash_format, verify_token
from crowdsec_distributed_allowlist.crowdsec import CrowdsecRunner
from crowdsec_distributed_allowlist.ipcheck import is_public_ipv4
from crowdsec_distributed_allowlist.state import load_state, save_state

logger = logging.getLogger(__name__)

MAX_BODY_BYTES = 8192

# Agent name validation regex per contract:
# ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$
_AGENT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

# ---------------------------------------------------------------------------
# ServerApp -- testable core
# ---------------------------------------------------------------------------


class ServerApp:
    """Core heartbeat processing logic, decoupled from HTTP transport.

    Parameters
    ----------
    config:
        Full server config dict (validated by caller).
    state_path:
        Filesystem path for the JSON state file.
    crowdsec_runner:
        A ``CrowdsecRunner`` instance (or mock for tests).
    """

    def __init__(
        self,
        config: dict,
        state_path: str,
        crowdsec_runner: CrowdsecRunner,
    ) -> None:
        self._config = config
        self._state_path = state_path
        self._runner = crowdsec_runner
        self._lock = threading.Lock()
        self._state: dict = load_state(state_path)

    # ------------------------------------------------------------------
    # public entry point
    # ------------------------------------------------------------------

    def handle_heartbeat(
        self,
        authorization_header: Optional[str],
        body_bytes: bytes,
        client_addr: str = "",
    ) -> Tuple[int, Dict[str, Any]]:
        """Process a heartbeat request.

        Returns ``(http_status, response_dict)``.

        All state mutations are serialised behind ``self._lock``.
        """
        # --- 1. parse body -------------------------------------------------
        try:
            payload = json.loads(body_bytes)
        except (json.JSONDecodeError, TypeError):
            return 400, {"ok": False, "error": "invalid JSON body"}

        if not isinstance(payload, dict):
            return 400, {"ok": False, "error": "body must be a JSON object"}

        agent_name = payload.get("agent")
        public_ipv4 = payload.get("public_ipv4")

        if not agent_name or not public_ipv4:
            return 400, {"ok": False, "error": "missing required fields: agent, public_ipv4"}

        if not isinstance(agent_name, str) or not _AGENT_NAME_RE.match(agent_name):
            return 400, {"ok": False, "error": "invalid agent name"}

        # --- 2. authenticate -----------------------------------------------
        token = _extract_bearer(authorization_header)
        if token is None:
            msg = f"auth failure: missing or malformed bearer token (client={client_addr})"
            logger.warning(msg)
            return 401, {"ok": False, "error": "unauthorized"}

        agent_config = self._config.get("agents", {}).get(agent_name)
        if agent_config is None:
            # Unknown agent: verify against dummy hash for timing safety.
            verify_token(token, DUMMY_HASH)
            logger.warning(
                "auth failure: unknown agent %s (client=%s)",
                agent_name,
                client_addr,
            )
            return 401, {"ok": False, "error": "unauthorized"}

        # Verify token first (constant-time), then check enabled.
        # This prevents unauthenticated callers from probing which
        # agent names exist and whether they are disabled.
        if not verify_token(token, agent_config["token_hash"]):
            logger.warning(
                "auth failure: wrong token for agent %s (client=%s)",
                agent_name,
                client_addr,
            )
            return 401, {"ok": False, "error": "unauthorized"}

        if not agent_config.get("enabled", True):
            logger.warning(
                "auth failure: disabled agent %s (client=%s)",
                agent_name,
                client_addr,
            )
            return 403, {"ok": False, "error": "agent disabled"}

        # --- 3. validate IP ------------------------------------------------
        if not isinstance(public_ipv4, str) or not is_public_ipv4(public_ipv4):
            return 400, {"ok": False, "error": "invalid or non-public IPv4 address"}

        # --- 4. determine allowlist / ttl ----------------------------------
        crowdsec_cfg = self._config["crowdsec"]
        allowlist = agent_config.get("allowlist", crowdsec_cfg["allowlist"])
        ttl = agent_config.get("ttl", crowdsec_cfg["ttl"])
        refresh_interval = int(crowdsec_cfg["refresh_interval_seconds"])

        # --- 5. process under lock -----------------------------------------
        with self._lock:
            now = datetime.now(timezone.utc)
            now_iso = now.isoformat()

            agents_state: dict = self._state.setdefault("agents", {})
            agent_state: dict = agents_state.get(agent_name, {})  # type: ignore[assignment]
            old_ip: Optional[str] = agent_state.get("public_ipv4")

            changed = False
            refreshed = False

            if old_ip != public_ipv4:
                # --- IP changed (or new agent) ---
                # cscli allowlists add does NOT refresh expiration of an
                # existing value (skips, warns, exit 0). So for a changed
                # IP we do a full remove-then-add cycle.
                if old_ip:
                    if isinstance(old_ip, str) and is_public_ipv4(old_ip):
                        self._runner.remove_ip(allowlist, old_ip)  # non-fatal
                    else:
                        logger.warning(
                            "ignoring invalid stored previous IP for agent %s: %r",
                            agent_name,
                            old_ip,
                        )

                if not self._runner.add_ip(allowlist, public_ipv4, ttl, agent_name):
                    # Fatal: do NOT record new IP or last_refresh.
                    return 500, {"ok": False, "error": "crowdsec update failed"}

                self._runner.delete_decisions(public_ipv4)  # non-fatal

                changed = True
                agent_state["public_ipv4"] = public_ipv4
                agent_state["last_refresh"] = now_iso

            else:
                # --- Same IP ---
                last_refresh_raw = agent_state.get("last_refresh")
                if last_refresh_raw:
                    try:
                        last_refresh = datetime.fromisoformat(last_refresh_raw)
                    except ValueError:
                        last_refresh = None
                else:
                    last_refresh = None

                if (
                    last_refresh is None
                    or (now - last_refresh).total_seconds() >= refresh_interval
                ):
                    # TTL refresh: remove then add because cscli add does
                    # NOT refresh expiration of existing values.
                    self._runner.remove_ip(allowlist, public_ipv4)  # non-fatal
                    if not self._runner.add_ip(allowlist, public_ipv4, ttl, agent_name):
                        # Fatal: keep old last_refresh, don't record refresh.
                        return 500, {"ok": False, "error": "crowdsec update failed"}
                    refreshed = True
                    agent_state["last_refresh"] = now_iso

            # Always bump last_seen.
            agent_state["last_seen"] = now_iso
            agents_state[agent_name] = agent_state

            save_state(self._state_path, self._state)

        return 200, {
            "ok": True,
            "agent": agent_name,
            "public_ipv4": public_ipv4,
            "changed": changed,
            "refreshed": refreshed,
            "allowlist": allowlist,
        }


def _extract_bearer(header: Optional[str]) -> Optional[str]:
    """Extract the token from an ``Authorization: Bearer <token>`` header.

    Returns ``None`` if the header is missing, malformed, or the token is
    empty.
    """
    if not header:
        return None
    parts = header.split(maxsplit=1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token if token else None


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------


_HTTP_STATUS_TO_NAME: Dict[int, str] = {
    200: "OK",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    413: "Content Too Large",
    500: "Internal Server Error",
}


class _HeartbeatHandler(BaseHTTPRequestHandler):
    """Thin handler that delegates to ``ServerApp``."""

    # Suppress default Python version banner in Server response header.
    server_version = "crowdsec-distributed-allowlist"
    sys_version = ""

    # Set by the caller after instantiating the handler class.
    server_app: ServerApp = None  # type: ignore[assignment]

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D401
        """Route HTTP server log lines to the ``logging`` module."""
        logger.info(
            "%s - %s",
            self.client_address[0],
            fmt % args,
        )

    # ------------------------------------------------------------------
    # routing
    # ------------------------------------------------------------------

    def do_GET(self) -> None:
        """Handle GET requests."""
        if self.path == "/health":
            self._send_json(200, {"ok": True})
        else:
            self._send_json(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:
        """Handle POST requests."""
        if self.path != "/v1/heartbeat":
            self._send_json(404, {"ok": False, "error": "not found"})
            return

        # Enforce max body size.
        raw_cl = self.headers.get("Content-Length", "0")
        try:
            content_length = int(raw_cl) if raw_cl else 0
        except (ValueError, TypeError):
            self._send_json(400, {"ok": False, "error": "invalid Content-Length"})
            return
        if content_length < 0:
            self._send_json(400, {"ok": False, "error": "invalid Content-Length"})
            return
        if content_length > MAX_BODY_BYTES:
            self._send_json(413, {"ok": False, "error": "request body too large"})
            return

        body = self.rfile.read(content_length) if content_length > 0 else b""
        auth = self.headers.get("Authorization", "")

        try:
            status, response = self.server_app.handle_heartbeat(
                auth,
                body,
                client_addr=self.client_address[0],
            )
            self._send_json(status, response)
        except Exception:
            logger.exception("unhandled exception in heartbeat handler")
            self._send_json(500, {"ok": False, "error": "internal server error"})

    def do_DELETE(self) -> None:
        self._send_json(405, {"ok": False, "error": "method not allowed"})

    def do_PATCH(self) -> None:
        self._send_json(405, {"ok": False, "error": "method not allowed"})

    def do_PUT(self) -> None:
        self._send_json(405, {"ok": False, "error": "method not allowed"})

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _send_json(self, status: int, body: Dict[str, Any]) -> None:
        """Send a JSON response with the given status code."""
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status, _HTTP_STATUS_TO_NAME.get(status, ""))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


# ---------------------------------------------------------------------------
# server startup
# ---------------------------------------------------------------------------


def validate_config(config: dict) -> dict:
    """Validate and enrich the server config. Returns enriched dict.

    Applies documented defaults for every optional key.  Raises
    ``ValueError`` with a clear message on any validation failure so
    that the caller can report the error to the user without a traceback.
    """
    # ── listen section defaults ────────────────────────────────────────
    config.setdefault("listen", {})
    if not isinstance(config["listen"], dict):
        raise ValueError("listen must be an object")
    config["listen"].setdefault("host", "0.0.0.0")
    config["listen"].setdefault("port", 8787)

    # ── crowdsec section validation ────────────────────────────────────
    crowdsec = config.get("crowdsec")
    if not isinstance(crowdsec, dict):
        raise ValueError("missing or invalid 'crowdsec' config section")

    allowlist = crowdsec.get("allowlist")
    if not allowlist or not isinstance(allowlist, str):
        raise ValueError(
            "crowdsec.allowlist is required and must be a non-empty string"
        )

    crowdsec.setdefault("container", "crowdsec")
    crowdsec.setdefault("ttl", "36h")
    crowdsec.setdefault("refresh_interval_seconds", 3600)
    crowdsec.setdefault("docker_bin", "docker")
    crowdsec.setdefault("timeout_seconds", 60)

    # ── agents section validation ──────────────────────────────────────
    agents = config.get("agents")
    if not isinstance(agents, dict) or len(agents) == 0:
        raise ValueError(
            "agents section is required and must be a non-empty object"
        )

    for name, agent_cfg in agents.items():
        if not _AGENT_NAME_RE.match(name):
            raise ValueError(
                f"invalid agent name: '{name}' "
                f"(must match ^[A-Za-z0-9][A-Za-z0-9._-]{{0,63}}$)"
            )
        if not isinstance(agent_cfg, dict):
            raise ValueError(
                f"agent '{name}': value must be an object"
            )
        th = agent_cfg.get("token_hash", "")
        if not isinstance(th, str) or not is_valid_hash_format(th):
            raise ValueError(
                f"agent '{name}': token_hash must be a well-formed "
                f"pbkdf2_sha256 hash (4 $-separated fields, "
                f"iterations 10000-10000000, 16-byte salt hex, "
                f"32-byte digest hex)"
            )

    return config


def start_server(config: dict, state_path: str) -> None:
    """Configure and start the HTTP server. Blocks until killed."""
    runner = CrowdsecRunner(config["crowdsec"])
    app = ServerApp(config, state_path, runner)

    # Inject the app into the handler class so that every request handler
    # instance can reach it.
    handler_class = type(
        "_ConfiguredHandler",
        (_HeartbeatHandler,),
        {"server_app": app},
    )

    listen = config.get("listen", {})
    host = listen.get("host", "0.0.0.0")
    port = int(listen.get("port", 8787))

    server = ThreadingHTTPServer((host, port), handler_class)  # type: ignore[arg-type]
    logger.info("server listening on %s:%d, state=%s", host, port, state_path)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("server shutting down")
        server.shutdown()
