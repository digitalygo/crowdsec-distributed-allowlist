"""argparse CLI entry point for crowdsec-distributed-allowlist.

Subcommands: server, agent, token (generate, hash).

Exit codes: 0 ok, 1 failure, 2 bad usage/config (argparse default for usage).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from importlib.metadata import PackageNotFoundError, version as _pkg_version
from typing import NoReturn, Optional

try:
    __version__ = _pkg_version("crowdsec-distributed-allowlist")
except PackageNotFoundError:
    from crowdsec_distributed_allowlist import __version__  # type: ignore[no-redef]


LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def _fail(message: str) -> NoReturn:
    """Print *message* to stderr and exit with code 2."""
    print(f"error: {message}", file=sys.stderr)
    sys.exit(2)


def _setup_logging(level: Optional[str]) -> None:
    """Configure root logger with our standard format."""
    numeric = getattr(logging, (level or "INFO").upper(), logging.INFO)
    logging.basicConfig(level=numeric, format=LOG_FORMAT, stream=sys.stderr)


# ---------------------------------------------------------------------------
# server subcommand
# ---------------------------------------------------------------------------


def _cmd_server(args: argparse.Namespace) -> None:
    """Run the HTTP server."""
    from crowdsec_distributed_allowlist.server import start_server, validate_config

    _setup_logging(args.log_level)

    if args.config:
        with open(args.config, "r", encoding="utf-8") as fh:
            config = json.load(fh)
    else:
        _fail("--config is required for server")

    # CLI host/port override config listen section.
    if args.host is not None:
        config.setdefault("listen", {})["host"] = args.host
    if args.port is not None:
        config.setdefault("listen", {})["port"] = args.port

    try:
        config = validate_config(config)
    except ValueError as exc:
        _fail(str(exc))

    state_path: str = args.state or "state.json"

    start_server(config, state_path)


# ---------------------------------------------------------------------------
# agent subcommand
# ---------------------------------------------------------------------------


def _cmd_agent(args: argparse.Namespace) -> None:
    """Run the heartbeat agent."""
    from crowdsec_distributed_allowlist.agent import run_agent

    _setup_logging(args.log_level)

    if args.once:
        run_agent(
            config_path=args.config,
            server_url=args.server_url,
            agent=args.agent,
            token=args.token,
            interval=args.interval,
            timeout=args.timeout,
            providers=args.providers,
            once=True,
        )
    else:
        run_agent(
            config_path=args.config,
            server_url=args.server_url,
            agent=args.agent,
            token=args.token,
            interval=args.interval,
            timeout=args.timeout,
            providers=args.providers,
            once=False,
        )


# ---------------------------------------------------------------------------
# token subcommands
# ---------------------------------------------------------------------------


def _cmd_token_generate(_args: argparse.Namespace) -> None:
    """Generate a new token and print its hash."""
    from crowdsec_distributed_allowlist.auth import generate_token, hash_token

    token = generate_token()
    token_hash = hash_token(token)

    print(f"token: {token}")
    print(f"token_hash: {token_hash}")
    print()
    print("# Paste this into your server config agents section:")
    print(json.dumps({"token_hash": token_hash}, indent=2))


def _cmd_token_hash(args: argparse.Namespace) -> None:
    """Hash an existing token value and print the result."""
    from crowdsec_distributed_allowlist.auth import hash_token

    token_hash = hash_token(args.token_str)
    print(token_hash)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="crowdsec-distributed-allowlist",
        description="Distributed dynamic IP allowlist for CrowdSec",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"crowdsec-distributed-allowlist {__version__}",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ---- server -----------------------------------------------------------
    srv = sub.add_parser("server", help="Run the HTTP API server")
    srv.add_argument("--config", required=True, help="Path to server config JSON")
    srv.add_argument("--state", help="Path to state JSON (default: ./state.json)")
    srv.add_argument("--host", help="Override listen host from config")
    srv.add_argument("--port", type=int, help="Override listen port from config")
    srv.add_argument("--log-level", default="INFO", help="Log level (default: INFO)")
    srv.set_defaults(func=_cmd_server)

    # ---- agent ------------------------------------------------------------
    agt = sub.add_parser("agent", help="Run the heartbeat agent")
    agt.add_argument("--config", help="Path to agent config JSON")
    agt.add_argument("--server-url", help="Heartbeat endpoint URL")
    agt.add_argument("--agent", help="Agent name")
    agt.add_argument("--token", help="Bearer token")
    agt.add_argument("--interval", type=int, help="Seconds between heartbeats")
    agt.add_argument("--timeout", type=int, help="HTTP request timeout seconds")
    agt.add_argument(
        "--providers",
        help="Comma-separated list of IP discovery provider URLs",
    )
    agt.add_argument("--once", action="store_true", help="Run a single heartbeat and exit")
    agt.add_argument("--log-level", default="INFO", help="Log level (default: INFO)")
    agt.set_defaults(func=_cmd_agent)

    # ---- token ------------------------------------------------------------
    tok = sub.add_parser("token", help="Token management")
    tok_sub = tok.add_subparsers(dest="token_action", required=True)

    tok_gen = tok_sub.add_parser("generate", help="Generate a new agent token")
    tok_gen.set_defaults(func=_cmd_token_generate)

    tok_hash = tok_sub.add_parser("hash", help="Hash an existing token")
    tok_hash.add_argument("token_str", metavar="TOKEN", help="Token value to hash")
    tok_hash.set_defaults(func=_cmd_token_hash)

    return parser


def main(args: Optional[list[str]] = None) -> None:
    """Parse args and dispatch to the appropriate subcommand."""
    parser = _build_parser()
    parsed = parser.parse_args(args)
    parsed.func(parsed)


if __name__ == "__main__":
    main()
