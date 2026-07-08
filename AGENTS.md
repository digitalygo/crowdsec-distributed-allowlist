# AGENTS.md

Instructions for AI agents working on this repository. Keep it simple, keep it
safe, and do not drift from the contract.

## Project invariants

- **KISS above all.** This project manages CrowdSec allowlists for a handful of
  trusted offices. It does not need frameworks, ORMs, async I/O, message
  queues, or microservices.
- **Python >= 3.9, stdlib only, zero runtime dependencies.** Adding a
  dependency requires explicit maintainer approval and a written justification
  kept in the repo.
- **One Docker image, one CLI entrypoint.** The image serves both agent and
  server roles via `crowdsec-distributed-allowlist <subcommand>`.
  `python -m crowdsec_distributed_allowlist` is the alternative entrypoint.
- **Code must stay small, boring, and auditable.** A single person should be
  able to read the entire codebase in under an hour.

## Architecture map

Each module has a single, clear responsibility. Do not blur the boundaries.

| Module | Responsibility |
| ------ | ------------- |
| `cli.py` | Argparse subcommand dispatch (server, agent, token) |
| `agent.py` | Public IPv4 discovery + heartbeat loop |
| `server.py` | `ThreadingHTTPServer` + `ServerApp` core (testable) |
| `auth.py` | Token generate / hash / verify (pbkdf2_sha256) |
| `ipcheck.py` | Public IPv4 validation, reject all non-public |
| `crowdsec.py` | Build cscli argv arrays, run via `subprocess.run` |
| `state.py` | Atomic JSON state load/save (tmp file + fsync + os.replace) |

Do not introduce new modules without a clear need. Do not move responsibilities
between existing modules unless the contract explicitly describes a different
split.

## Security rules (non-negotiable)

- **Never `shell=True`** or build shell commands from strings. `subprocess.run`
  with argv arrays only. Every argument in that array must be pre-validated.
- **Every write endpoint requires auth.** The heartbeat handler authenticates
  before touching allowlists or state.
- **Never log or print tokens.** Token values must never appear in log output,
  stderr, or diffs.
- **Constant-time comparisons for secrets.** Use `hmac.compare_digest` for
  token verification. Verify unknown agents against `DUMMY_HASH` to avoid
  timing-based agent-name enumeration.
- **All reported IPs go through `ipcheck` before any use.** This includes the
  `public_ipv4` field in heartbeat payloads and the output of discovery
  providers.
- **Never trust TCP source address for allowlisting.** The server sees the
  NetBird mesh IP, not the office WAN IP. The agent must self-discover.
- **`/health` must never expose config, state, or secrets.** The response is
  `{"ok": true}` and nothing else; no version, no agent list, no config keys.
- **No plaintext tokens in server config.** Only `pbkdf2_sha256$...` hashes.
  Tokens belong in agent configs (chmod 600) and env vars.
- **IPv6 stays rejected everywhere** until explicitly supported end to end.

## Change rules

- **Update tests with every behavior change.** Run `PYTHONPATH=src python3 -m
  unittest discover -s tests -v` and keep it green. Add tests for new paths.
- **Update README.md when CLI flags, config keys, or API shapes change.** The
  README is the user-facing contract.
- **Keep Python 3.9 compatibility.** No `match`/`case` statements, no
  `datetime.UTC` (use `datetime.timezone.utc`), no type union syntax (`X | Y`).
- **Keep Dockerfile multi-arch.** The base images (`python:3.13-alpine`,
  `docker:cli`) must continue to support at least amd64, arm64, arm/v7, arm/v6.
- **Config and state formats stay JSON.** No YAML, no TOML, no database.

## Verification checklist

Before considering any change complete, run through this list:

- [ ] `PYTHONPATH=src python3 -m unittest discover -s tests -v` passes
- [ ] `crowdsec-distributed-allowlist token generate` produces valid output
- [ ] Server starts cleanly against `examples/server-config.json`
- [ ] `pip list` or `grep -r '^\s*import ' src/` shows no new runtime deps
- [ ] `git diff` contains no token values, no plaintext secrets, no
  `print(token)` or equivalent
