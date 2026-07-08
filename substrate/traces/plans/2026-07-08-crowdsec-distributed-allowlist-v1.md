---
status: completed
created_at: 2026-07-08
---

# Plan: crowdsec-distributed-allowlist v1

## Problem statement

Trusted remote sites (Raspberry Pi Zero class devices behind NetBird mesh VPN)
must keep their dynamic public IPv4 addresses allowlisted in CrowdSec running
on an external VPS (Pangolin/Traefik/CrowdSec Docker Compose stack). The
server sees only the mesh IP of the agent, so the agent must discover and
report its own public IPv4. A single KISS Python project provides both agent
and server modes, one Docker image, zero runtime dependencies.

This document is the binding contract for all implementation subagents.
Deviations require orchestrator approval.

## Decision summary

| Decision | Choice | Rationale |
| -------- | ------ | --------- |
| Language / deps | Python >= 3.9, stdlib only, zero runtime deps | KISS, auditable, Pi Zero friendly (RPi OS ships 3.9/3.11) |
| HTTP server | `http.server.ThreadingHTTPServer` + thin handler | stdlib adequate for a few heartbeats per minute |
| HTTP client | `urllib.request` | stdlib adequate |
| Auth scheme | `Authorization: Bearer <token>`, PBKDF2-SHA256 hash at rest | Transport is NetBird mesh (encrypted peer to peer); bearer is enough; documented decision. No replay protection in v1 (documented accepted risk) |
| Token format | `cda_` + `secrets.token_urlsafe(32)` | ~256 bits entropy; prefix aids secret scanning |
| Hash format | `pbkdf2_sha256$100000$<salt_hex>$<hash_hex>` | stdlib `hashlib.pbkdf2_hmac`; 100k iterations is defense in depth only, token entropy is the real barrier; constant time compare via `hmac.compare_digest` |
| Unknown agent timing | verify against a dummy hash | avoid agent-name enumeration via timing |
| Config format | JSON (server and agent) | zero deps |
| State | single JSON file, atomic write (tmp file + fsync + `os.replace`), `threading.Lock` around heartbeat processing | concurrency is trivial (few agents); SQLite unnecessary |
| TTL refresh | remove then add | VERIFIED: `cscli allowlists add` does NOT update expiration of an existing value (skips, warns, exit 0) |
| Decisions cleanup | explicit `cscli decisions delete --ip` after add | deterministic across CrowdSec versions (1.7.x also auto-applies on add; explicit stays safe) |
| Docker base | `python:3.13-alpine` + `COPY --from=docker:cli /usr/local/bin/docker /usr/local/bin/docker` | multi-arch amd64/arm64/arm/v7/arm/v6; alpine python includes ca-certificates; docker CLI is a static Go binary, no musl/glibc issue |
| Container user | root (v1) | needs `/var/run/docker.sock`; mesh-only exposure; documented as a security note |
| Rate limiting | none in v1 | mesh VPN + firewall is the boundary; documented limitation |
| IPv6 | rejected everywhere | requirement is public IPv4 only |
| License | MIT, copyright 2026 DigItalyGo SRL SB | requested |

## Target state

```text
crowdsec-distributed-allowlist/
├── README.md
├── AGENTS.md
├── LICENSE
├── Dockerfile
├── .dockerignore
├── .gitignore
├── pyproject.toml
├── src/crowdsec_distributed_allowlist/
│   ├── __init__.py        # __version__ = "0.1.0"
│   ├── __main__.py        # calls cli.main()
│   ├── cli.py             # argparse subcommands: agent, server, token
│   ├── agent.py           # discovery + heartbeat loop
│   ├── server.py          # ThreadingHTTPServer + ServerApp (testable core)
│   ├── auth.py            # token generate/hash/verify
│   ├── ipcheck.py         # public IPv4 validation
│   ├── crowdsec.py        # cscli via subprocess argv arrays
│   └── state.py           # JSON state load/save atomic
├── tests/
│   ├── test_auth.py
│   ├── test_ipcheck.py
│   ├── test_agent.py
│   ├── test_server.py
│   └── test_crowdsec.py
└── examples/
    ├── server-config.json
    ├── agent-config.json
    ├── docker-compose.server.yml
    ├── docker-compose.agent.yml
    └── safe-ip-agent.service
```

## Binding contract

### CLI

Console script `crowdsec-distributed-allowlist` and `python -m
crowdsec_distributed_allowlist`, argparse subcommands:

- `server --config PATH [--state PATH] [--host H] [--port P] [--log-level L]`
  (state default `/data/state.json`? NO: default `./state.json`; compose passes
  `--state /data/state.json` explicitly. CLI host/port override config
  `listen` section.)
- `agent [--config PATH] [--server-url URL] [--agent NAME] [--token T]
  [--interval SEC] [--timeout SEC] [--providers CSV] [--once]
  [--log-level L]`
- `token generate` prints `token: ...` and `token_hash: ...` plus a ready to
  paste agents config snippet
- `token hash TOKEN` prints only the hash line
- exit codes: 0 ok, 1 failure, 2 bad usage/config (argparse default for usage)

### Agent config precedence

CLI flag > environment variable > config file > default.

Env vars: `CDA_SERVER_URL`, `CDA_AGENT`, `CDA_TOKEN`, `CDA_INTERVAL`,
`CDA_TIMEOUT`, `CDA_IP_PROVIDERS` (comma separated), `CDA_LOG_LEVEL`.

Agent config file (JSON): keys `server_url`, `agent`, `token`,
`interval` (default 300), `timeout` (default 10), `ip_providers` (list,
default `["https://api.ipify.org", "https://checkip.amazonaws.com",
"https://ifconfig.me/ip"]`), `log_level` (default INFO).

Required after merge: `server_url`, `agent`, `token`. Missing => exit 2 with
clear message.

### Agent behavior

- Discovery: try providers in order, GET with timeout, User-Agent
  `crowdsec-distributed-allowlist/<version>`, strip body, validate with
  ipcheck. First valid wins. All fail => log error; in loop mode sleep and
  retry, in `--once` exit 1.
- Heartbeat: `POST server_url` with header `Authorization: Bearer <token>`,
  body `{"agent": NAME, "public_ipv4": IP}`. Logs discovered IP, success or
  failure, and server-reported `changed` / `refreshed` / no-op. Never logs the
  token.
- Loop mode: `time.sleep(interval)` between rounds, exceptions caught and
  logged, loop never dies. `--once`: single round, exit 0 on 200, else 1.

### Server config (JSON)

```json
{
  "listen": {"host": "0.0.0.0", "port": 8787},
  "crowdsec": {
    "container": "crowdsec",
    "allowlist": "dynamic-safe-offices",
    "ttl": "36h",
    "refresh_interval_seconds": 3600,
    "docker_bin": "docker",
    "timeout_seconds": 60
  },
  "agents": {
    "office-milano": {
      "token_hash": "pbkdf2_sha256$100000$...$...",
      "enabled": true,
      "allowlist": "dynamic-safe-offices",
      "ttl": "36h"
    }
  }
}
```

Per-agent `allowlist`/`ttl` optional, falling back to the `crowdsec` section.
`enabled` defaults true. Agent names must match
`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` (validated at config load and on payload).
No plaintext tokens anywhere in server config.

### State file (JSON)

```json
{
  "agents": {
    "office-milano": {
      "public_ipv4": "93.45.12.34",
      "last_seen": "2026-07-08T10:00:00+00:00",
      "last_refresh": "2026-07-08T10:00:00+00:00"
    }
  }
}
```

Timestamps ISO 8601 UTC. Atomic writes. Missing/corrupt state file => start
empty with a warning (never crash the server on state load).

### HTTP API

- `GET /health` => 200 `{"ok": true}`. No config, no version, no secrets.
- `POST /v1/heartbeat`:
  - max body 8192 bytes, must be `application/json` object
  - 401 `{"ok": false, "error": "unauthorized"}` missing/malformed bearer,
    unknown agent, wrong token (dummy-verify on unknown agent for timing)
  - 403 `{"ok": false, "error": "agent disabled"}` for `enabled: false`
  - 400 `{"ok": false, "error": "..."}` bad JSON, missing fields, payload
    `agent` not matching authenticated agent name, invalid/non-public IPv4
  - 500 `{"ok": false, "error": "crowdsec update failed"}` when the cscli add
    step fails
  - 200 `{"ok": true, "agent": A, "public_ipv4": IP, "changed": bool,
    "refreshed": bool, "allowlist": NAME}`
- 404 unknown path, 405 wrong method. Auth failures logged at WARNING without
  stack traces and without tokens.

### Heartbeat processing (single global lock)

1. Authenticate bearer token against `token_hash` for payload agent name.
2. Validate `public_ipv4` with ipcheck.
3. `last_seen` updates on every authenticated valid heartbeat.
4. If IP changed (or agent unknown in state):
   - `allowlists remove OLD` (only if old exists; non-fatal on failure)
   - `allowlists add NEW -e TTL -d agent:<name>` (fatal => 500, do not record
     new IP or `last_refresh`)
   - `decisions delete --ip NEW` (non-fatal)
   - record new IP + `last_refresh`, save state, `changed: true`
5. If unchanged and `now - last_refresh >= refresh_interval_seconds`:
   - remove then add same IP (add failure => 500, keep old `last_refresh`)
   - `refreshed: true`
6. Else no-op: `changed: false, refreshed: false`, save `last_seen`.

### cscli invocation (crowdsec.py)

`subprocess.run(argv, capture_output=True, text=True, timeout=timeout_seconds,
check=False)` with argv arrays only, never `shell=True`, never string
interpolation into a shell:

```text
[docker_bin, "exec", container, "cscli", "allowlists", "add", allowlist, ip, "-e", ttl, "-d", "agent:<name>"]
[docker_bin, "exec", container, "cscli", "allowlists", "remove", allowlist, ip]
[docker_bin, "exec", container, "cscli", "decisions", "delete", "--ip", ip]
```

All inputs reaching argv are pre-validated (ip via ipcheck, agent name via
regex, allowlist/ttl/container from trusted operator config). Log rc plus
trimmed stdout/stderr at DEBUG (INFO on failure); never log tokens. Timeouts
and `FileNotFoundError` (docker missing) are failures of the step, not
crashes.

VERIFIED cscli facts (docs.crowdsec.net, crowdsec source, 2026-07):

- `allowlists create NAME -d DESC` (description REQUIRED)
- `allowlists add` of an existing value: warns, exit 0, does NOT refresh
  expiration => refresh must remove then add
- `allowlists remove` of a missing value: exit 0 "no value to remove"
- `decisions delete --ip` with no match: exit 0 "0 decision(s) deleted"
- expiration accepts Go durations plus `d` suffix (`36h`, `7d`, `2d3h`)
- centralized allowlists need CrowdSec >= 1.6.0 (1.6.8+ recommended)
- since 1.7.x `allowlists add` also applies allowlists to existing decisions;
  explicit `decisions delete` stays for determinism

### auth.py

- `generate_token() -> str`
- `hash_token(token, iterations=100000) -> str` format
  `pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>`
- `verify_token(token, token_hash) -> bool` constant time, tolerant of
  malformed hashes (returns False, never raises)
- `DUMMY_HASH` constant used when agent unknown

### ipcheck.py

`is_public_ipv4(value: str) -> bool` plus `rejection_reason(value) ->
Optional[str]` (or equivalent single function returning reason). Rules:
must parse as `ipaddress.IPv4Address` (strings only, no int, no CIDR); reject
private, loopback, link-local, multicast, reserved, unspecified, broadcast,
CGNAT `100.64.0.0/10` (explicit membership check regardless of Python
version), and anything where `is_global` is False. IPv6 always rejected.

### Dockerfile

- `FROM docker:cli AS dockercli` then `FROM python:3.13-alpine`
- `COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker`
- copy project, `pip install --no-cache-dir .`
- `ENTRYPOINT ["crowdsec-distributed-allowlist"]`, default `CMD ["--help"]`
- no secrets in image; ca-certificates already present in alpine python

### Tests (unittest, no deps)

- ipcheck: valid publics; reject private/loopback/link-local/multicast/
  reserved/unspecified/broadcast/CGNAT/IPv6/garbage/CIDR
- auth: roundtrip verify, wrong token, malformed hash, constant format
- crowdsec: mock `subprocess.run`, assert exact argv arrays, non-fatal vs
  fatal paths, timeout handling
- agent: config precedence (file/env/flag), discovery fallback with mocked
  `urlopen`, payload shape
- server: ServerApp-level tests: auth failure 401, disabled 403, bad payload
  400, success changed, unchanged no-op, refresh path, cscli failure 500,
  state persistence; crowdsec layer mocked

## Step-by-step procedure

1. python-dev: full package, tests, pyproject, examples JSON + systemd unit,
   .gitignore. Verify: `python -m unittest discover -s tests -v` green,
   `python -m crowdsec_distributed_allowlist token generate` works.
2. docker-specialist (parallel): Dockerfile, .dockerignore, both compose
   examples per contract.
3. documentation-writer (parallel): README.md, AGENTS.md, LICENSE per
   contract.
4. Orchestrator verify: tests, smoke (token/server/agent --once end to end
   with fake docker shim on PATH), docker build + container smoke, README
   consistency reconciliation.
5. Operation record + final security review gate.

## Risks and mitigations

| Risk | Impact | Mitigation |
| ---- | ------ | ---------- |
| README/code drift from parallel work | confusing docs | contract in this file; orchestrator reconciliation pass |
| cscli syntax changes upstream | broken allowlist ops | verified against current docs/source; version noted in README |
| docker.sock mount is root-equivalent | host compromise if server popped | mesh-only exposure, documented; small auditable code; argv-only subprocess |
| replay of captured heartbeat | stale IP allowlisted | requires compromised mesh peer; documented accepted risk v1, HMAC noted as future work |
| Pi Zero (armv6) users | image must run | alpine + docker:cli both ship arm/v6; agent also runs bare (stdlib only) |

## Success criteria

- All acceptance criteria from the task prompt pass (token generate, server
  start, agent --once, unit tests, docker build, README clarity, no secrets
  logged, argv-only subprocess).
- AGENTS.md and LICENSE (MIT, DigItalyGo SRL SB) exist; docs in English.
- Zero runtime dependencies in pyproject.

## Research references

- web-researcher fact sheet: cscli allowlists create/add/remove, decisions
  delete, expiration format, refresh semantics (docs.crowdsec.net and
  github.com/crowdsecurity/crowdsec source, retrieved 2026-07-08)
- web-researcher fact sheet: python alpine/slim arch matrix, docker:cli static
  binary pattern (docker-library official-images, retrieved 2026-07-08)
