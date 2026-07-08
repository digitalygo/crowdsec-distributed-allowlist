---
status: completed
created_at: 2026-07-08
updated_at: 2026-07-08
files_edited: [
  "pyproject.toml",
  "src/crowdsec_distributed_allowlist/__init__.py",
  "src/crowdsec_distributed_allowlist/__main__.py",
  "src/crowdsec_distributed_allowlist/cli.py",
  "src/crowdsec_distributed_allowlist/agent.py",
  "src/crowdsec_distributed_allowlist/server.py",
  "src/crowdsec_distributed_allowlist/auth.py",
  "src/crowdsec_distributed_allowlist/ipcheck.py",
  "src/crowdsec_distributed_allowlist/crowdsec.py",
  "src/crowdsec_distributed_allowlist/state.py",
  "tests/test_auth.py",
  "tests/test_ipcheck.py",
  "tests/test_agent.py",
  "tests/test_server.py",
  "tests/test_crowdsec.py",
  "examples/server-config.json",
  "examples/agent-config.json",
  "examples/safe-ip-agent.service",
  "examples/docker-compose.server.yml",
  "examples/docker-compose.agent.yml",
  "Dockerfile",
  ".dockerignore",
  ".gitignore",
  "README.md",
  "AGENTS.md",
  "LICENSE"
]
rationale: "Initial full implementation of the crowdsec-distributed-allowlist v1 project: KISS stdlib-only Python package with agent/server/token CLI, CrowdSec centralized allowlist integration via cscli, single multi-arch Docker image, examples, tests, and production documentation"
supporting_docs: [
  "substrate/traces/plans/2026-07-08-crowdsec-distributed-allowlist-v1.md",
  "substrate/traces/reviews/2026-07-08-initial-security-gate.md",
  "https://docs.crowdsec.net/docs/next/cscli/cscli_allowlists_add/",
  "https://github.com/crowdsecurity/crowdsec/blob/master/cmd/crowdsec-cli/cliallowlists/allowlists.go",
  "https://github.com/docker-library/official-images/blob/master/library/python",
  "https://github.com/docker-library/docker/blob/master/29/cli/Dockerfile"
]
---

# Implement crowdsec-distributed-allowlist v1

## Summary of changes

Built the complete v1 of the project from an empty repository: a zero
dependency Python (>= 3.9) package providing `agent`, `server`, and `token`
subcommands, CrowdSec centralized allowlist updates via
`docker exec <container> cscli` argv arrays, one multi-arch Docker image
(python:3.13-alpine plus static docker CLI), 85 unit tests, deployment
examples (server and agent compose, Raspberry Pi systemd unit), production
README, AGENTS.md contributor contract for AI agents, and MIT license owned
by DigItalyGo SRL SB.

## Technical reasoning

Key decisions (full contract in the plan document):

- Bearer token auth with PBKDF2-SHA256 hashes at rest (100k iterations,
  constant time verify, dummy-hash verification for unknown agents).
  Transport security delegated to the NetBird mesh; replay protection
  documented as deferred future work.
- TTL refresh is remove-then-add: verified against CrowdSec source that
  `cscli allowlists add` does not update the expiration of existing values.
- Explicit `cscli decisions delete --ip` after every add for deterministic
  behavior across CrowdSec versions.
- JSON config and state (atomic replace writes), `ThreadingHTTPServer` with
  a single lock and a socket-free testable `ServerApp` core.
- Docker base `python:3.13-alpine` + `COPY --from=docker:cli` static binary:
  covers amd64, arm64, arm/v7, arm/v6 (Pi Zero); ca-certificates included.

Review fixes applied after verification:

- Token verification moved before the enabled-agent check (prevents
  unauthenticated probing of disabled agent names, uniform timing).
- Startup config validation with documented defaults and fail-fast exit 2
  (prevents runtime KeyError on minimal configs).
- Non-numeric Content-Length returns 400 instead of raising.
- systemd unit: absolute `ExecStart` path and removed `DynamicUser=yes`
  (an ephemeral user cannot read the root-owned chmod 600 agent config).
- Agent quick start URLs corrected to include the `/v1/heartbeat` path.
- Compose server example dropped a misleading `CDA_LOG_LEVEL` env (agent-only
  variables); agent compose env example fixed to full heartbeat URL.
- Example server config placeholder hashes normalized to valid hex lengths.
- Writing style pass: em dashes removed everywhere; one broken Markdown
  table (missing blank line) repaired; table delimiter rows normalized.

## Impact assessment

- New repository content entirely; no prior code affected (first commit not
  yet created, branch `alpha`).
- AGENTS.md now defines the behavioral contract for future agents: stdlib
  only, argv-only subprocess, token logging ban, module boundaries.
- The Docker socket mount grants the server container root-equivalent host
  access; deployment docs restrict exposure to the NetBird interface and
  warn that published ports bypass ufw INPUT rules.
- Remaining MD013 line-length lint findings are inside Markdown tables only;
  no repository lint config mandates the 80 column default.

## Validation steps

- `PYTHONPATH=src python3 -m unittest discover -s tests -v`: 85 tests, OK.
- `token generate` / `token hash` smoke on host and inside the container.
- End-to-end smoke with a fake `docker` shim on PATH: real server + real
  agent `--once` produced `changed: true`, exact argv sequences verified
  (`allowlists add ... -e 36h -d agent:office-milano`, `decisions delete
  --ip ...`, remove-old on IP change), state JSON written atomically.
- ServerApp matrix exercised directly: no-op, changed IP, private/CGNAT/IPv6
  rejects (400), wrong token (401), disabled agent (403), unauthorized 401,
  404, 413, invalid Content-Length 400, bad config exit 2.
- `docker build` green; container smoke: `--version`, `token generate`,
  `docker --version` (29.6.1 static CLI), outbound TLS check against
  api.ipify.org, server against `examples/server-config.json` with
  `/health` returning `{"ok": true}`; image size 149MB.
- `docker compose config -q` passes for both example compose files.
- markdownlint: only in-table MD013 remains; grep confirms zero em dashes,
  zero token values in logs, diffs, or examples.
- Scanners: trivy fs (2 documented accepted Dockerfile findings: root user
  for docker.sock access, no HEALTHCHECK) and trivy image (0 HIGH/CRITICAL,
  no secrets); gitleaks/trufflehog/bandit/semgrep/hadolint unavailable on
  this host.

## Update 2026-07-08: security gate remediation

The final security review
(`substrate/traces/reviews/2026-07-08-initial-security-gate.md`) reported
two low and one informational finding; all three were fixed and validated
as RESOLVED by the reviewer in the same file:

- Stored `old_ip` from the state file is now revalidated
  (`isinstance` + `is_public_ipv4`) before reaching the
  `cscli allowlists remove` argv; invalid stale values are logged and
  skipped while add-new proceeds.
- `auth.is_valid_hash_format()` enforces full hash shape at startup
  (4 fields, iterations 10000..10000000, 16-byte hex salt, 32-byte hex
  digest) via `validate_config`, preserving dummy-hash timing equivalence.
- `Server` response header no longer leaks the Python version banner
  (`server_version` / `sys_version` overrides).

Validation: suite grew to 116 tests, all green; image rebuilt; container
smoke shows `Server: crowdsec-distributed-allowlist` and healthy
`/health`; reviewer re-ran the suite and confirmed each fix with
file:line evidence.
