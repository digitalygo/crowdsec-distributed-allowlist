---
status: completed
created_at: 2026-07-08
updated_at: 2026-07-08
reviewer: security-review-specialist
target: crowdsec-distributed-allowlist initial implementation on branch alpha
scope: full new working tree, with focus on auth, ip validation, subprocess argv construction, HTTP handling, Docker examples, secrets, and state handling
supporting_docs:
  - substrate/traces/plans/2026-07-08-crowdsec-distributed-allowlist-v1.md
  - substrate/traces/operations/2026-07-08-implement-crowdsec-distributed-allowlist-v1.md
---

# Initial security gate review

## Summary

No critical, high, or medium findings. Found two low-severity hardening gaps and one informational disclosure: poisoned local state can feed unvalidated prior IP values into `cscli remove`, malformed token hashes pass startup validation and weaken timing equivalence, and default `BaseHTTPRequestHandler` response headers expose Python server version data.

## Scope and methodology

Reviewed `git status`, `git diff`, Python source, tests, Dockerfile, compose examples, example configs, README, and trace docs. Checked subprocess construction, auth flow, hash parsing, IP validation, HTTP body handling, secret logging, Docker exposure, and state paths. Used grep for shell/subprocess/token logging patterns and ran two local Python checks for `ipaddress` behavior and malformed hash config acceptance. No Docker, scanner, network, or active exploit tests run in this review. Known accepted risks from the prompt were not re-reported.

## Findings by severity

### Critical

None.

### High

None.

### Medium

None.

### Low

#### Low 1: poisoned state can send unvalidated prior IP values to `cscli remove`

- **Location**: `src/crowdsec_distributed_allowlist/state.py:27-41`, `src/crowdsec_distributed_allowlist/server.py:155-168`, `src/crowdsec_distributed_allowlist/crowdsec.py:54-70`
- **Evidence**: `load_state()` returns any top-level JSON object without validating nested `agents` entries. `ServerApp.handle_heartbeat()` reads `old_ip = agent_state.get("public_ipv4")` and, if truthy, calls `self._runner.remove_ip(allowlist, old_ip)` before any validation of `old_ip`. `build_remove_argv()` then places that value directly into the `docker exec ... cscli allowlists remove` argv array.
- **Impact**: Attacker or process with write access to the local state file can make next valid heartbeat for that agent remove an arbitrary allowlist value or pass option-shaped data to `cscli`. No shell execution found, and remote heartbeats cannot write invalid `old_ip` because new `public_ipv4` is validated first. Impact is local state poisoning and allowlist integrity or availability, not RCE.
- **False-positive notes**: State file is local and normally app-created with restrictive permissions through `mkstemp`. This is not remotely reachable through the heartbeat API. Risk remains for manual restore, lax volume permissions, or compromised same-user process.
- **Remediation**: Validate state schema on load and before use. Drop entries with invalid agent names, non-public or non-canonical `public_ipv4`, malformed timestamps, or wrong types. Recheck `old_ip` with `is_public_ipv4(old_ip)` before `remove_ip`; if invalid, log a warning and ignore the stale value.

#### Low 2: malformed token hashes pass config validation and break timing equivalence

- **Location**: `src/crowdsec_distributed_allowlist/server.py:387-392`, `src/crowdsec_distributed_allowlist/auth.py:72-86`, `src/crowdsec_distributed_allowlist/auth.py:98-100`, `src/crowdsec_distributed_allowlist/server.py:110-130`
- **Evidence**: `validate_config()` only checks that `token_hash` starts with `pbkdf2_sha256$`. `_parse_hash()` rejects malformed hash parts, and `verify_token()` returns `False` before PBKDF2 when parsing fails. Unknown agents still verify against `DUMMY_HASH`, so malformed configured agents can fail faster than unknown agents.
- **Impact**: Operator typo in `token_hash` causes that agent to fail closed, but it also creates timing difference between malformed configured names and unknown names. This weakens the documented dummy-hash equivalence and can leak registered agent names in misconfigured deployments. No auth bypass found.
- **False-positive notes**: Generated hashes from `token generate` are valid. Risk requires malformed trusted config, not attacker-controlled input.
- **Remediation**: Add full startup validation for hash format. Require exactly four fields, numeric iteration count in an approved range, 16-byte salt, and 32-byte digest. Reject invalid config before binding the server socket.

### Informational

#### Info 1: default HTTP server banner exposes Python version data

- **Location**: `src/crowdsec_distributed_allowlist/server.py:252-256`, `src/crowdsec_distributed_allowlist/server.py:324-331`
- **Evidence**: `_HeartbeatHandler` inherits `BaseHTTPRequestHandler` without overriding `server_version`, `sys_version`, or `version_string()`. `_send_json()` calls `send_response()`, which emits the inherited `Server` header.
- **Impact**: Responses can disclose `BaseHTTP/... Python/...` banner data. This does not expose config, state, or secrets, but it conflicts with the documented goal that `/health` expose no version details.
- **False-positive notes**: Body stays `{"ok": true}` for `/health`; leak is header-only and low value.
- **Remediation**: Override `server_version` and `sys_version`, or override `version_string()` to return a static product name without Python version.

## Remediation timeline

1. Fix low 1 before first production deploy if state directory permissions are not strictly controlled.
2. Fix low 2 before first production deploy to keep auth timing behavior aligned with the documented design.
3. Fix info 1 during hardening pass; not release-blocking by itself.

## Validation notes

- Add unit tests where poisoned state contains invalid `agents`, invalid `public_ipv4`, non-string `public_ipv4`, and naive or malformed timestamps. Expected result: invalid entries are dropped and no invalid value reaches `FakeCrowdsecRunner.remove_ip()`.
- Add unit tests where `validate_config()` rejects malformed hashes with correct prefix, bad hex, wrong salt length, wrong digest length, zero iterations, and excessive iterations.
- Add HTTP handler test or smoke check that `Server` response header no longer contains Python version data.

## Update: 2026-07-08 by security-review-specialist

### Prior finding status

- Low 1: resolved - stale `public_ipv4` from state is rechecked as a string public IPv4 before `remove_ip`; invalid stored values are logged and skipped while add-new continues.
- Low 2: resolved - startup config validation now rejects malformed `pbkdf2_sha256` hashes before server bind and names the affected agent.
- Info 1: resolved - HTTP handler overrides default `BaseHTTPRequestHandler` banner fields so `Server` no longer includes Python version data.

### Remediation validation

#### Low 1: resolved

- **Location**: `src/crowdsec_distributed_allowlist/server.py:141-142`, `src/crowdsec_distributed_allowlist/server.py:157-177`, `src/crowdsec_distributed_allowlist/server.py:198-205`, `tests/test_server.py:411-461`
- **Evidence**: Current heartbeat `public_ipv4` is still validated before any CrowdSec call. Stored `old_ip` is read from state, but `remove_ip(allowlist, old_ip)` now runs only when `isinstance(old_ip, str) and is_public_ipv4(old_ip)` is true. Otherwise the server logs `ignoring invalid stored previous IP` and skips removal. Same-IP refresh removes `public_ipv4`, which is already validated, not an untrusted stale value. Unit tests cover non-string and non-public stored IP values and assert `remove_ip` is not called.
- **Impact**: Poisoned local state no longer reaches the `cscli allowlists remove` argv path through prior IP handling. Add-new behavior remains available for valid heartbeat IPs.
- **False-positive notes**: Full nested state schema validation was not added, but the reported stale-value-to-argv path is closed. Remaining malformed-state effects are outside this finding unless they feed unvalidated values to subprocess argv.
- **Remediation**: Complete for this finding.

#### Low 2: resolved

- **Location**: `src/crowdsec_distributed_allowlist/auth.py:72-86`, `src/crowdsec_distributed_allowlist/auth.py:89-108`, `src/crowdsec_distributed_allowlist/server.py:398-405`, `tests/test_auth.py:84-153`, `tests/test_server.py:622-701`, `examples/server-config.json:11-24`
- **Evidence**: `_parse_hash()` enforces the `pbkdf2_sha256$` prefix, exactly four fields, integer iterations, and hex-decoded salt and digest. `is_valid_hash_format()` bounds iterations to `10000 <= iterations <= 10000000`, requires 16-byte salt, and requires 32-byte digest. `validate_config()` rejects invalid hashes with `agent '<name>': token_hash must be a well-formed pbkdf2_sha256 hash ...`. Tests cover bad prefix, field count, bad hex, wrong salt length, wrong digest length, non-numeric iterations, low iterations, high iterations, zero, negative, wrong type, generated hashes, dummy hash, and example placeholder. Local validation accepted `examples/server-config.json`.
- **Impact**: Misconfigured agent hashes fail closed at startup instead of creating a faster auth-failure path for configured agents. Dummy-hash timing equivalence is preserved for running server configs.
- **False-positive notes**: Config remains trusted operator input. No auth bypass found before or after fix.
- **Remediation**: Complete for this finding.

#### Info 1: resolved

- **Location**: `src/crowdsec_distributed_allowlist/server.py:259-264`, `src/crowdsec_distributed_allowlist/server.py:335-342`, `tests/test_server.py:704-722`
- **Evidence**: `_HeartbeatHandler.server_version` is now `crowdsec-distributed-allowlist` and `_HeartbeatHandler.sys_version` is `""`. `_send_json()` still uses `send_response()`, but the inherited banner values no longer include `BaseHTTP` or `Python`. Tests assert the version attributes and combined version string contain no `Python` text.
- **Impact**: Response headers no longer disclose Python server version data.
- **False-positive notes**: This review did not repeat the container smoke test; validation is from source and unit tests.
- **Remediation**: Complete for this finding.

### New findings

None.

### New validation notes

- Ran `PYTHONPATH=src python3 -m unittest discover -s tests`; result: 116 tests passed.
- Ran a local config-load check that calls `validate_config()` on `examples/server-config.json`; result: accepted.
- No Docker, scanner, network, or active exploit tests run during this follow-up validation.
