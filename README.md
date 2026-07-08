# crowdsec-distributed-allowlist

Distributed dynamic CrowdSec allowlist system. Trusted remote sites (Raspberry
Pi Zero class devices behind a NetBird mesh VPN) self-discover their public
IPv4 address and report it to a central server. The server keeps CrowdSec
centralized allowlists updated via `docker exec crowdsec cscli`, so your
reverse proxies never block the office that manages them.

## Architecture

```text
Office (Pi Zero / bare metal agent)
  │
  │ 1. Discover public IPv4
  │    api.ipify.org / checkip.amazonaws.com / ifconfig.me
  │
  ▼
  NetBird mesh VPN (encrypted peer to peer)
  │
  │ 2. POST /v1/heartbeat
  │    Authorization: Bearer <token>
  │    {"agent":"office-milano","public_ipv4":"93.45.12.34"}
  │
  ▼
  VPS Docker host
  ┌─────────────────────────────────────────────┐
  │  crowdsec-distributed-allowlist (server)     │
  │  ╎  docker exec crowdsec cscli              │
  │  ╎  allowlists add / remove                 │
  └──────────┬──────────────────────────────────┘
             │
             ▼
  ┌─────────────────────────────────────────────┐
  │  crowdsec                                   │
  │  centralized allowlist: dynamic-safe-offices │
  └─────────────────────────────────────────────┘
```

## Why agents send the public IPv4 in the payload

The server only sees the NetBird mesh source IP of each agent, never the
office WAN IP. TCP source address is useless for allowlisting. The agent must
self-discover its public IPv4 by querying external IP providers and include it
in the heartbeat payload. The server validates the reported IP (must be a
genuine public IPv4) before trusting it.

## Why the server must only be reachable over the mesh VPN

The server exposes a bearer-token authenticated write endpoint and mounts the
Docker socket (`/var/run/docker.sock`), which is root-equivalent on the
host. The NetBird mesh VPN is the security boundary. The published port must be
bound to the NetBird interface IP, never to `0.0.0.0`.

> **Warning:** Docker published ports bypass `ufw` INPUT rules. Binding to
> `0.0.0.0` publishes the port on all host interfaces regardless of firewall
> rules. Always bind to the NetBird mesh IP (e.g. `100.92.0.5:8787:8787`).

## Requirements

- **Server (VPS):** CrowdSec >= 1.6.0 (1.6.8+ recommended for centralized
  allowlists), Docker, NetBird mesh VPN
- **Agent (remote site):** Python >= 3.9 (stdlib only, zero Python
  dependencies), NetBird mesh VPN
- The agent needs **no** CrowdSec credentials and **no** Docker

## Quick start server

### 1. Create the CrowdSec allowlist

The `-d` description flag is **required** by `cscli`:

```bash
docker exec crowdsec cscli allowlists create dynamic-safe-offices \
  -d "Dynamic safe IPs for trusted remote offices"
```

### 2. Generate a token

On the VPS, using the image:

```bash
docker run --rm ghcr.io/digitalygo/crowdsec-distributed-allowlist:latest token generate
```

Or with a local install:

```bash
crowdsec-distributed-allowlist token generate
```

Save the output. It prints a ready-to-use agent config snippet.

### 3. Write the server config

Create `server.json` (chmod 600). Replace the `token_hash` with the one from
step 2:

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
      "token_hash": "pbkdf2_sha256$100000$abc...$def...",
      "enabled": true,
      "allowlist": "dynamic-safe-offices",
      "ttl": "36h"
    }
  }
}
```

Per-agent `allowlist` and `ttl` are optional; they fall back to the
`crowdsec` section defaults. `enabled` defaults to `true`.

### 4. Add to your docker compose stack

Use `examples/docker-compose.server.yml` alongside your Pangolin / Traefik /
CrowdSec stack:

```yaml
services:
  crowdsec-distributed-allowlist:
    image: ghcr.io/digitalygo/crowdsec-distributed-allowlist:latest
    command:
      - server
      - "--config"
      - "/config/server.json"
      - "--state"
      - "/data/state.json"
    volumes:
      - "./config/allowlist-server.json:/config/server.json:ro"
      - "./data/allowlist:/data"
      - "/var/run/docker.sock:/var/run/docker.sock"
    ports:
      # REPLACE with your NetBird mesh interface IP
      - "100.92.0.5:8787:8787"
    restart: unless-stopped
```

### 5. Start and verify

```bash
docker compose up -d crowdsec-distributed-allowlist

# Verify over the mesh VPN (from any mesh peer):
curl http://100.92.0.5:8787/health
# {"ok": true}
```

## Quick start agent

### 1. Write agent config

Create `agent.json` (chmod 600):

```json
{
  "server_url": "http://100.92.0.5:8787/v1/heartbeat",
  "agent": "office-milano",
  "token": "cda_aB3xK...",
  "interval": 300,
  "timeout": 10,
  "ip_providers": [
    "https://api.ipify.org",
    "https://checkip.amazonaws.com",
    "https://ifconfig.me/ip"
  ],
  "log_level": "INFO"
}
```

Required keys: `server_url`, `agent`, `token`. Everything else has defaults.
`server_url` must include the full `/v1/heartbeat` path.

### 2. Environment variables

All settings can also be set via environment variables (precedence:
CLI > env > config file > default):

| Variable | Config key | Default |
| -------- | ---------- | ------- |
| `CDA_SERVER_URL` | `server_url` | (required) |
| `CDA_AGENT` | `agent` | (required) |
| `CDA_TOKEN` | `token` | (required) |
| `CDA_INTERVAL` | `interval` | `300` |
| `CDA_TIMEOUT` | `timeout` | `10` |
| `CDA_IP_PROVIDERS` | `ip_providers` | `api.ipify.org,checkip.amazonaws.com,ifconfig.me/ip` |
| `CDA_LOG_LEVEL` | `log_level` | `INFO` |

`CDA_IP_PROVIDERS` is a comma-separated string.

### 3. Test with --once

```bash
crowdsec-distributed-allowlist agent --config agent.json --once --log-level DEBUG
```

Or with env vars only (no config file):

```bash
export CDA_SERVER_URL=http://100.92.0.5:8787/v1/heartbeat
export CDA_AGENT=office-milano
export CDA_TOKEN=cda_aB3xK...
crowdsec-distributed-allowlist agent --once --log-level DEBUG
```

### 4. Install on Raspberry Pi (systemd)

```bash
# Clone the repo
git clone https://github.com/digitalygo/crowdsec-distributed-allowlist.git
cd crowdsec-distributed-allowlist

# Run with PYTHONPATH (stdlib-only, no pip install needed)
# or install in a venv:
python3 -m venv venv && source venv/bin/activate && pip install .

# Copy the systemd unit
sudo cp examples/safe-ip-agent.service /etc/systemd/system/
sudo mkdir -p /etc/crowdsec-distributed-allowlist
sudo cp agent.json /etc/crowdsec-distributed-allowlist/agent.json
sudo chmod 600 /etc/crowdsec-distributed-allowlist/agent.json

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now safe-ip-agent
sudo systemctl status safe-ip-agent
```

The agent needs **no** CrowdSec credentials and **no** Docker installed.

## CLI reference

### `server`

```text
crowdsec-distributed-allowlist server --config PATH
    [--state PATH] [--host H] [--port P] [--log-level L]
```

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--config` | (required) | Path to server config JSON |
| `--state` | `./state.json` | Path to state file |
| `--host` | config `listen.host` | Override listen host |
| `--port` | config `listen.port` | Override listen port |
| `--log-level` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

### `agent`

```text
crowdsec-distributed-allowlist agent [--config PATH]
    [--server-url URL] [--agent NAME] [--token T]
    [--interval SEC] [--timeout SEC] [--providers CSV]
    [--once] [--log-level L]
```

| Flag | Description |
| ---- | ----------- |
| `--config` | Path to agent config JSON |
| `--server-url` | Server heartbeat endpoint URL |
| `--agent` | Agent name (must match server config key) |
| `--token` | Bearer token |
| `--interval` | Seconds between heartbeats |
| `--timeout` | HTTP request timeout seconds |
| `--providers` | Comma-separated IP discovery provider URLs |
| `--once` | Run one heartbeat and exit (0 = success, 1 = failure) |
| `--log-level` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

### `token generate`

```text
crowdsec-distributed-allowlist token generate
```

Prints `token:`, `token_hash:`, and a ready-to-paste agent config snippet.

### `token hash`

```text
crowdsec-distributed-allowlist token hash <TOKEN>
```

Prints only the `pbkdf2_sha256$...` hash line.

Exit codes: `0` on success, `1` on failure, `2` on bad usage or invalid config.

## Configuration reference

### Server config

| Key | Type | Default | Description |
| --- | ---- | ------- | ----------- |
| `listen.host` | string | `"0.0.0.0"` | Listen address |
| `listen.port` | integer | `8787` | Listen port |
| `crowdsec.container` | string | `"crowdsec"` | CrowdSec container name for `docker exec` |
| `crowdsec.allowlist` | string | (required) | Default allowlist name |
| `crowdsec.ttl` | string | `"36h"` | Default IP entry TTL (Go duration + `d`, e.g. `36h`, `7d`) |
| `crowdsec.refresh_interval_seconds` | integer | `3600` | Minimum seconds between TTL refreshes for unchanged IPs |
| `crowdsec.docker_bin` | string | `"docker"` | Path to docker binary |
| `crowdsec.timeout_seconds` | integer | `60` | Timeout for each `cscli` invocation |
| `agents.NAME.token_hash` | string | (required) | `pbkdf2_sha256$...` hash of the agent's token |
| `agents.NAME.enabled` | boolean | `true` | Whether this agent can submit heartbeats |
| `agents.NAME.allowlist` | string | `crowdsec.allowlist` | Per-agent allowlist override |
| `agents.NAME.ttl` | string | `crowdsec.ttl` | Per-agent TTL override |

The server validates the config at startup and exits with a clear error when
`crowdsec.allowlist`, `agents`, or any `token_hash` is missing or malformed.

Agent names must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`.

### Agent config

| Key | Type | Default | Description |
| --- | ---- | ------- | ----------- |
| `server_url` | string | (required) | Server heartbeat endpoint URL |
| `agent` | string | (required) | Agent name |
| `token` | string | (required) | Bearer token |
| `interval` | integer | `300` | Seconds between heartbeats in loop mode |
| `timeout` | integer | `10` | HTTP request timeout seconds |
| `ip_providers` | list | 3 public providers | IP discovery provider URLs (tried in order) |
| `log_level` | string | `"INFO"` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

## How it works

### Heartbeat flow

Every heartbeat goes through these steps under a single global lock:

1. **Authenticate.** The server extracts the `Authorization: Bearer` header and
   verifies the token against the agent's `token_hash` using constant-time
   comparison (`hmac.compare_digest`). Unknown agent names are verified against
   a dummy hash to prevent timing-based agent-name enumeration.

2. **Validate IPv4.** The reported `public_ipv4` is validated by `ipcheck`.
   The following are rejected:
   - Private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
   - Loopback (`127.0.0.0/8`)
   - Link-local (`169.254.0.0/16`)
   - Multicast (`224.0.0.0/4`)
   - Reserved (`240.0.0.0/4`)
   - Unspecified / broadcast
   - CGNAT (`100.64.0.0/10`)
   - IPv6 addresses
   - Anything where `ipaddress.IPv4Address.is_global` is `False`

3. **Update `last_seen`** on every authenticated, valid heartbeat.

4. **If IP changed (or agent is new in state):**
   - Remove old IP from the allowlist (if one existed; non-fatal)
   - Add new IP with `-e TTL -d agent:<name>` (fatal failure => 500, do not
     record new IP)
   - Delete any existing decisions for the new IP (`cscli decisions delete --ip`)
   - Record new IP and `last_refresh`, save state
   - Response: `"changed": true`

5. **If IP unchanged and TTL needs refresh** (`now - last_refresh >=
   refresh_interval_seconds`):
   - Remove then add the same IP (add failure => 500, keep old `last_refresh`)
   - This remove+add pattern is intentional: `cscli allowlists add` does **not**
     update the expiration of an existing entry (it warns and exits 0)
   - Response: `"refreshed": true`

6. **Else:** no allowlist operations needed. Response: `"changed": false,
   "refreshed": false`. Only `last_seen` is updated.

### State file

The server persists agent state to a JSON file using atomic writes (write to
temp file, `fsync`, then `os.replace`). Missing or corrupt state files start
empty with a warning; they never crash the server.

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

### API response shape

`GET /health`:

```json
{"ok": true}
```

`POST /v1/heartbeat` (success):

```json
{
  "ok": true,
  "agent": "office-milano",
  "public_ipv4": "93.45.12.34",
  "changed": true,
  "refreshed": false,
  "allowlist": "dynamic-safe-offices"
}
```

Error responses:

```json
{"ok": false, "error": "unauthorized"}
{"ok": false, "error": "agent disabled"}
{"ok": false, "error": "crowdsec update failed"}
```

## Security notes

- **Token hashing at rest.** Server config stores only `pbkdf2_sha256$...`
  hashes (100,000 iterations). Tokens are 256-bit random strings (`cda_` +
  `secrets.token_urlsafe(32)`). Verification is constant-time via
  `hmac.compare_digest`.
- **Bearer over mesh.** Transport security comes from the NetBird mesh VPN
  (peer-to-peer WireGuard encryption). HMAC-based authentication and replay
  protection are deliberately deferred to future work; replaying a heartbeat
  requires a compromised mesh peer, which is a higher-threat scenario than v1
  targets. See limitations.
- **Docker socket mount is root-equivalent.** The server mounts
  `/var/run/docker.sock` to run `docker exec crowdsec cscli`. This is only
  acceptable because the server is reachable exclusively over the mesh VPN.
- **Never expose port 8787 publicly.** The compose examples bind the published
  port to a NetBird mesh IP only.
- **`/health` leaks nothing.** No config keys, no agent list, no version, no
  state.
- **Tokens are never logged.** Subprocess output is logged at DEBUG, but
  tokens never appear in logs, stderr, or diffs.
- **No shell in subprocess.** All `cscli` invocations use `subprocess.run` with
  argv arrays. Every argument is pre-validated before reaching the array.

## Limitations

- **IPv4 only.** IPv6 is rejected everywhere. IPv6 support is future work.
- **No rate limiting.** v1 relies on the mesh VPN boundary and the small number
  of trusted agents for access control.
- **Single server, no HA.** The state file is local JSON. Running multiple
  server instances against the same state is not supported.
- **JSON state file.** No database. Suitable for a handful of agents, not
  hundreds.
- **No replay protection.** Heartbeat replay would allowlist a stale IP if a
  mesh peer is compromised. HMAC-based request signing is noted as future work.

## Troubleshooting

### Inspect what CrowdSec sees

```bash
# Check the allowlist contents
docker exec crowdsec cscli allowlists inspect dynamic-safe-offices

# Check if an IP has active decisions
docker exec crowdsec cscli decisions list --ip 93.45.12.34

# Manually remove a stale entry (useful during testing)
docker exec crowdsec cscli decisions delete --ip 93.45.12.34
```

### Server troubleshooting

```bash
# Check server logs
docker logs crowdsec-distributed-allowlist

# Verify server is reachable over the mesh
curl http://100.92.0.5:8787/health
```

### Agent troubleshooting

```bash
# Run a single heartbeat with debug output
crowdsec-distributed-allowlist agent --config agent.json --once --log-level DEBUG

# Check the systemd unit
sudo systemctl status safe-ip-agent
sudo journalctl -u safe-ip-agent -f
```

## Development

### Run tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

### Smoke test

```bash
# Token generation
crowdsec-distributed-allowlist token generate

# Token hashing
crowdsec-distributed-allowlist token hash "cda_test-token"

# Server startup check (Ctrl+C to stop)
crowdsec-distributed-allowlist server --config examples/server-config.json
```

### Project layout

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
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── agent.py
│   ├── server.py
│   ├── auth.py
│   ├── ipcheck.py
│   ├── crowdsec.py
│   └── state.py
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

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2026 DigItalyGo SRL SB.
