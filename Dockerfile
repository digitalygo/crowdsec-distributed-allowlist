# Stage 1: extract the static Docker CLI binary from the official docker:cli image.
# docker:cli and python:3.13-alpine both ship linux/amd64, linux/arm64,
# linux/arm/v7, and linux/arm/v6 - the full intersection we support.
FROM docker:cli AS dockercli

# Stage 2: runtime image. python:3.13-alpine already includes ca-certificates,
# so outbound HTTPS (ip providers, NetBird coordination) works out of the box.
FROM python:3.13-alpine

# docker CLI is a static Go binary - no musl/glibc issue, works on any base.
# The server subcommand runs `docker exec <container> cscli ...` to manage
# CrowdSec allowlists inside the crowdsec container via the mapped Docker socket.
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker

WORKDIR /app

# Install the Python package and its console script.
# pyproject.toml references README.md for the description field, so both are
# copied for the install step.
COPY pyproject.toml README.md ./
COPY src/ src/
RUN pip install --no-cache-dir .

# The image runs as root in v1 because the server subcommand needs access to
# /var/run/docker.sock (root-equivalent on the host). Acceptable because the
# server must only be reachable over the NetBird mesh VPN - never on a public,
# unfiltered interface. See the compose examples for port-binding guidance.
# Agents that do not need docker.sock can also run rootless; v2 may add a
# dedicated non-root agent-only image variant.

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["crowdsec-distributed-allowlist"]
CMD ["--help"]
