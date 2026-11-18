#!/usr/bin/env bash
# ABOUTME: Copies bind-mounted TLS files to a postgres-owned directory with correct permissions.
# ABOUTME: Required because Docker Desktop on Windows mounts files as 0755, which postgres rejects.

set -euo pipefail

TLS_SRC="/var/lib/postgresql/tls-src"
TLS_DST="/var/lib/postgresql/tls"

mkdir -p "$TLS_DST"
cp "$TLS_SRC/server.crt" "$TLS_DST/server.crt"
cp "$TLS_SRC/server.key" "$TLS_DST/server.key"
chown 70:70 "$TLS_DST/server.key" "$TLS_DST/server.crt"
chmod 600 "$TLS_DST/server.key"
chmod 644 "$TLS_DST/server.crt"

# Hand off to the real postgres entrypoint with all original arguments.
exec docker-entrypoint.sh "$@"
