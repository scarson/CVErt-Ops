#!/usr/bin/env bash
# ABOUTME: Generates a self-signed TLS certificate for the dev postgres container.
# ABOUTME: Run once; output is gitignored. Re-run to regenerate if expired.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Output files — mounted into the postgres container via compose.yml
CERT_FILE="$SCRIPT_DIR/server.crt"
KEY_FILE="$SCRIPT_DIR/server.key"

if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "TLS cert already exists at $CERT_FILE — skipping generation."
    echo "Delete server.crt and server.key to regenerate."
    exit 0
fi

echo "Generating self-signed TLS certificate for dev postgres..."

# MSYS_NO_PATHCONV prevents Git Bash on Windows from mangling /CN= as a file path.
MSYS_NO_PATHCONV=1 openssl req -new -x509 -nodes \
    -days 3650 \
    -subj "/CN=cvert-ops-postgres" \
    -addext "subjectAltName=DNS:postgres,DNS:localhost,IP:127.0.0.1" \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    2>/dev/null

# Postgres requires the key file to have restricted permissions (mode 0600).
# On Windows/Docker Desktop the mount may not respect this, so the compose.yml
# also sets the file ownership via command-line chmod in the entrypoint.
chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE"

echo "Done. Files created:"
echo "  $CERT_FILE"
echo "  $KEY_FILE"
