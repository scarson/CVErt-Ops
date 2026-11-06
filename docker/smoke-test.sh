#!/usr/bin/env bash
# ABOUTME: Builds the production Compose stack, starts it on empty volumes, and checks it serves requests.
# ABOUTME: Run by CI. Uses its own project, container names and ports, so it can run beside a development stack.

set -euo pipefail

cd "$(dirname "$0")/.."

work="$(mktemp -d)"
https_port=18443
http_port=18080

cat > "$work/smoke.env" <<EOF
POSTGRES_PASSWORD=$(openssl rand -hex 32)
APP_DB_PASSWORD=$(openssl rand -hex 32)
JWT_SECRET=$(openssl rand -hex 32)
CADDY_HOST=localhost
CADDY_HTTP_PORT=$http_port
CADDY_HTTPS_PORT=$https_port
EXTERNAL_URL=https://localhost:$https_port
FEED_SCHEDULER_ENABLED=false
EOF

# container_name is fixed in compose.yml; clearing it lets Compose derive names from the project.
cat > "$work/names.yml" <<'EOF'
services:
  postgres:
    container_name: !reset null
  mailpit:
    container_name: !reset null
  migrate:
    container_name: !reset null
  app:
    container_name: !reset null
  caddy:
    container_name: !reset null
EOF

compose() {
    docker compose -p cvert-ops-smoke \
        -f docker/compose.yml -f docker/compose.prod.yml -f "$work/names.yml" \
        --profile app --env-file "$work/smoke.env" "$@"
}

cleanup() {
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $1" >&2
    compose ps -a >&2 || true
    compose logs --no-color --tail 30 >&2 || true
    exit 1
}

bash docker/postgres-tls/generate-cert.sh

compose up -d --build --wait --wait-timeout 180 || fail "the stack did not become healthy"

base="https://localhost:$https_port"

# Caddy needs a moment to issue its local certificate after it starts.
ready=""
for _ in $(seq 1 30); do
    ready="$(curl -sk "$base/readyz" || true)"
    case "$ready" in
        *'"status":"ready"'*) break ;;
    esac
    sleep 2
done
case "$ready" in
    *'"status":"ready"'*) echo "ok: /readyz through Caddy" ;;
    *) fail "/readyz through Caddy returned: $ready" ;;
esac

root="$(curl -sk "$base/")"
case "$root" in
    *'id="app"'*) echo "ok: the image serves the built web UI" ;;
    *) fail "/ does not serve the built web UI: ${root:0:200}" ;;
esac

# Metrics listen on their own port; on the main port this path gets the web UI's fallback page.
case "$(curl -sk "$base/metrics")" in
    *go_goroutines*) fail "Prometheus metrics are reachable through Caddy" ;;
    *) echo "ok: Prometheus metrics are not public" ;;
esac

sessions="$(compose exec -T postgres psql -U cvert_ops -d cvert_ops -Atc \
    "SELECT count(*) FROM pg_stat_activity WHERE usename = 'cvert_ops_app'")"
case "$sessions" in
    0 | "") fail "the app has no database sessions as cvert_ops_app" ;;
    *) echo "ok: the app is connected as cvert_ops_app ($sessions sessions)" ;;
esac

attributes="$(compose exec -T postgres psql -U cvert_ops -d cvert_ops -Atc \
    "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'cvert_ops_app'")"
case "$attributes" in
    "f|f") echo "ok: cvert_ops_app is neither superuser nor BYPASSRLS" ;;
    *) fail "cvert_ops_app attributes: $attributes" ;;
esac

published="$(compose ps --format '{{.Service}} {{.Publishers}}' | grep -v '^caddy ' | grep -E '[0-9]+->' || true)"
if [ -n "$published" ]; then
    fail "services other than caddy publish ports: $published"
fi
echo "ok: only caddy publishes host ports"

echo "smoke test passed"
