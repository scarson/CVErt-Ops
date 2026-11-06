# Getting Started

Quickstart guide for running CVErt Ops with Docker Compose.

## Prerequisites

- Docker Engine 24+ and Docker Compose v2
- A domain name (for TLS in production) or `localhost` for local dev
- 2 GB RAM minimum (4 GB recommended)

## 1. Clone and Configure

```bash
git clone https://github.com/scarson/cvert-ops.git
cd cvert-ops
cp .env.example .env
```

Edit `.env` and set the required variables. Docker Compose builds the app's `DATABASE_URL` from these; `DATABASE_URL` in `.env` is only for running the binary outside Compose:

```bash
# Required
POSTGRES_PASSWORD=generate-a-random-hex-string
APP_DB_PASSWORD=generate-a-different-random-hex-string
JWT_SECRET=generate-a-random-32-byte-hex-string

# Required for production
CADDY_HOST=cvert.example.com
EXTERNAL_URL=https://cvert.example.com

# SMTP — replace with your mail provider in production
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_TLS=true
SMTP_FROM=noreply@example.com
```

Generate each secret separately. The two database passwords go into connection URLs, so hex avoids characters that would need URL encoding:

```bash
openssl rand -hex 32
```

For local development the values already in `.env.example` work for everything except `JWT_SECRET`.

Postgres applies `APP_DB_PASSWORD` when it first initializes an empty data volume. To change it later, follow the [app database password runbook](runbooks/app-db-password.md).

## 2. Generate the Postgres TLS Certificate

```bash
bash docker/postgres-tls/generate-cert.sh
```

This creates the self-signed certificate the Postgres container serves, in development and production. The app connects with `sslmode=require` over the internal Docker network. Idempotent — skips if certs already exist.

## 3. Start Services

**Development:**

```bash
docker compose -f docker/compose.yml --env-file .env up -d
```

This starts PostgreSQL and Mailpit (dev mail catcher).

**Production (with app + Caddy reverse proxy):**

```bash
docker compose -f docker/compose.yml -f docker/compose.prod.yml \
  --profile app --env-file .env up -d
```

## 4. Run Migrations

With `--profile app`, the one-shot `migrate` service runs as the Postgres superuser before the app starts. For manual control when running the binary outside Compose:

```bash
go run ./cmd/cvert-ops migrate
```

Or with the Docker image:

```bash
docker compose -f docker/compose.yml --env-file .env --profile app run --rm migrate
```

## 5. Create First Admin User

Register the first user through the API or web UI. Then promote them to site admin via the database:

```bash
docker compose -f docker/compose.yml --env-file .env exec postgres psql -U cvert_ops -d cvert_ops \
  -c "UPDATE users SET is_site_admin = true WHERE email = 'admin@example.com';"
```

Once you have a site admin, they can manage all users, organizations, and system settings through the admin UI at `/admin/dashboard`.

## 6. Verify Installation

Run the built-in doctor command to check system health:

```bash
docker compose -f docker/compose.yml --env-file .env --profile app exec app /cvert-ops doctor
```

Or outside Compose:

```bash
go run ./cmd/cvert-ops doctor
```

Or via the API (requires site admin):

```
GET /api/v1/admin/doctor
```

The doctor checks:
- Database connectivity and migration status
- Security header configuration
- Encryption sentinel integrity (if configured)

All checks should show `pass`. Any `warn` or `fail` status includes a message explaining the issue.

## 7. Access the Application

| Endpoint | URL |
|----------|-----|
| Web UI | `http://localhost:5173` (dev) or `https://your-domain.com` (prod) |
| API | `http://localhost:8080/api/v1/` (dev) or `https://your-domain.com/api/v1/` (prod) |
| Mailpit | `http://localhost:8025` (dev only) |
| Healthz | `http://localhost:8080/healthz` (dev) or `https://your-domain.com/healthz` (prod) |
| Readyz | `http://localhost:8080/readyz` (dev) or `https://your-domain.com/readyz` (prod) |

In production only Caddy publishes host ports, so everything else goes through your domain or `docker compose exec`.

## Environment Variables Reference

### Required

| Variable | Description |
|----------|-------------|
| `POSTGRES_PASSWORD` | Postgres superuser password (Docker Compose) |
| `APP_DB_PASSWORD` | Password of the restricted `cvert_ops_app` role (Docker Compose) |
| `DATABASE_URL` | PostgreSQL connection string (running the binary outside Compose; Compose builds it) |
| `JWT_SECRET` | HMAC secret for JWT signing (≥32 bytes) |

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `LISTEN_ADDR` | `:8080` | HTTP listen address |
| `APP_ENV` | `development` | Environment (`development`, `production`) |
| `EXTERNAL_URL` | `http://localhost:8080` | Public-facing URL |
| `FRONTEND_URL` | `/` | Frontend base path |
| `SHUTDOWN_TIMEOUT_SECONDS` | `60` | Graceful shutdown timeout |
| `REGISTRATION_MODE` | `invite-only` | `invite-only` or `open` |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `LOG_FORMAT` | `json` | `json` or `text` |

### Database

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL_MIGRATE` | (none) | Separate URL for migrations (superuser) |
| `DB_MAX_CONNS` | `25` | Max pool connections |
| `DB_MAX_CONN_IDLE_TIME` | `5m` | Max idle connection lifetime |
| `DB_STATEMENT_TIMEOUT_MS` | `14000` | Statement timeout in milliseconds |
| `DB_QUERY_EXEC_MODE` | `cache_describe` | pgx query exec mode: `cache_describe` (works through PgBouncer) or `extended_protocol` (direct connections only) |

### Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `COOKIE_SECURE` | `false` | Set `true` in production (HTTPS) |
| `LOCKOUT_THRESHOLD` | `5` | Failed login attempts before lockout |
| `LOCKOUT_DURATION` | `15m` | Account lockout duration |
| `CORS_ALLOWED_ORIGINS` | (none) | Comma-separated allowed origins |
| `TRUSTED_PROXIES` | (none) | CIDR ranges for trusted proxies |

### SMTP

| Variable | Default | Description |
|----------|---------|-------------|
| `SMTP_HOST` | `localhost` | SMTP server hostname |
| `SMTP_PORT` | `1025` | SMTP server port |
| `SMTP_FROM` | `cvert-ops@localhost` | From address for emails |
| `SMTP_USERNAME` | (none) | SMTP auth username |
| `SMTP_PASSWORD` | (none) | SMTP auth password |
| `SMTP_TLS` | `false` | Enable STARTTLS |

### OAuth / SSO (optional)

| Variable | Description |
|----------|-------------|
| `GITHUB_CLIENT_ID` | GitHub OAuth app client ID |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth app secret |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `SSO_ENCRYPTION_KEY` | 32-byte hex key for SSO state encryption |

### Feed Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `NVD_API_KEY` | (none) | NVD API key (recommended for higher rate limits) |
| `GITHUB_TOKEN` | (none) | GitHub token for the GHSA feed (recommended for higher rate limits) |
| `FEED_SCHEDULER_ENABLED` | `true` | Enable automatic feed scheduling |

## Next Steps

- [Production Hardening](production.md) — TLS, backups, monitoring
- [TLS Configuration](tls.md) — TLS termination options
- [Upgrading](upgrading.md) — Version upgrade procedures
