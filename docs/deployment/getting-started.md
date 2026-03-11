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

Edit `.env` and set the required variables:

```bash
# Required
DATABASE_URL=postgres://cvert:yourpassword@localhost:5432/cvert_ops?sslmode=require
JWT_SECRET=generate-a-random-32-byte-hex-string

# Required for production
EXTERNAL_URL=https://cvert.example.com
COOKIE_SECURE=true

# SMTP — replace with your mail provider in production
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_FROM=noreply@example.com
```

Generate a strong JWT secret:

```bash
openssl rand -hex 32
```

## 2. Generate TLS Certificates (Dev Postgres)

```bash
bash docker/postgres-tls/generate-cert.sh
```

This creates self-signed TLS certificates for the dev Postgres container. Idempotent — skips if certs already exist.

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

Migrations run automatically on app startup (`cvert-ops serve` calls auto-migrate). For manual control:

```bash
go run ./cmd/cvert-ops migrate
```

Or with the Docker image:

```bash
docker compose -f docker/compose.yml --profile app run --rm migrate
```

## 5. Create First Admin User

Register the first user through the API or web UI. Then promote them to site admin via the database:

```sql
UPDATE users SET is_site_admin = true WHERE email = 'admin@example.com';
```

Once you have a site admin, they can manage all users, organizations, and system settings through the admin UI at `/admin/dashboard`.

## 6. Verify Installation

Run the built-in doctor command to check system health:

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
| API | `http://localhost:8080/api/v1/` (dev) |
| Mailpit | `http://localhost:8025` (dev only) |
| Healthz | `http://localhost:8080/healthz` |
| Readyz | `http://localhost:8080/readyz` |
| Metrics | `http://localhost:8080/metrics` |

## Environment Variables Reference

### Required

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string |
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
| `DB_QUERY_EXEC_MODE` | `simple_protocol` | pgx query exec mode (`simple_protocol` for PgBouncer) |

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
| `FEED_SCHEDULER_ENABLED` | `true` | Enable automatic feed scheduling |

## Next Steps

- [Production Hardening](production.md) — TLS, backups, monitoring
- [TLS Configuration](tls.md) — TLS termination options
- [Upgrading](upgrading.md) — Version upgrade procedures
