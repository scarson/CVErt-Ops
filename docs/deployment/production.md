# Production Deployment

Guide for hardening CVErt Ops for production use.

## TLS Termination

CVErt Ops does not terminate TLS directly. Use a reverse proxy:

- **Caddy** (included in Docker Compose) — automatic ACME/Let's Encrypt
- **nginx** — manual cert management or certbot
- **AWS ALB / Azure App Gateway** — managed TLS

See [TLS Configuration](tls.md) for detailed setup instructions.

Set these env vars when behind a reverse proxy:

```bash
EXTERNAL_URL=https://cvert.example.com
COOKIE_SECURE=true
TRUSTED_PROXIES=172.16.0.0/12   # Docker bridge network
```

## Docker Compose Production Overlay

Use the production overlay for resource limits, log rotation, and production defaults:

```bash
docker compose -f docker/compose.yml -f docker/compose.prod.yml \
  --profile app --env-file .env up -d
```

The overlay needs a Docker Compose version that supports the `!reset` and `!override` merge tags (tested on v2.35). An older version stops with a parse error.

The overlay provides:
- Resource limits on all containers (CPU + memory)
- JSON log rotation (10 MB × 5 files per container)
- Production environment defaults (`APP_ENV=production`, `LOG_FORMAT=json`)
- `COOKIE_SECURE=true` for HTTPS-only cookies
- Every application setting read from `.env`, except `POSTGRES_PASSWORD` and `DATABASE_URL_MIGRATE`, which stay out of the app container
- No Mailpit: set `SMTP_HOST` and `SMTP_PORT` to your mail relay. `.env.example` points them at a local trap, and an unset `SMTP_HOST` means `localhost` inside the app container, so email fails until you set it
- Host ports on Caddy only (see below)

### Host Ports

Only Caddy publishes host ports (80 and 443). Postgres, the app and the metrics port are reachable only from other containers, so a host firewall is a second layer rather than the only one.

Reach Postgres through its container:

```bash
docker compose -f docker/compose.yml -f docker/compose.prod.yml --env-file .env \
  exec postgres psql -U cvert_ops -d cvert_ops
```

## Backup Strategy

### PostgreSQL Backups

Use `pg_dump` for logical backups, run inside the Postgres container. These commands use the default `POSTGRES_USER` and `POSTGRES_DB` (`cvert_ops`):

```bash
# Full backup
docker compose -f docker/compose.yml -f docker/compose.prod.yml --env-file .env \
  exec -T postgres pg_dump -Fc -U cvert_ops cvert_ops > backup_$(date +%Y%m%d_%H%M%S).dump

# Restore
docker compose -f docker/compose.yml -f docker/compose.prod.yml --env-file .env \
  exec -T postgres pg_restore -U cvert_ops -d cvert_ops --clean --if-exists < backup_20260310.dump
```

Automate with cron, from the directory holding the checkout and `.env`:

```bash
# /etc/cron.d/cvert-ops-backup
0 2 * * * root cd /opt/cvert-ops && docker compose -f docker/compose.yml -f docker/compose.prod.yml --env-file .env exec -T postgres pg_dump -Fc -U cvert_ops cvert_ops > /backups/cvert_ops_$(date +\%Y\%m\%d).dump 2>> /var/log/cvert-backup.log
0 3 * * * root find /backups -name "cvert_ops_*.dump" -mtime +30 -delete
```

For larger deployments, consider:
- **pg_basebackup** for physical backups with point-in-time recovery (PITR)
- **WAL archiving** for continuous backup
- **pgBackRest** for managed backup/restore with compression and parallel operation

### What to Back Up

| Component | Method | Frequency |
|-----------|--------|-----------|
| PostgreSQL | `pg_dump` or WAL archiving | Daily minimum |
| `.env` file | File copy | On change |
| Docker volumes | Volume backup | Weekly |
| TLS certificates | File copy | On renewal |

## Resource Sizing

### Minimum (small team, <10 users)

| Component | CPU | Memory |
|-----------|-----|--------|
| PostgreSQL | 1 core | 512 MB |
| App server | 1 core | 256 MB |
| Caddy | 0.5 core | 64 MB |
| **Total** | ~2.5 cores | ~832 MB |

### Recommended (team of 50, active feed ingestion)

| Component | CPU | Memory |
|-----------|-----|--------|
| PostgreSQL | 2 cores | 1 GB |
| App server | 2 cores | 1 GB |
| Caddy | 1 core | 256 MB |
| **Total** | ~5 cores | ~2.25 GB |

### PostgreSQL Tuning

For production workloads, tune these PostgreSQL parameters:

```
shared_buffers = 256MB          # 25% of available RAM
effective_cache_size = 768MB    # 75% of available RAM
work_mem = 16MB
maintenance_work_mem = 128MB
random_page_cost = 1.1          # SSD storage
```

### PostgreSQL Shared Memory (`/dev/shm`)

PostgreSQL keeps the shared state of parallel queries in `/dev/shm`: the hash table of a parallel hash join and the bitmap of a parallel bitmap scan. Docker gives a container 64 MB of `/dev/shm` by default, which is too small for large parallel hashes over the full CVE corpus. Those queries fail with `could not resize shared memory segment ... No space left on device`. `docker/compose.yml` therefore sets `shm_size: 256mb` on the Postgres service.

Pages in `/dev/shm` count against the container's memory limit while they are in use, so leave room for them beside `shared_buffers`. The overlay's 1 GB limit allows 256 MB of `shared_buffers` and 256 MB of `/dev/shm`. If you run PostgreSQL in your own container rather than from this Compose file, set the same size (`docker run --shm-size=256m`, or `shm_size` in your Compose file). A PostgreSQL outside a container uses the host's `/dev/shm` and needs no change.

## Monitoring

### Built-in Endpoints

| Endpoint | Purpose | Auth Required |
|----------|---------|---------------|
| `GET /healthz` | Liveness probe — always returns 200 if process is alive | No |
| `GET /readyz` | Readiness probe — checks DB connectivity and migration status | No |
| `GET /api/v1/admin/doctor` | Comprehensive health check | Site admin |

### Prometheus + Grafana

CVErt Ops exposes Prometheus metrics at `/metrics` on a separate port (`METRICS_PORT`, default 9090), with no authentication. In the Compose stack that port has no host mapping, so attach Prometheus to the stack's `cvert-public-net` network and scrape:

```yaml
scrape_configs:
  - job_name: cvert-ops
    static_configs:
      - targets: ['app:9090']
    metrics_path: /metrics
    scrape_interval: 15s
```

Key metrics to monitor:
- `http_requests_total` — request count by status code
- `http_request_duration_seconds` — request latency
- `feed_fetch_duration_seconds` — feed ingestion timing
- `notification_deliveries_total` — delivery success/failure counts

### Alerting Recommendations

| Condition | Threshold | Action |
|-----------|-----------|--------|
| `/readyz` returns non-200 | Any occurrence | Check database and migrations |
| Feed consecutive failures | > 3 | Check feed adapter logs, see [Feed Failure Runbook](runbooks/feed-failure.md) |
| Failed delivery count growing | > 10/hour | Check notification channels, see [Delivery Failure Runbook](runbooks/delivery-failure.md) |
| Disk usage | > 80% | Run retention cleanup, check `pg_dump` backups |
| Memory usage | > 85% of limit | Increase container memory limit |

### Log Aggregation

CVErt Ops outputs structured JSON logs (`LOG_FORMAT=json`). Ship to your log aggregator:

- **Docker logging drivers**: `json-file` (default), `syslog`, `fluentd`
- **Loki + Promtail**: Lightweight, pairs well with Grafana
- **ELK/OpenSearch**: Full-text search over logs

## Security Checklist

- [ ] `COOKIE_SECURE=true` — HTTPS-only cookies
- [ ] `JWT_SECRET` — unique, random, ≥32 bytes
- [ ] `REGISTRATION_MODE=invite-only` — prevent open registration
- [ ] TLS termination configured — no plaintext HTTP in production
- [ ] `TRUSTED_PROXIES` — set to your reverse proxy CIDR
- [ ] `POSTGRES_PASSWORD` and `APP_DB_PASSWORD` — each random and unique (`openssl rand -hex 32`); changing one later follows the [app database password runbook](runbooks/app-db-password.md)
- [ ] Firewall — only expose ports 80/443 (Caddy) publicly
- [ ] Metrics endpoint — not publicly accessible (internal network only)
- [ ] Regular backups tested — verify restore procedure works

## Next Steps

- [TLS Configuration](tls.md) — detailed TLS setup
- [Upgrading](upgrading.md) — version upgrade procedures
- [Runbooks](runbooks/) — operational procedures
