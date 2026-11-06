# Runbook: Database Backup and Recovery

## Backup

### Logical Backup (pg_dump)

In the production stack Postgres publishes no host port, so these commands run inside its container. Define the Compose invocation once, from the directory holding the checkout and `.env`. The examples use the default `POSTGRES_USER` and `POSTGRES_DB` (`cvert_ops`):

```bash
COMPOSE="docker compose -f docker/compose.yml -f docker/compose.prod.yml --profile app --env-file .env"
```

Best for small-to-medium databases and point-in-time snapshots:

```bash
# Custom format (compressed, supports parallel restore)
$COMPOSE exec -T postgres pg_dump -Fc -U cvert_ops cvert_ops > backup_$(date +%Y%m%d_%H%M%S).dump

# Plain SQL (human-readable, larger)
$COMPOSE exec -T postgres pg_dump -U cvert_ops cvert_ops > backup_$(date +%Y%m%d_%H%M%S).sql
```

### Automated Daily Backup

```bash
#!/bin/bash
# /opt/cvert-ops/backup.sh
BACKUP_DIR=/backups/cvert-ops
RETENTION_DAYS=30
COMPOSE="docker compose -f docker/compose.yml -f docker/compose.prod.yml --profile app --env-file .env"

cd /opt/cvert-ops || exit 1
mkdir -p "$BACKUP_DIR"
$COMPOSE exec -T postgres pg_dump -Fc -U cvert_ops cvert_ops > "$BACKUP_DIR/cvert_ops_$(date +%Y%m%d_%H%M%S).dump"

# Clean up old backups
find "$BACKUP_DIR" -name "cvert_ops_*.dump" -mtime +$RETENTION_DAYS -delete
```

Add to cron:

```
0 2 * * * /opt/cvert-ops/backup.sh >> /var/log/cvert-backup.log 2>&1
```

## Restore

### Full Restore from pg_dump

```bash
# Stop the application
$COMPOSE stop app

# Restore (custom format)
$COMPOSE exec -T postgres pg_restore -U cvert_ops -d cvert_ops --clean --if-exists < backup.dump

# Restore (plain SQL)
$COMPOSE exec -T postgres psql -U cvert_ops -d cvert_ops < backup.sql

# Restart
$COMPOSE start app
```

### Restore to a Fresh Database

If the database is corrupted beyond repair:

```bash
# Stop the application so nothing holds a connection
$COMPOSE stop app

# Drop and recreate, connected to the maintenance database
$COMPOSE exec -T postgres psql -U cvert_ops -d postgres -c "DROP DATABASE IF EXISTS cvert_ops;"
$COMPOSE exec -T postgres psql -U cvert_ops -d postgres -c "CREATE DATABASE cvert_ops OWNER cvert_ops;"

# Restore
$COMPOSE exec -T postgres pg_restore -U cvert_ops -d cvert_ops < backup.dump

# Restart application (auto-migrate will run if needed)
$COMPOSE start app
```

The `cvert_ops_app` role lives in the cluster, not the database, so it and its password survive the drop. If the data volume itself was lost, Postgres recreates the role from `APP_DB_PASSWORD` when it initializes the new volume.

### Verify After Restore

```bash
# Check readiness
curl -s https://your-domain.com/readyz

# Run doctor
curl -s -H "Authorization: Bearer $TOKEN" https://your-domain.com/api/v1/admin/doctor

# Check migration status
$COMPOSE exec app /cvert-ops doctor
```

## Disaster Recovery Checklist

1. **Stop the application** to prevent writes during recovery
2. **Assess the damage** — is the database running? Can you connect?
3. **Check available backups** — find the most recent good backup
4. **Restore from backup** — use the appropriate restore method
5. **Run migrations** — auto-migrate handles this on startup
6. **Verify with doctor** — ensure all health checks pass
7. **Check data integrity** — spot-check recent CVE data and user accounts
8. **Resume service** — start the application and monitor logs

## PostgreSQL Maintenance

### Vacuum

PostgreSQL auto-vacuums by default, and CVErt Ops configures aggressive autovacuum on high-churn tables. Manual vacuum is rarely needed:

```sql
-- Full vacuum (locks tables — use during maintenance windows only)
VACUUM FULL ANALYZE;

-- Regular vacuum (non-blocking)
VACUUM ANALYZE;
```

### Check Table Sizes

```sql
SELECT relname, pg_size_pretty(pg_total_relation_size(oid))
FROM pg_class
WHERE relkind = 'r'
ORDER BY pg_total_relation_size(oid) DESC
LIMIT 20;
```

### Check Index Usage

```sql
SELECT indexrelname, idx_scan, pg_size_pretty(pg_relation_size(indexrelid))
FROM pg_stat_user_indexes
ORDER BY idx_scan ASC
LIMIT 20;
```
