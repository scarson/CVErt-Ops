# Runbook: Database Backup and Recovery

## Backup

### Logical Backup (pg_dump)

Best for small-to-medium databases and point-in-time snapshots:

```bash
# Custom format (compressed, supports parallel restore)
pg_dump -Fc -h localhost -U cvert cvert_ops > backup_$(date +%Y%m%d_%H%M%S).dump

# Plain SQL (human-readable, larger)
pg_dump -h localhost -U cvert cvert_ops > backup_$(date +%Y%m%d_%H%M%S).sql
```

### Automated Daily Backup

```bash
#!/bin/bash
# /opt/cvert-ops/backup.sh
BACKUP_DIR=/backups/cvert-ops
RETENTION_DAYS=30

mkdir -p "$BACKUP_DIR"
pg_dump -Fc -h localhost -U cvert cvert_ops > "$BACKUP_DIR/cvert_ops_$(date +%Y%m%d_%H%M%S).dump"

# Clean up old backups
find "$BACKUP_DIR" -name "cvert_ops_*.dump" -mtime +$RETENTION_DAYS -delete
```

Add to cron:

```
0 2 * * * /opt/cvert-ops/backup.sh >> /var/log/cvert-backup.log 2>&1
```

### Docker Compose Backup

If PostgreSQL runs in Docker:

```bash
docker compose exec -T postgres pg_dump -Fc -U cvert cvert_ops > backup.dump
```

## Restore

### Full Restore from pg_dump

```bash
# Stop the application
docker compose -f docker/compose.yml -f docker/compose.prod.yml \
  --profile app stop app

# Restore (custom format)
pg_restore -h localhost -U cvert -d cvert_ops --clean --if-exists backup.dump

# Restore (plain SQL)
psql -h localhost -U cvert -d cvert_ops < backup.sql

# Restart
docker compose -f docker/compose.yml -f docker/compose.prod.yml \
  --profile app start app
```

### Restore to a Fresh Database

If the database is corrupted beyond repair:

```bash
# Drop and recreate
psql -h localhost -U postgres -c "DROP DATABASE IF EXISTS cvert_ops;"
psql -h localhost -U postgres -c "CREATE DATABASE cvert_ops OWNER cvert;"

# Restore
pg_restore -h localhost -U cvert -d cvert_ops backup.dump

# Restart application (auto-migrate will run if needed)
docker compose -f docker/compose.yml -f docker/compose.prod.yml \
  --profile app restart app
```

### Verify After Restore

```bash
# Check readiness
curl -s http://localhost:8080/readyz

# Run doctor
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/admin/doctor

# Check migration status
docker compose exec app /cvert-ops doctor
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
