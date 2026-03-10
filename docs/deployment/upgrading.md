# Upgrading CVErt Ops

## Upgrade Procedure

### 1. Back Up the Database

Always back up before upgrading:

```bash
pg_dump -Fc -h localhost -U cvert cvert_ops > backup_pre_upgrade_$(date +%Y%m%d_%H%M%S).dump
```

### 2. Pull the Latest Image

```bash
docker compose -f docker/compose.yml -f docker/compose.prod.yml pull
```

Or if building from source:

```bash
git pull origin main
docker compose -f docker/compose.yml -f docker/compose.prod.yml build
```

### 3. Restart Services

```bash
docker compose -f docker/compose.yml -f docker/compose.prod.yml \
  --profile app --env-file .env up -d
```

Migrations run automatically on startup. The app acquires an advisory lock to prevent multiple instances from migrating concurrently.

### 4. Verify the Upgrade

```bash
# Check version
curl -s https://your-domain.com/api/v1/admin/version

# Run health check
curl -s https://your-domain.com/readyz

# Run doctor (requires admin auth)
curl -s -H "Authorization: Bearer $TOKEN" https://your-domain.com/api/v1/admin/doctor
```

Or use the CLI:

```bash
docker compose exec app /cvert-ops doctor
```

All doctor checks should return `pass`.

## Rollback Procedure

If the upgrade fails:

### 1. Stop the New Version

```bash
docker compose -f docker/compose.yml -f docker/compose.prod.yml \
  --profile app down
```

### 2. Roll Back Database Migrations

Check which migration version you were on before the upgrade. Then roll back:

```bash
# Roll back one migration at a time
docker compose run --rm migrate \
  -path /migrations -database "$DATABASE_URL" down 1
```

Repeat until you reach the pre-upgrade migration version.

### 3. Restore the Previous Image

```bash
# Tag or note the previous image version before upgrading
docker compose -f docker/compose.yml -f docker/compose.prod.yml \
  --profile app up -d --no-build
```

### 4. Restore from Backup (if needed)

If migration rollback doesn't cleanly restore the schema:

```bash
# Drop and recreate the database
psql -h localhost -U postgres -c "DROP DATABASE cvert_ops;"
psql -h localhost -U postgres -c "CREATE DATABASE cvert_ops OWNER cvert;"

# Restore from backup
pg_restore -h localhost -U cvert -d cvert_ops backup_pre_upgrade.dump

# Restart the previous version
docker compose -f docker/compose.yml -f docker/compose.prod.yml \
  --profile app up -d
```

## Migration Safety

CVErt Ops migrations follow these safety conventions:

- **Advisory lock**: Only one instance runs migrations at a time. If two instances start simultaneously, one waits.
- **Concurrent indexes**: All `CREATE INDEX` operations use `CONCURRENTLY` to avoid locking tables during migration.
- **Reversible**: Every migration has an `up` and `down` file. Down migrations are tested.
- **Auto-migrate**: The `serve` command runs pending migrations on startup before accepting traffic.

## Version Compatibility

CVErt Ops follows semantic versioning. Check the release notes for:

- **Breaking changes** — schema changes that require data migration
- **New environment variables** — required configuration for new features
- **Deprecated features** — features scheduled for removal

## See Also

- [Upgrade Checklist Runbook](runbooks/upgrade-checklist.md) — step-by-step verification
- [Database Recovery Runbook](runbooks/db-recovery.md) — backup and restore procedures
