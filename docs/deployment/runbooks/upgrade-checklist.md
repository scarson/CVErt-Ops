# Runbook: Upgrade Checklist

Step-by-step verification for CVErt Ops version upgrades.

## Pre-Upgrade

- [ ] Read the release notes for the target version
- [ ] Check for breaking changes or new required environment variables
- [ ] Back up the database:
  ```bash
  pg_dump -Fc -h localhost -U cvert cvert_ops > backup_pre_upgrade_$(date +%Y%m%d).dump
  ```
- [ ] Verify the backup is valid:
  ```bash
  pg_restore --list backup_pre_upgrade_*.dump | head -5
  ```
- [ ] Note the current migration version (for rollback):
  ```bash
  psql -h localhost -U cvert -d cvert_ops \
    -c "SELECT version, dirty FROM schema_migrations;"
  ```
- [ ] Note the current app version:
  ```bash
  curl -s https://your-domain.com/api/v1/admin/version
  ```
- [ ] Schedule a maintenance window if needed
- [ ] Notify users of planned downtime (if applicable)

## Upgrade

- [ ] Pull the new version:
  ```bash
  docker compose -f docker/compose.yml -f docker/compose.prod.yml pull
  ```
- [ ] Restart services:
  ```bash
  docker compose -f docker/compose.yml -f docker/compose.prod.yml \
    --profile app --env-file .env up -d
  ```
- [ ] Watch startup logs for migration output:
  ```bash
  docker compose logs -f app --since 1m
  ```

## Post-Upgrade Verification

- [ ] Check liveness:
  ```bash
  curl -s http://localhost:8080/healthz
  # Expected: {"status":"alive"}
  ```
- [ ] Check readiness:
  ```bash
  curl -s http://localhost:8080/readyz
  # Expected: {"status":"ready","checks":[...all pass...]}
  ```
- [ ] Check version:
  ```bash
  curl -s -H "Authorization: Bearer $TOKEN" \
    https://your-domain.com/api/v1/admin/version
  # Expected: new version number
  ```
- [ ] Run doctor:
  ```bash
  curl -s -H "Authorization: Bearer $TOKEN" \
    https://your-domain.com/api/v1/admin/doctor
  # Expected: all checks pass
  ```
- [ ] Verify feed status:
  ```bash
  curl -s -H "Authorization: Bearer $TOKEN" \
    https://your-domain.com/api/v1/admin/feeds
  # Expected: feeds running, no new failures
  ```
- [ ] Check for failed deliveries:
  ```bash
  curl -s -H "Authorization: Bearer $TOKEN" \
    "https://your-domain.com/api/v1/admin/deliveries?status=failed&limit=5"
  # Expected: no new failures
  ```
- [ ] Spot-check the web UI — login, search CVEs, view a watchlist
- [ ] Check application logs for errors:
  ```bash
  docker compose logs app --since 5m | grep -i error
  ```

## Rollback (if needed)

If any verification step fails:

1. Stop the application:
   ```bash
   docker compose -f docker/compose.yml -f docker/compose.prod.yml \
     --profile app stop app
   ```
2. Roll back migrations (one at a time):
   ```bash
   docker compose run --rm migrate \
     -path /migrations -database "$DATABASE_URL" down 1
   ```
3. Restore the previous image version
4. If migration rollback fails, restore from backup:
   ```bash
   pg_restore -h localhost -U cvert -d cvert_ops --clean backup_pre_upgrade_*.dump
   ```
5. Restart with the previous version

See [Upgrading](../upgrading.md) for detailed rollback procedures.
