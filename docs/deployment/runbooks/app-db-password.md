# Runbook: Change the App Database Password

`APP_DB_PASSWORD` is the password of the restricted `cvert_ops_app` role, the role the application connects as. The Postgres image applies it only when an empty data volume is first initialized. Editing `.env` on an existing install changes what the app sends, not what Postgres expects, so the app stops being able to log in until both match.

The symptom of a mismatch is the app restarting with `password authentication failed for user "cvert_ops_app"` in its logs.

## Change the Password

Generate a value. It goes into a connection URL, so hex avoids characters that would need URL encoding:

```bash
openssl rand -hex 32
```

Set it in Postgres. `\password` prompts for the value, so it does not land in shell history or `ps` output:

```bash
docker compose -f docker/compose.yml -f docker/compose.prod.yml --env-file .env \
  exec postgres psql -U cvert_ops -d cvert_ops -c '\password cvert_ops_app'
```

Replace `APP_DB_PASSWORD` in `.env` with the same value, then recreate the app container so it reads the new value. The app cannot reconnect until this finishes, so expect a short outage:

```bash
docker compose -f docker/compose.yml -f docker/compose.prod.yml \
  --profile app --env-file .env up -d --force-recreate app
```

## Verify

```bash
curl -s https://your-domain.com/readyz
# Expected: {"status":"ready",...}

docker compose -f docker/compose.yml -f docker/compose.prod.yml --env-file .env \
  exec postgres psql -U cvert_ops -d cvert_ops \
  -c "SELECT usename, count(*) FROM pg_stat_activity WHERE usename = 'cvert_ops_app' GROUP BY usename;"
# Expected: one row with a non-zero count
```

## Other Credentials

`POSTGRES_PASSWORD` has the same first-initialization behavior for the superuser role. Change it the same way with `\password cvert_ops`, then update `.env` and recreate the `migrate` service with the next `up`.
