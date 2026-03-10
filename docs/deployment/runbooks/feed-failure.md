# Runbook: Feed Adapter Failure

## Symptoms

- Admin dashboard shows feeds with `consecutive_failures > 0`
- Feed status page shows "Failing" badge
- CVE data not updating (stale `last_success_at`)
- `feed_fetch_duration_seconds` metric shows errors

## Diagnosis

### 1. Check Feed Status

**Via admin UI:** Navigate to `/admin/feeds` — shows status, failure count, and last error for each feed.

**Via API:**

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  https://your-domain.com/api/v1/admin/feeds | jq '.feeds[] | select(.consecutive_failures > 0)'
```

### 2. Check Recent Logs

Expand the failing feed in the admin UI to see recent fetch logs with error details.

**Via container logs:**

```bash
docker compose logs app --since 1h | grep -i "feed"
```

### 3. Common Causes

| Error | Cause | Fix |
|-------|-------|-----|
| `429 Too Many Requests` | Upstream rate limit exceeded | Wait for backoff to expire; check `NVD_API_KEY` is set |
| `timeout` | Upstream server slow/down | Check upstream status page; increase timeout if persistent |
| `connection refused` | Network/DNS issue | Check DNS resolution and outbound connectivity |
| `403 Forbidden` | API key invalid or expired | Rotate API key in `.env` |
| `JSON decode error` | Upstream response format changed | Check for application updates; report issue |

### 4. Check Upstream Status

- **NVD:** https://nvd.nist.gov/
- **MITRE CVE:** https://www.cve.org/
- **GitHub Advisories:** https://github.com/advisories
- **EPSS:** https://www.first.org/epss/

## Recovery

### Resume a Paused Feed

If a feed was manually paused:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://your-domain.com/api/v1/admin/feeds/{feed_name}/resume
```

### Trigger a Manual Fetch

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://your-domain.com/api/v1/admin/feeds/{feed_name}/run
```

### Restart the Application

If feeds are stuck (not making progress despite no errors):

```bash
docker compose -f docker/compose.yml -f docker/compose.prod.yml \
  --profile app restart app
```

## Prevention

- Set `NVD_API_KEY` for higher NVD rate limits
- Monitor `consecutive_failures` metric — alert at > 3
- Check feed status after each application upgrade
