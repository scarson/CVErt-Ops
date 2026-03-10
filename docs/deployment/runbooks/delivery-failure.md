# Runbook: Notification Delivery Failure

## Symptoms

- Admin dashboard shows failed delivery count > 0
- Delivery status page shows deliveries with `failed` status
- Users report not receiving notifications
- `notification_deliveries_total{status="failed"}` metric increasing

## Diagnosis

### 1. Check Failed Deliveries

**Via admin UI:** Navigate to `/admin/deliveries` — filter by "Failed" status to see error details.

**Via API:**

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  https://your-domain.com/api/v1/admin/deliveries?status=failed&limit=20 | jq '.items[]'
```

### 2. Check the Last Error

Each failed delivery includes a `last_error` field. Common errors:

| Error | Cause | Fix |
|-------|-------|-----|
| `connection refused` | Webhook endpoint unreachable | Verify the channel URL is correct and reachable |
| `timeout` | Webhook endpoint too slow | Endpoint must respond within 10 seconds |
| `403`/`401` | Authentication failure | Check webhook secret/token configuration |
| `SSRF blocked` | URL targets a private/internal IP | Webhook URLs must be publicly routable |
| `max attempts exceeded` | Delivery exhausted all retries | Fix the underlying issue, then retry |
| `SMTP error` | Email delivery failure | Check SMTP credentials and server connectivity |

### 3. Check SMTP Configuration

For email notification failures:

```bash
# Verify SMTP connectivity
docker compose exec app sh -c 'nc -zv $SMTP_HOST $SMTP_PORT'
```

Verify `.env` settings:
- `SMTP_HOST`, `SMTP_PORT` — correct server and port
- `SMTP_USERNAME`, `SMTP_PASSWORD` — valid credentials
- `SMTP_TLS` — matches server requirements

## Recovery

### Retry a Single Delivery

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://your-domain.com/api/v1/admin/deliveries/{delivery_id}/retry
```

Returns `409` if the delivery is already in progress (not retryable).

### Bulk Retry All Failed

**Via admin UI:** Click "Retry All Failed" on the deliveries page.

**Via API:**

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://your-domain.com/api/v1/admin/deliveries/retry-failed
```

Returns `{"rows_affected": N}` with the count of deliveries re-queued.

### Fix and Retry

1. Identify the root cause from the `last_error`
2. Fix the issue (update channel config, fix SMTP, etc.)
3. Retry the failed deliveries

## Prevention

- Test notification channels after creation (send a test notification)
- Monitor the failed delivery count — alert if growing
- Ensure webhook endpoints respond within 10 seconds
- Use reliable SMTP providers for email notifications
- Review delivery failure trends in the admin dashboard
