# Phase 8E — Secure Pillar

> **Date:** 2026-03-16
> **Branch:** `phase8e-secure` → merged via PR #43
> **Plan:** `dev/plans/2026-03-16-phase8-ops-secure-v2-plan.md`

## What was built

Security operations infrastructure: dual-key JWT rotation for zero-downtime secret
rotation, dual-key SSO encryption rotation with `DecryptWithFallback`, SIGHUP-based
config hot-reload with `ReloadableConfig` (atomic pointer), `rotate-encryption-key`
CLI command, `POST /admin/reload-config` endpoint, security events pipeline (async writer
with rate limiting, syslog/SIEM output, `security_events` table + migration),
`GET /admin/security-events` endpoint with cursor pagination, security event wiring
into auth/admin handlers, doctor security checks (headers, SSRF, CORS, JWT dual-key),
Prometheus metrics for the security event pipeline, security_events retention cleanup
(90-day default), and a secret rotation runbook.

## Files created/modified

| File | Action | Batch |
|------|--------|-------|
| `internal/auth/jwt.go` | Modified | 1 |
| `internal/auth/jwt_test.go` | Modified | 1 |
| `internal/config/config.go` | Modified | 1, 3 |
| `internal/api/auth.go` | Modified | 1 |
| `internal/api/middleware_auth.go` | Modified | 1 |
| `internal/crypto/aes.go` | Modified | 2 |
| `internal/crypto/aes_test.go` | Modified | 2 |
| `internal/api/sso.go` | Modified | 2 |
| `cmd/cvert-ops/rotate.go` | Created | 2 |
| `cmd/cvert-ops/rotate_test.go` | Created | 2 |
| `internal/config/reloadable.go` | Created | 3 |
| `internal/config/reloadable_test.go` | Created | 3 |
| `internal/config/reload.go` | Created | 3 |
| `internal/config/reload_test.go` | Created | 3 |
| `internal/config/sighup_unix.go` | Created | 3 |
| `internal/config/sighup_windows.go` | Created | 3 |
| `internal/api/admin_reload.go` | Created | 3 |
| `internal/api/admin_reload_test.go` | Created | 3 |
| `migrations/000039_create_security_events.up.sql` | Created | 4 |
| `migrations/000039_create_security_events.down.sql` | Created | 4 |
| `internal/store/security_events.go` | Created | 4 |
| `internal/store/queries/security_events.sql` | Created | 4 |
| `internal/secure/writer.go` | Created | 4 |
| `internal/secure/writer_test.go` | Created | 4 |
| `internal/secure/ratelimit.go` | Created | 4 |
| `internal/secure/ratelimit_test.go` | Created | 4 |
| `internal/secure/syslog.go` | Created | 4 |
| `internal/secure/syslog_test.go` | Created | 4 |
| `internal/api/admin_security_events.go` | Created | 4 |
| `internal/api/admin_security_events_test.go` | Created | 4 |
| `internal/doctor/checks.go` | Modified | 5 |
| `internal/doctor/doctor_test.go` | Modified | 5 |
| `internal/metrics/security.go` | Created | 6 |
| `internal/metrics/security_test.go` | Created | 6 |
| `deploy/grafana/alerts.yml` | Modified | 6 |
| `docs/deployment/runbooks/secret-rotation.md` | Created | 6 |
| `internal/retention/runner.go` | Modified | 4 |
| `internal/retention/runner_test.go` | Modified | 4 |
| `internal/store/retention.go` | Modified | 4 |
| `internal/store/retention_test.go` | Modified | 4 |

## Key implementation decisions

1. **Dual-key JWT verification**: `ParseWithDualKey` tries the current secret first, falls
   back to `JWT_SECRET_PREVIOUS`. Enables zero-downtime secret rotation — old tokens remain
   valid until they expire naturally.

2. **`DecryptWithFallback` for SSO encryption**: Tries current AES key, falls back to
   `SSO_ENCRYPTION_KEY_PREVIOUS`. SSO state tokens encrypted at rest can be decrypted during
   key rotation window.

3. **ReloadableConfig with `atomic.Pointer`**: Thread-safe config hot-reload without restart.
   `SIGHUP` handler (Unix) or `POST /admin/reload-config` (all platforms) triggers reload.
   Only secret fields are reloadable — structural config changes still require restart.

4. **Async security event writer**: Non-blocking channel-based writer with configurable
   buffer size. Rate limiter prevents event storms from saturating the DB. Events are
   batched and flushed periodically.

5. **Syslog SIEM integration**: RFC 5424 syslog output for security events. Configurable
   facility/severity mapping. Supports both UDP and TCP transports.

6. **Security events retention**: 90-day default retention for `security_events` table,
   integrated into the existing retention cleanup runner.

## Gotchas discovered

- **Windows SIGHUP**: Windows has no SIGHUP signal — `sighup_windows.go` is a no-op stub.
  Config reload on Windows is only available via the HTTP endpoint.
- **Phase 8E took migration 000039**: This caused a numbering collision with the MFA plan
  (which also planned for 000039), requiring MFA tables to be renumbered to 000040.

## Quality checks

- **go build ./...:** Clean
- **golangci-lint:** Clean
- **All tests pass** across auth, config, crypto, secure, doctor, metrics, retention packages
- **3 review rounds** with 4 parallel code-reviewer agents (findings documented in plan)
