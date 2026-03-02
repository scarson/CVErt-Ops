# Phase 5 — Hardening & SaaS Readiness: Design

**Date:** 2026-03-01
**Scope:** Tier enforcement, data retention automation, audit log, generic OIDC
**PLAN.md refs:** §7.2, §14, §17, §21, §18 Phase 5

## Scope Decisions

| Item | Decision |
|------|----------|
| SAML 2.0 | Deferred — generic OIDC covers 90%+ of enterprise IdPs |
| Audit log data model | Event log + old/new state JSONB snapshots (diffs computed at read time) |
| Audit log writes | All tiers write; read API Enterprise-only |
| Failed action logging | Yes — `success=false` for 403 on mutation attempts |
| Tier enforcement depth | `orgs.tier` column + full enforcement (no billing integration) |
| OIDC org discovery | Email domain discovery (user enters email → system looks up SSO) |
| OIDC client secret storage | App-layer AES-256-GCM with `SSO_ENCRYPTION_KEY` env var |
| OIDC auto-provisioning | Removed — SSO is authentication-only; users must be invited first |
| Memory protection for secrets | Standard approach (env var → struct field); memguard noted as future hardening |

## Implementation Order

```
Tier enforcement → Data retention → Audit log → Generic OIDC
```

Each builds on the previous: retention uses tier-resolved windows, audit log uses retention for cleanup, OIDC uses tier gating (Enterprise-only).

---

## 1. Tier Enforcement

### Schema

```sql
-- ALTER organizations
ALTER TABLE organizations ADD COLUMN tier TEXT NOT NULL DEFAULT 'free'
    CHECK (tier IN ('free', 'pro', 'enterprise'));
ALTER TABLE organizations ADD COLUMN tier_overrides JSONB NOT NULL DEFAULT '{}';
```

No separate overrides table — overrides live on the org row (already loaded in auth middleware).

### Tier Resolver (`internal/tier`)

```go
type Resolver struct {
    Tier      string
    Overrides map[string]any // from tier_overrides JSONB
}

func (r *Resolver) IntLimit(name string, free, pro, enterprise int) int
func (r *Resolver) BoolFlag(name string, free, pro, enterprise bool) bool
```

Constructed from org's tier + overrides in auth middleware, passed via context.

**Precedence:** org override → tier default → free fallback.

### Tier-Gated Enforcement Points

| Limit | Free | Pro | Enterprise | Enforcement location |
|-------|------|-----|------------|---------------------|
| Alert rules per org | 5 | 50 | unlimited (-1) | Alert rule create handler |
| Watchlists per org | 3 | 20 | unlimited | Watchlist create handler |
| Members per org | 5 | 25 | unlimited | Member invite handler |
| AI NL search/day | 10 | 100 | 1000 | AI handler (existing) |
| AI summarize/day | 5 | 50 | 500 | AI handler (existing) |
| API req/min/org | 60 | 300 | 1000 | Per-org rate limiter middleware |
| Email channels | No | Yes | Yes | Channel create handler |
| Slack channels | No | Yes | Yes | Channel create handler |
| Audit log read | No | No | Yes | Audit log API handler |
| SSO connections | No | No | Yes | SSO CRUD handlers |

### Per-Org API Rate Limiter

Same architecture as `ipRateLimiter` but keyed by `orgID`. Accepts tier-resolved rate per request:

```go
func (rl *orgRateLimiter) Allow(orgID string, limit rate.Limit, burst int) bool
```

If stored limiter's rate differs from resolved rate (tier changed), creates a new limiter. Eviction goroutine cleans idle entries.

### AI Burst Rate Limits

Per-minute per-org rate limit on AI endpoints, complementing daily quotas. Separate `orgRateLimiter` instance. Prevents burning through daily quota in seconds.

### CVE Enumeration Defense

Handled inherently by daily quota + burst rate limit. No standalone feature needed.

### Admin API

- `GET /api/v1/orgs/{org_id}/tier` — all roles can view
- Tier changes: system admin via direct DB or future admin API (not org-owner accessible)

### Config Additions

```
# Per-org API rate limits are tier-derived, no separate env vars needed.
# AI quotas already have per-tier env vars.
```

---

## 2. Data Retention Automation

### Architecture

**Job-based, not ticker-based.** A daily ticker in the worker checks if a retention job exists in `job_queue` with `status IN ('pending', 'running')` and `job_type = 'retention_cleanup'`. If not, enqueues one. The job uses `lock_key = 'cleanup:retention'` to prevent concurrent runs (per PLAN.md §21.3).

**AI cleanup migration.** The existing `runAICleanup` ticker in the notify worker moves into the retention job. Frequency changes from "every N minutes" to "daily" — acceptable because `ai_cache` lookups already filter by `expires_at > now()`.

### Retention Targets

| Table | Default | Tier-configurable | Timestamp col | Status filter |
|-------|---------|-------------------|---------------|---------------|
| `cve_raw_payloads` | 90 days | Enterprise: 30-365d | `ingested_at` | — |
| `feed_fetch_log` | 90 days | Enterprise: configurable | `started_at` | — |
| `alert_events` | 1 year | Enterprise: 90d-indefinite | `first_fired_at` | — |
| `notification_deliveries` | 90 days | Enterprise: configurable | `created_at` | — |
| `audit_log` | 1 year | Enterprise: configurable | `created_at` | — |
| `ai_request_log` | 90 days | — | `created_at` | — |
| `ai_cache` | TTL-based | — | `expires_at` | — |
| `ai_usage_counters` | daily: 90d | — | `counter_date` | monthly: indefinite |
| `job_queue` | 24 hours | — | `updated_at` | `status IN ('succeeded','dead')` only |
| `refresh_tokens` | expired+60s | — | `expires_at` | — |

Note: `report_runs` does not exist as a separate table. Digest delivery retention is handled via `notification_deliveries` with `kind = 'digest'`.

### Bounded-Batch CTE Pattern (§21.3)

```sql
WITH doomed AS (
  SELECT id FROM target_table
  WHERE timestamp_col < $1
  ORDER BY timestamp_col
  LIMIT $2  -- batch_size (default 10000)
)
DELETE FROM target_table t USING doomed WHERE t.id = doomed.id;
```

Loop until 0 rows deleted. Max runtime cap stops processing after N seconds.

### Per-Org-Group Retention

For tier-gated tables (org-scoped with configurable retention):

```go
// Group orgs by distinct retention window
windowGroups := map[int][]uuid.UUID{} // days -> org_ids
for _, org := range orgs {
    days := resolver.IntLimit("retention_alert_events_days", 365, 365, 365, org)
    windowGroups[days] = append(windowGroups[days], org.ID)
}
// Delete per window group (typically 1-3 groups)
for days, orgIDs := range windowGroups {
    cutoff := now.AddDate(0, 0, -days)
    batchDelete("alert_events", "org_id = ANY($1) AND first_fired_at < $2", orgIDs, cutoff)
}
```

### Retention Indexes (new migration)

| Table | Index |
|-------|-------|
| `cve_raw_payloads` | `(ingested_at)` standalone |
| `feed_fetch_log` | `(started_at)` standalone |
| `job_queue` | `(updated_at) WHERE status IN ('succeeded','dead')` partial |

Existing indexes sufficient for: `alert_events(first_fired_at)`, `notification_deliveries(created_at)`, `ai_request_log(org_id, created_at)`, `ai_cache(expires_at)`.

### Config Additions

```
RETENTION_RAW_PAYLOAD_DAYS=90
RETENTION_FEED_FETCH_LOG_DAYS=90
RETENTION_ALERT_EVENTS_DAYS=365
RETENTION_NOTIFICATION_DELIVERIES_DAYS=90
RETENTION_AUDIT_LOG_DAYS=365
RETENTION_JOB_QUEUE_HOURS=24
RETENTION_MAX_RUNTIME_SECONDS=300
```

Existing: `RETENTION_CLEANUP_ENABLED`, `RETENTION_CLEANUP_BATCH_SIZE`, `AI_LOG_RETENTION_DAYS`.

### Error Handling

Each table's cleanup is independent. Failure on one table logs the error and continues to the next. Only DB transaction failures propagate. The job records per-table row counts in `system_jobs_log`.

---

## 3. Audit Log

### Schema

```sql
CREATE TABLE IF NOT EXISTS audit_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL,          -- NOT a FK; audit records survive org deletion
    actor_id    UUID,                   -- NULL for system actions; NOT a FK
    actor_email TEXT,                   -- NULL for system actions; denormalized
    action      TEXT NOT NULL CHECK (action IN ('create', 'update', 'delete')),
    entity_type TEXT NOT NULL,          -- 'alert_rule', 'channel', 'watchlist', etc.
    entity_id   TEXT NOT NULL,          -- UUID as text (supports different PK types)
    entity_name TEXT,                   -- denormalized display name at write time
    success     BOOLEAN NOT NULL DEFAULT true,  -- false for denied mutation attempts
    old_state   JSONB,                  -- NULL for create / denied attempts
    new_state   JSONB,                  -- NULL for delete / denied attempts
    metadata    JSONB,                  -- IP, user agent, API key prefix, request ID
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_log_org_created_idx
    ON audit_log (org_id, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_log_entity_idx
    ON audit_log (org_id, entity_type, entity_id);

-- RLS
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON audit_log
    USING (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid)
    WITH CHECK (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid);

-- Autovacuum tuning (append-heavy)
ALTER TABLE audit_log SET (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_vacuum_cost_delay   = 2,
    fillfactor                     = 80
);

GRANT SELECT, INSERT, DELETE ON audit_log TO cvert_ops_app;
-- DELETE for retention cleanup. No UPDATE — immutable.
```

**Key decisions:**
- `org_id` and `actor_id` are NOT FKs — audit records survive org/user deletion (compliance).
- `actor_email` denormalized for human-readable audit trail post-deletion.
- `entity_name` denormalized at write time — readable even after entity deletion.
- No `UPDATE` grant — append-only, immutable. Only retention job deletes.

### Write-Time Secret Redaction

`internal/audit` package. `redactSecrets(entityType string, state map[string]any) map[string]any`:

- Always-redacted key names (case-insensitive substring): `secret`, `password`, `api_key`, `token`, `private_key`, `key_hash`
- Entity-specific: `channel` entity → `url` field shows domain only (`https://hooks.slack.com/***`)
- Recursive through nested JSONB
- Applied at write time on both `old_state` and `new_state`

### Audit Writer

```go
type Entry struct {
    OrgID      uuid.UUID
    ActorID    *uuid.UUID
    ActorEmail string
    Action     string
    EntityType string
    EntityID   string
    EntityName string
    Success    bool
    OldState   any
    NewState   any
    Metadata   map[string]any
}

func (w *Writer) Log(ctx context.Context, entry Entry) error
```

Non-blocking: errors logged via slog but never fail the parent operation.

### Audited Entities

| Entity | Actions | Notes |
|--------|---------|-------|
| `alert_rule` | create, update, delete | Full rule config |
| `channel` | create, update, delete | Secrets redacted |
| `watchlist` | create, update, delete | Full config |
| `org_member` | create, update, delete | Role, email |
| `api_key` | create, delete | Key prefix only |
| `saved_search` | create, update, delete | Search config |
| `sso_connection` | create, update, delete | Secrets redacted |

Failed authorization (403) on any mutation produces `success=false` entry with both states nil.

### Integration Pattern

Each handler captures old state before mutation:

```go
oldRule := store.GetAlertRule(ctx, ruleID)
store.UpdateAlertRule(ctx, ruleID, input)
audit.Log(ctx, Entry{Action: "update", OldState: oldRule, NewState: input, ...})
```

### API Endpoints

- `GET /api/v1/orgs/{org_id}/audit-log` — cursor pagination, filter by `entity_type`, `action`, `actor_id`, date range
- RBAC: owner + admin only
- Tier: Enterprise-only (403 for other tiers)

---

## 4. Generic OIDC

### Schema

```sql
CREATE TABLE IF NOT EXISTS sso_connections (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            UUID NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    display_name      TEXT NOT NULL,
    issuer_url        TEXT NOT NULL,
    client_id         TEXT NOT NULL,
    client_secret_enc BYTEA NOT NULL,   -- AES-256-GCM encrypted
    scopes            TEXT[] NOT NULL DEFAULT '{openid,profile,email}',
    enabled           BOOLEAN NOT NULL DEFAULT false,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS sso_connections_org_id_idx
    ON sso_connections (org_id);  -- also covered by UNIQUE

ALTER TABLE sso_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE sso_connections FORCE ROW LEVEL SECURITY;
-- standard dual-escape RLS policy

GRANT SELECT, INSERT, UPDATE, DELETE ON sso_connections TO cvert_ops_app;

CREATE TABLE IF NOT EXISTS sso_email_domains (
    domain              TEXT PRIMARY KEY,
    sso_connection_id   UUID NOT NULL REFERENCES sso_connections(id) ON DELETE CASCADE,
    org_id              UUID NOT NULL  -- denormalized for RLS
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS sso_email_domains_connection_idx
    ON sso_email_domains (sso_connection_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS sso_email_domains_org_id_idx
    ON sso_email_domains (org_id);

ALTER TABLE sso_email_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE sso_email_domains FORCE ROW LEVEL SECURITY;
-- standard dual-escape RLS policy

GRANT SELECT, INSERT, DELETE ON sso_email_domains TO cvert_ops_app;
```

### Encryption (`internal/crypto`)

AES-256-GCM with nonce-prepended ciphertext:

```go
func Encrypt(key [32]byte, plaintext []byte) ([]byte, error)
func Decrypt(key [32]byte, ciphertext []byte) ([]byte, error)
```

Key loaded from `SSO_ENCRYPTION_KEY` env var at startup. Required only if SSO connections exist.

### Authentication Flow

1. User enters email on login page
2. `POST /api/v1/auth/discover` — extracts domain, looks up `sso_email_domains`
   - Match: returns `{display_name, login_url}`
   - No match: returns empty (show normal login)
3. User clicks SSO → `GET /api/v1/auth/oidc/{connection_id}/login`
   - Sets CSRF state cookie (encodes `connection_id` + CSRF token)
   - Sets nonce cookie
   - Redirects to IdP authorization endpoint
4. IdP authenticates → redirects to `GET /api/v1/auth/oidc/callback`
   - Validates CSRF state, extracts `connection_id`
   - Exchanges code for tokens
   - Verifies ID token via `coreos/go-oidc/v3` (issuer, nonce, expiry)
   - Extracts `sub` claim
5. Identity matching: `user_identities(provider='oidc:{connection_id}', provider_user_id=sub)`
   - Match → login (issue JWT + refresh token)
   - No match → "You don't have access to this organization. Contact your administrator."

### Identity Linking (separate from login)

Existing org members link SSO via account settings:

1. `POST /api/v1/orgs/{org_id}/sso/link` — initiates OIDC flow for linking (not login)
2. Callback verifies identity and creates `user_identities` record
3. Future logins use SSO automatically

### Provider Caching

Lazy-initialized `oidc.Provider` instances per SSO connection. Cached in a `sync.Map[uuid.UUID]*oidc.Provider`. Cache invalidated (entry deleted) when connection config is updated (issuer URL change).

### API Endpoints

| Endpoint | Method | RBAC | Description |
|----------|--------|------|-------------|
| `/api/v1/orgs/{org_id}/sso` | POST | owner | Create SSO connection |
| `/api/v1/orgs/{org_id}/sso` | GET | owner | Get SSO config (secrets masked) |
| `/api/v1/orgs/{org_id}/sso` | PATCH | owner | Update SSO config |
| `/api/v1/orgs/{org_id}/sso` | DELETE | owner | Remove SSO connection |
| `/api/v1/orgs/{org_id}/sso/domains` | PUT | owner | Set email domains |
| `/api/v1/auth/discover` | POST | public | Email domain discovery |
| `/api/v1/auth/oidc/{connection_id}/login` | GET | public | Initiate OIDC flow |
| `/api/v1/auth/oidc/callback` | GET | public | OIDC callback |
| `/api/v1/orgs/{org_id}/sso/link` | POST | member+ | Link SSO identity |

All SSO CRUD endpoints are Enterprise-only (tier gated).

### Config Addition

```
SSO_ENCRYPTION_KEY=  # 32-byte key; required if SSO connections are configured
```

### Security Notes

- Identity matching uses `sub` claim (OIDC subject), never email
- Provider key in `user_identities` is `'oidc:{connection_id}'` — prevents cross-org collision
- Email domains globally unique — prevents phishing via domain hijacking
- Domain ownership verification deferred to SaaS phase (noted as known limitation)
- SSO is authentication-only — users must be invited to org first

---

## 5. Carry-Forward Items

| Item | Where it's handled |
|------|--------------------|
| Tier enforcement (hardcoded "free") | Section 1 — resolved |
| AI burst rate limits | Section 1 — per-org per-minute rate limit |
| CVE enumeration defense | Section 1 — handled by quota + burst rate limit |
| Data retention (ai_request_log, ai_usage_counters) | Section 2 — included in retention targets |
| AI summary execution in digests | Deferred — field is plumbed, LLM call not Phase 5 scope |

---

## 6. Schema Review Findings (pre-resolved)

| # | Issue | Resolution |
|---|-------|------------|
| 1 | `sso_email_domains` missing `org_id` denormalization | Added `org_id` column + RLS |
| 2 | `audit_log.org_id` as FK would CASCADE-delete on org deletion | Made NOT a FK (compliance) |
| 3 | `sso_connections` missing `org_id` FK | Added `REFERENCES organizations(id) ON DELETE CASCADE` |
| 4 | `audit_log.actor_email` NOT NULL fails for system actions | Made nullable |
| 5 | `sso_email_domains` missing index on `sso_connection_id` FK | Added BTREE index |
| 6 | `report_runs` table doesn't exist | Removed from retention targets |

---

## 7. Test Coverage Plan

### Tier Enforcement

| Test | Validates |
|------|-----------|
| `TestResolveLimit_Precedence` | Override → tier default → free fallback (table-driven) |
| `TestResolveLimit_EdgeCases` | Negative, zero, empty map, unknown tier |
| `TestBoolFlag_AllTiers` | Feature flags per tier + override |
| `TestAlertRuleCreate_TierLimit` | Free blocked at 5; Pro allowed up to 50 |
| `TestWatchlistCreate_TierLimit` | Free blocked at 3 |
| `TestMemberInvite_TierLimit` | Free blocked at 5 |
| `TestChannelCreate_TypeGating` | Free can't create email/Slack |
| `TestAIQuota_TierResolution` | Real tier used, not hardcoded "free" |
| `TestTierUpgrade_LimitsIncrease` | Tier change → limits update immediately |
| `TestOverride_TakesPrecedence` | Per-org override beats tier default |
| `TestOrgRateLimiter_TierRates` | 60/300/1000 req/min per tier |
| `TestOrgRateLimiter_TierChange` | Rate adjusts on tier change |
| `TestOrgRateLimiter_Eviction` | Idle orgs evicted after TTL |
| `TestOrgRateLimiter_CrossOrg` | Org A's limit doesn't affect Org B |
| `TestAIBurstRate` | Per-minute limit on AI endpoints |
| `TestTierLimit_LogsWarning` | slog Warn on limit exceeded |

### Data Retention

| Test | Validates |
|------|-----------|
| `TestBoundedBatch_ExactBatchSize` | Deletes batch_size when more rows exist |
| `TestBoundedBatch_FewerThanBatch` | Deletes all when fewer than batch_size |
| `TestBoundedBatch_ZeroRows` | Loop terminates on empty table |
| `TestMaxRuntime_StopsProcessing` | Stops after cap, remaining rows for next run |
| `TestRetention_CveRawPayloads` | Rows >90d deleted, newer retained |
| `TestRetention_FeedFetchLog` | Same pattern |
| `TestRetention_AlertEvents_PerOrgGroup` | Per-org-group windows respected |
| `TestRetention_NotificationDeliveries` | Same pattern |
| `TestRetention_AIRequestLog` | Same pattern |
| `TestRetention_AICache_Expired` | Expired entries deleted, valid retained |
| `TestRetention_AIUsageCounters` | Daily >90d deleted, monthly retained |
| `TestRetention_JobQueue_StatusFilter` | Succeeded/dead >24h deleted; pending/running untouched |
| `TestRetention_RefreshTokens_GraceWindow` | Expired+60s deleted; active retained |
| `TestRetention_ErrorIsolation` | One table failure doesn't block others |
| `TestRetention_Disabled` | `RETENTION_CLEANUP_ENABLED=false` → zero deletions |
| `TestRetention_JobScheduling` | Ticker enqueues; no double-enqueue |
| `TestRetention_LogsPerTable` | slog Info per table with row counts |
| `TestRetention_Timeout_LogsWarning` | slog Warn on runtime cap |

### Audit Log

| Test | Validates |
|------|-----------|
| `TestRedactSecrets_FieldNames` | Redacts secret/password/api_key/token/private_key/key_hash |
| `TestRedactSecrets_CaseInsensitive` | `Signing_Secret` redacted |
| `TestRedactSecrets_SubstringMatch` | `webhook_signing_secret` redacted |
| `TestRedactSecrets_NestedJSON` | Secret in nested object redacted |
| `TestRedactSecrets_ChannelURL` | Domain-only for channel entity |
| `TestRedactSecrets_PreservesNonSecret` | Non-secret fields unchanged |
| `TestRedactSecrets_NilState` | Handles NULL/empty without panic |
| `TestEntry_CreateAction` | old=nil, new populated |
| `TestEntry_UpdateAction` | Both populated |
| `TestEntry_DeleteAction` | old populated, new=nil |
| `TestEntry_DeniedAction` | success=false, both nil |
| `TestEntry_SystemAction` | actor_id=nil, actor_email=nil |
| `TestAudit_AlertRuleCRUD` | Create/update/delete produce entries |
| `TestAudit_ChannelSecretRedaction` | signing_secret=[REDACTED], URL domain-only |
| `TestAudit_MemberOperations` | Invite/role-change/remove produce entries |
| `TestAudit_FailedAuth` | 403 on mutation → success=false entry |
| `TestAudit_NonBlocking` | Audit failure doesn't fail parent mutation |
| `TestAuditAPI_RBAC` | Owner/admin can list; member/viewer 403 |
| `TestAuditAPI_Pagination` | Cursor pagination correct |
| `TestAuditAPI_Filters` | entity_type, action, actor_id, date range |
| `TestAuditAPI_CrossOrgIsolation` | Org A can't see Org B's audit |
| `TestAuditAPI_TierGating` | Non-Enterprise 403 |
| `TestAudit_Retention` | Old entries cleaned by retention job |
| `TestAuditWriteFailure_LogsError` | slog Error, parent succeeds |

### Generic OIDC

| Test | Validates |
|------|-----------|
| `TestAESGCM_RoundTrip` | Encrypt → decrypt returns original |
| `TestAESGCM_UniqueNonce` | Same plaintext → different ciphertexts |
| `TestAESGCM_TamperedCiphertext` | Modified ciphertext fails |
| `TestAESGCM_WrongKey` | Wrong key fails |
| `TestAESGCM_EmptyPlaintext` | Empty string works |
| `TestAESGCM_InvalidKeyLength` | Non-32-byte key rejected |
| `TestExtractEmailDomain` | Domain extraction + edge cases |
| `TestStateEncoding_RoundTrip` | CSRF + connection_id round-trip |
| `TestSSOConnection_CRUD` | Owner CRUD; secrets masked in GET |
| `TestSSOConnection_RBAC` | Non-owner 403; non-Enterprise 403 |
| `TestSSOConnection_SecretEncrypted` | DB contains ciphertext not plaintext |
| `TestSSOConnection_UniquePerOrg` | Second connection for same org fails |
| `TestEmailDomain_Uniqueness` | Two orgs same domain → second fails |
| `TestEmailDomain_Cascade` | Delete connection → domains deleted |
| `TestDiscover_MatchingDomain` | Returns SSO info for known domain |
| `TestDiscover_UnknownDomain` | Returns empty |
| `TestDiscover_RateLimited` | Unauthenticated endpoint rate limited |
| `TestOIDCFlow_Success` | Mock IdP → identity matched → JWT issued |
| `TestOIDCFlow_NoIdentity` | No existing identity → "contact admin" |
| `TestOIDCFlow_CSRFMismatch` | Tampered state → 403 |
| `TestOIDCFlow_NonceMismatch` | Nonce failure → error |
| `TestOIDCFlow_ExpiredCode` | Invalid code → error |
| `TestOIDCFlow_CrossOrgIsolation` | Same sub, different connections = different users |
| `TestIdentityLinking` | Member links SSO → user_identities created |
| `TestOIDCFlow_Disabled` | Disabled connection → login fails |
| `TestOIDCFlow_AuditLogged` | SSO operations produce audit entries |
| `TestOIDCLoginFailed_LogsWarning` | slog Warn on auth failure |

### Cross-Cutting

| Concern | How handled |
|---------|------------|
| RLS isolation | Every org-scoped table includes cross-org isolation test |
| testcontainers-go | All Postgres integration tests |
| Pristine output | Intentional errors captured and validated |
| Test data isolation | Each test creates own org/user/data |
| Clock injection | Rate limiter and retention use injectable `now` function |

---

## 8. Structured Logging (slog)

### Tier Enforcement

| Level | Event | Fields |
|-------|-------|--------|
| `Warn` | Tier limit exceeded | `org_id`, `limit_name`, `current`, `max`, `tier` |
| `Info` | Org rate limit triggered | `org_id`, `rate_per_min`, `tier` |
| `Info` | Tier changed | `org_id`, `old_tier`, `new_tier` |

### Data Retention

| Level | Event | Fields |
|-------|-------|--------|
| `Info` | Run started | `job_id` |
| `Info` | Per-table result | `table`, `rows_deleted`, `cutoff` |
| `Warn` | Runtime cap hit | `runtime_seconds`, `max_runtime_seconds`, `tables_remaining` |
| `Error` | Per-table failure | `table`, `err` |
| `Info` | Run complete | `total_rows_deleted`, `runtime_seconds`, `tables_processed` |

### Audit Log

| Level | Event | Fields |
|-------|-------|--------|
| `Error` | Write failed (non-blocking) | `org_id`, `entity_type`, `entity_id`, `action`, `err` |

### OIDC

| Level | Event | Fields |
|-------|-------|--------|
| `Info` | SSO connection created | `org_id`, `issuer` |
| `Info` | OIDC login initiated | `connection_id`, `org_id` |
| `Info` | OIDC login success | `connection_id`, `user_id`, `org_id` |
| `Warn` | OIDC login failed | `connection_id`, `reason`, `err` |
| `Info` | Identity linked | `user_id`, `connection_id` |
| `Debug` | Provider cache created | `connection_id`, `issuer` |

---

## 9. Future Hardening (not Phase 5)

- **memguard for all config secrets:** Platform-specific memory protection (mlock, guard pages, zeroing). Applies to JWT_SECRET, SMTP_PASSWORD, GEMINI_API_KEY, SSO_ENCRYPTION_KEY — all env var secrets. Requires config system refactor.
- **OIDC domain ownership verification:** DNS TXT record verification before accepting email domain claims. Required for SaaS multi-tenant but not self-hosted single-org.
- **SAML 2.0:** `crewjam/saml` integration. Deferred from Phase 5.
- **SSO staging validator:** Mock SAML/OIDC flow without saving config (deferred-features §3.2).
- **Redis-backed rate limiting:** For multi-instance SaaS deployments (PLAN.md §16.1 D6).
