# Phase 5 Test Coverage Review — Hardening & SaaS Readiness

**Date:** 2026-03-03
**Scope:** All Phase 5 source files (~32 source files, ~30 test files)
**Method:** 6 parallel subagents with per-function path mapping, security checklist, depth threshold, operator variant rules
**Design docs:** `dev/plans/2026-03-01-phase5-hardening-saas-readiness-design.md`, `dev/plans/2026-03-01-phase5-implementation-plan.md`

---

## Executive Summary

Phase 5 has the highest-risk attack surface of any phase: SSO/OIDC authentication flows, AES-256-GCM crypto, identity linking, tier-based access control, audit logging with secret redaction, and data retention. This review mapped every code path across 32 source files and cross-referenced against test coverage.

**2 production bugs discovered** (see §Bugs).

| Severity | Gaps | Key Themes |
|----------|------|------------|
| Security-critical | 36 | OIDC callback validation (11), cross-org isolation at store level (6), middleware fail-open (4), handler fail-closed defense (5), audit/redaction (5), crypto edge (1), SSO CRUD (4) |
| Correctness | 144 | Error→500 paths (~55), tier variant coverage (~20), SSO handler branches (~32), audit/retention logic (~37) |
| Nice-to-have | 43 | Cache eviction edges, cleanup loops, config boundary values, unlikely runtime failures |
| **Total** | **223** | |

---

## Production Bugs Discovered

### BUG-1: Invitation handler missing audit log on tier block
**File:** `internal/api/orgs.go:404-407`
**Impact:** All other tier-gated handlers (alert_rules, channels, watchlists) write an audit entry with `Success: false` when a tier limit is hit. The invitation handler does NOT. This creates a gap in the audit trail for member limit enforcement.
**Fix:** Add audit log entry matching the pattern in alert_rules.go:185-191.

### BUG-2: org_tier endpoint uses wrong count method for member usage
**File:** `internal/api/org_tier.go:61`
**Impact:** Uses `CountMembersByOrg` (counts active members only) instead of `CountMemberSlotsUsedByOrg` (counts members + pending invitations). The displayed "used" count in the tier status response will be lower than actual slot consumption when pending invitations exist. Users will see available slots that are actually consumed.
**Fix:** Change to `CountMemberSlotsUsedByOrg`.

### Design Inconsistency: channels.go uses inline BoolFlag defaults
**File:** `internal/api/channels.go:98`
**Impact:** Calls `resolver.BoolFlag("channels_"+req.Type, req.Type == "webhook", true, true)` with inline values instead of using `tier.FlagChannelsEmail`/`tier.FlagChannelsWebhook` constants from `limits.go`. If the defaults in `limits.go` change, the handler will use stale inline values.
**Fix:** Use centralized constants.

---

## What's Well-Covered

- **Resolver core logic is exhaustively tested.** `IntLimit` and `BoolFlag` in `resolver_test.go` cover all tier values, override precedence, wrong-type override fallback, empty overrides, and unknown-tier fallback. The strongest area in the tier work stream.

- **Integration tier gating covers the critical enforcement points.** 12 integration tests in `tier_gating_test.go` cover alert rules, watchlists, members, and channels at free-tier boundaries, with override expansion, enterprise unlimited, and pending-invitation slot consumption.

- **AES-256-GCM core operations are solid.** Round-trip, nonce uniqueness, tamper detection, wrong key, empty plaintext, and short ciphertext. The `[32]byte` key type eliminates key-length bugs at compile time.

- **SSO CRUD happy paths + domain validation are thorough.** Full lifecycle, tier gating, RBAC, secret masking, unique constraints, RFC 1035 domain validation (9 invalid + 4 valid cases), cascade delete, discovery, disabled filtering, rate limiting, cache eviction, and audit logging.

- **Audit redaction keywords are individually tested.** All 6 sensitive keywords have per-keyword assertions, plus case-insensitive and substring matching.

- **Store-level count queries have strong edge-case coverage.** Soft-delete exclusion, pending-vs-expired-vs-accepted invitation logic, and org-scoping via RLS.

- **Retention bounded-batch DELETEs across all 10 tables** have dedicated integration tests against real Postgres. Org-scoped deletions proved safe via `_OrgFilter` tests.

---

## Coverage Summary

| File | Paths Mapped | Covered | GAP | Gap Rate |
|------|-------------|---------|-----|----------|
| `tier/resolver.go` | 19 | 17 | 2 | 11% |
| `tier/limits.go` | 14 | 0 | 14 | **100%** |
| `api/middleware_tier.go` | 17 | 7 | 10 | **59%** |
| `api/tier_cache.go` | 18 | 10 | 8 | 44% |
| `api/org_ratelimit.go` | 15 | 9 | 6 | 40% |
| `api/org_tier.go` | 16 | 3 | 13 | **81%** |
| `store/org.go` (tier methods) | 24 | 12 | 12 | 50% |
| `api/alert_rules.go` (gating) | 9 | 6 | 3 | 33% |
| `api/channels.go` (gating) | 7 | 5 | 2 | 29% |
| `api/watchlists.go` (gating) | 10 | 6 | 4 | 40% |
| `api/orgs.go` (gating) | 10 | 6 | 4 | 40% |
| `retention/runner.go` | 23 | 12 | 11 | 48% |
| `store/retention.go` | 20 | 10 | 10 | 50% |
| `store/jobs.go` (retention) | 10 | 4 | 6 | 60% |
| `notify/worker.go` (retention) | 7 | 4 | 3 | 43% |
| `config/config.go` (new vars) | 6 | 3 | 3 | 50% |
| `audit/redact.go` | 17 | 11 | 6 | 35% |
| `audit/writer.go` | 15 | 6 | 9 | **60%** |
| `api/audit_log.go` | 33 | 26 | 7 | 21% |
| `store/audit.go` | 15 | 10 | 5 | 33% |
| `crypto/aes.go` | 14 | 11 | 3 | 21% |
| `api/sso.go` | 82 | 42 | 40 | **49%** |
| `api/oauth_oidc.go` | 60 | 17 | 43 | **72%** |
| `store/sso.go` | 16 | 12 | 4 | 25% |

**Highest risk files (>50% gap rate):** `limits.go` (100%), `org_tier.go` (81%), `oauth_oidc.go` (72%), `middleware_tier.go` (59%), `writer.go` (60%).

---

## Security-Critical Gaps (36)

### Tier Middleware Fail-Open (4)

| # | Gap | File:Line |
|---|-----|-----------|
| 1 | `tierMiddleware`: orgID missing from context → request passes through WITHOUT resolver injected (fail-open) | `middleware_tier.go:21-26` |
| 2 | No test proving full chain: missing orgID → tierMiddleware pass-through → downstream handler returns 500 (defense-in-depth) | `middleware_tier.go:21` → handlers |
| 3 | `orgRateLimitMiddleware`: orgID missing → rate limiting silently skipped (fail-open) | `middleware_tier.go:52-56` |
| 4 | `orgRateLimitMiddleware`: resolver missing → falls back to free-tier 60/min instead of denying | `middleware_tier.go:59-62` |

### Handler Fail-Closed Defense Untested (5)

| # | Gap | File:Line |
|---|-----|-----------|
| 5 | `createAlertRuleHandler`: resolver missing → 500 untested | `alert_rules.go:170-175` |
| 6 | `createChannelHandler`: resolver missing → 500 untested | `channels.go:92-97` |
| 7 | `createWatchlistHandler`: resolver missing → 500 untested | `watchlists.go:175-180` |
| 8 | `createInvitationHandler`: resolver missing → 500 untested | `orgs.go:390-395` |
| 9 | `getOrgTierHandler`: resolver missing → 500 untested | `org_tier.go:34-37` |

### Cross-Org Isolation at Store Level (6)

| # | Gap | File:Line |
|---|-----|-----------|
| 10 | `UpdateOrgTier`: no cross-org test (uses `withBypassTx`) | `store/org.go:367-374` |
| 11 | `CountAlertRulesByOrg`: no cross-org isolation test at store level | `store/org.go:401-412` |
| 12 | `CountWatchlistsByOrg`: no cross-org isolation test at store level | `store/org.go:416-427` |
| 13 | `CountMembersByOrg` + `CountMemberSlotsUsedByOrg`: no cross-org test | `store/org.go:431-457` |
| 14 | `ListAuditEntries`: no store-level cross-org isolation test | `store/audit.go:83-133` |
| 15 | SSO store methods: no cross-org isolation test | `store/sso.go` |

### Org Tier API Security (2)

| # | Gap | File:Line |
|---|-----|-----------|
| 16 | GET /tier: unauthenticated → 401 not tested | `org_tier.go` |
| 17 | GET /tier: cross-org access not tested | `org_tier.go` |

### Audit & Redaction (5)

| # | Gap | File:Line |
|---|-----|-----------|
| 18 | `redactURL`: query params (e.g., `?token=abc`) — implementation strips them but no test proves it | `redact.go:64-65` |
| 19 | `redactURL`: userinfo (`user:pass@host`) — `u.Host` excludes it but no test confirms credentials aren't leaked | `redact.go:64-65` |
| 20 | `buildStoreEntry` marshal error → audit entry silently dropped (security action happened, no record) | `writer.go:64-68` |
| 21 | Audit log endpoint: unauthenticated → 401 not tested | `audit_log.go` |
| 22 | Invitation handler missing audit log on tier block — **BUG-1** | `orgs.go:404-407` |

### AES-256-GCM Crypto (1)

| # | Gap | File:Line |
|---|-----|-----------|
| 23 | Decrypt: nonce-only ciphertext (exactly 12 bytes, 0-length payload) — `gcm.Open` should fail but untested | `aes.go:49-57` |

### SSO CRUD (2)

| # | Gap | File:Line |
|---|-----|-----------|
| 24 | No API-level cross-org isolation test for SSO endpoints | `sso.go` |
| 25 | PATCH SSO: client_secret re-encryption via PATCH entirely untested | `sso.go:294-307` |

### OIDC Callback Validation (11)

The `oidcVerifyCallback` function is the security core of the OIDC flow — 12 distinct code paths, only 2 have dedicated tests.

| # | Gap | File:Line |
|---|-----|-----------|
| 26 | Malformed state parameter (no underscore separator) → 400 untested | `oauth_oidc.go:114-118` |
| 27 | Invalid UUID in state parameter → 400 untested | `oauth_oidc.go:119-123` |
| 28 | TOCTOU: SSO connection deleted between redirect and callback → 404 untested | `oauth_oidc.go:132-135` |
| 29 | TOCTOU: SSO connection disabled between redirect and callback → 403 untested | `oauth_oidc.go:136-139` |
| 30 | Missing `id_token` in token response → 400 untested | `oauth_oidc.go:159-164` |
| 31 | Token signed with wrong key → verification failure untested (mock IdP lacks adversarial mode) | `oauth_oidc.go:166-171` |
| 32 | Token with wrong issuer → rejected untested | `oauth_oidc.go:166-171` |
| 33 | Token with wrong audience → rejected untested | `oauth_oidc.go:166-171` |
| 34 | Token expired → rejected untested | `oauth_oidc.go:166-171` |
| 35 | Missing `sub` claim in ID token → 400 untested | `oauth_oidc.go:180-183` |
| 36 | Nonce mismatch (cookie vs ID token) → 400 untested (design doc listed `TestOIDCFlow_NonceMismatch`, never implemented) | `oauth_oidc.go:186-194` |

**Root cause for gaps 31-36:** `MockOIDC` in `testutil/mock_oidc.go` always issues valid, correctly-signed tokens with all required claims. It has no mechanism to produce adversarial tokens (wrong key, wrong issuer, expired, missing claims, wrong nonce). Adding configurable error modes to the mock would unblock all 6 validation tests at once.

---

## Correctness Gaps (144)

### Tier Enforcement (53)

#### limits.go — No Test File (14)

`limits.go` has zero tests. The entire file is untested.

| # | Gap | Line |
|---|-----|------|
| 1 | `ResolveInt`: no dedicated unit test | 35 |
| 2 | `ResolveInt` with `LimitAlertRules` (5/50/-1) | 35 |
| 3 | `ResolveInt` with `LimitWatchlists` (3/20/-1) | 35 |
| 4 | `ResolveInt` with `LimitMembers` (5/25/-1) | 35 |
| 5 | `ResolveInt` with `LimitAPIRate` (60/300/1000) | 35 |
| 6 | `ResolveBool`: no dedicated unit test | 40 |
| 7 | `ResolveBool` with `FlagChannelsEmail` | 40 |
| 8 | `ResolveBool` with `FlagChannelsWebhook` | 40 |
| 9 | `LimitAlertRules` constant values not asserted against design doc | 24 |
| 10 | `LimitWatchlists` constant values not asserted | 25 |
| 11 | `LimitMembers` constant values not asserted | 26 |
| 12 | `LimitAPIRate` constant values not asserted | 27 |
| 13 | `FlagChannelsEmail` constant values not asserted | 29 |
| 14 | `FlagChannelsWebhook` constant values not asserted | 30 |

#### middleware_tier.go (6)

| # | Gap | Line |
|---|-----|------|
| 15 | `tierMiddleware`: cache-hit path (no dedicated test) | 29-30 |
| 16 | `tierMiddleware`: store.GetOrgTier error → 500 | 33-37 |
| 17 | `tierMiddleware`: cache population after DB read not verified | 38-39 |
| 18 | `orgRateLimitMiddleware`: burst < 1 → clamp to 1 | 66-68 |
| 19 | `orgRateLimitMiddleware`: pro tier rate (300/min) untested | 61 |
| 20 | `orgRateLimitMiddleware`: enterprise tier rate (1000/min) untested | 61 |

#### Other Tier Files (9)

| # | Gap | File:Line |
|---|-----|-----------|
| 21 | `IntLimit`: negative override value (e.g., -1 for "unlimited") | `resolver.go:15-17` |
| 22 | `tierCache.Set`: overwrite existing entry for same orgID | `tier_cache.go:67` |
| 23 | `tierCache.evictExpired`: entry removal not directly tested | `tier_cache.go:101-103` |
| 24 | `tierCache.evictExpired`: entry retention within TTL not directly tested | `tier_cache.go:102` |
| 25 | `orgRateLimiter.Allow`: burst-only change (rate same) | `org_ratelimit.go:50` |
| 26 | `orgRateLimiter.Allow`: rate downgrade not tested | `org_ratelimit.go:50-52` |
| 27 | No test verifies cache invalidation on tier change (stale cache = privilege escalation on downgrade) | tier_cache + middleware |
| 28 | `getOrgTierHandler`: orgID missing → 400 | `org_tier.go:28-31` |
| 29 | `getOrgTierHandler`: uses `CountMembersByOrg` instead of `CountMemberSlotsUsedByOrg` — **BUG-2** | `org_tier.go:61` |

#### org_tier Endpoint Response Gaps (6)

| # | Gap | File:Line |
|---|-----|-----------|
| 30 | Pro tier response with correct limits never tested | `org_tier.go:41-46` |
| 31 | Enterprise tier response with unlimited (-1) limits never tested | `org_tier.go:41-46` |
| 32 | Override applied to response never tested | `org_tier.go:41-46` |
| 33 | `api_rate_limit` value not asserted in response | `org_tier.go:76` |
| 34 | `watchlists.used` count not asserted | `org_tier.go` |
| 35 | `members.used` count not asserted | `org_tier.go` |

#### org_tier Handler Error Paths (3)

| # | Gap | File:Line |
|---|-----|-----------|
| 36 | `CountAlertRulesByOrg` error → 500 | `org_tier.go:49-54` |
| 37 | `CountWatchlistsByOrg` error → 500 | `org_tier.go:55-60` |
| 38 | `CountMembersByOrg` error → 500 | `org_tier.go:61-66` |

#### store/org.go Tier Methods (8)

| # | Gap | File:Line |
|---|-----|-----------|
| 39 | `GetOrgTier`: nonexistent org → `ErrNoRows` | `store/org.go:349-351` |
| 40 | `GetOrgTier`: malformed JSON in tier_overrides → unmarshal error | `store/org.go:355-357` |
| 41 | `UpdateOrgTier`: nonexistent org (0 rows affected, no error) | `store/org.go:369-372` |
| 42 | `UpdateOrgTier`: invalid tier value (CHECK constraint) | `store/org.go` |
| 43 | `ListAllOrgs`: overrides not tested in result | `store/org.go:388-392` |
| 44 | `ListAllOrgs`: malformed JSON overrides | `store/org.go:389-392` |
| 45 | `ListAllOrgs`: empty result | `store/org.go` |
| 46 | `ListAllOrgs`: behavior with soft-deleted orgs undocumented/untested | SQL |

#### Handler Tier Gating (9)

| # | Gap | File:Line |
|---|-----|-----------|
| 47 | Pro tier at boundary for alert rules (limit=50) | `alert_rules.go` |
| 48 | Pro tier at boundary for watchlists (limit=20) | `watchlists.go` |
| 49 | Pro tier at boundary for members (limit=25) | `orgs.go` |
| 50 | `CountAlertRulesByOrg` DB error → 500 in handler | `alert_rules.go:179-183` |
| 51 | `CountWatchlistsByOrg` DB error → 500 in handler | `watchlists.go:184-188` |
| 52 | `CountMemberSlotsUsedByOrg` DB error → 500 in handler | `orgs.go:399-403` |
| 53 | Audit log content on tier block not asserted (alert rules) | `alert_rules.go:185-191` |
| 54 | Audit log content on tier block not asserted (channels) | `channels.go:99-106` |
| 55 | Audit log content on tier block not asserted (watchlists) | `watchlists.go:190-196` |

### Retention + Supporting (16)

| # | Gap | File:Line |
|---|-----|-----------|
| 56 | `cleanupTierGated`: `ListAllOrgs` failure → error logged but continuation not tested | `runner.go:102-105` |
| 57 | `Run` returns nil even when `cleanupTierGated` errors — not asserted | `runner.go:97` |
| 58 | `notification_deliveries` per-org-group tier differentiation — no dedicated test | `runner.go:117-123` |
| 59 | Context cancellation mid-cleanup loop | `runner.go:167-169` |
| 60 | `CleanupAlertEvents`: recent data for the SAME cleaned org not tested to survive | `retention.sql` |
| 61 | `CleanupNotificationDeliveries`: recent data for same org not tested to survive | `retention.sql` |
| 62 | `CleanupAIUsageCounters`: monthly rows surviving cleanup not tested | `retention.sql` |
| 63 | `HasPendingOrRunningJob` with `running` status job not tested | `jobs.go:116-124` |
| 64 | `HasPendingOrRunningJob` with `succeeded`/`dead` job returning false not tested | `jobs.go:116-124` |
| 65 | `scheduleRetention`: `HasPendingOrRunningJob` returns error | `worker.go:355-359` |
| 66 | `scheduleRetention`: `EnqueueJob` returns error | `worker.go:367-370` |
| 67 | No panic recovery in retention ticker — crash kills entire worker | `worker.go:94` |
| 68 | `RETENTION_CLEANUP_ENABLED=false` non-default value parsing | `config.go:102` |
| 69 | Zero-value retention integers (e.g., `RETENTION_RAW_PAYLOAD_DAYS=0`) | `config.go:105` |
| 70 | Zero-value boundary for `RETENTION_MAX_RUNTIME_SECONDS` | `config.go:111` |
| 71 | `ListAllOrgs` error in `cleanupTierGated` — not forced | `runner.go:102-105` |

### Audit Logging (19)

| # | Gap | File:Line |
|---|-----|-----------|
| 72 | `redactSecrets`: channel entity with URL value as non-string | `redact.go:33-37` |
| 73 | `redactSecrets`: channel entity "URL" key (uppercase) via EqualFold | `redact.go:33` |
| 74 | `redactSecrets`: deeply nested secrets (3+ levels) — only 2-level tested | `redact.go:39-42` |
| 75 | `Writer.Log`: `context.WithoutCancel` — goroutine completes after parent context cancel | `writer.go:45` |
| 76 | `Writer.Log`: panic recovery — no test triggers panic | `writer.go:50-53` |
| 77 | `Writer.Log`: `GetUserByID` returns error — email stays empty | `writer.go:58-59` |
| 78 | `Writer.Log`: `GetUserByID` returns nil user | `writer.go:59` |
| 79 | `buildStoreEntry`: OldState marshal error path | `writer.go:81-84` |
| 80 | `buildStoreEntry`: NewState marshal error path | `writer.go:85-88` |
| 81 | `buildStoreEntry`: Metadata marshal error path | `writer.go:89-92` |
| 82 | `marshalState`: initial `json.Marshal` failure (channel/func type) | `writer.go:123-125` |
| 83 | `listAuditLogHandler`: orgID not in context → 400 | `audit_log.go:41-44` |
| 84 | `listAuditLogHandler`: tier resolver missing → 500 | `audit_log.go:48-52` |
| 85 | `listAuditLogHandler`: `ListAuditEntries` DB error → 500 | `audit_log.go:126-129` |
| 86 | `listAuditLogHandler`: nil ActorID → omitted from response | `audit_log.go:156-159` |
| 87 | `ListAuditEntries`: DB error → wrapped and returned | `store/audit.go:106-108` |
| 88 | `ListAuditEntries`: row mapping null ActorID → nil pointer | `store/audit.go:114` |
| 89 | `api_key` entity create audit not tested in integration | integration |
| 90 | `api_key` entity delete audit not tested in integration | integration |

### SSO/OIDC + Crypto (56)

#### sso.go Handler Branches (32)

| # | Gap | File:Line |
|---|-----|-----------|
| 91 | `ssoEncryptionKey`: invalid hex string | `sso.go:73-75` |
| 92 | `ssoEncryptionKey`: hex decodes to wrong length | `sso.go:76-78` |
| 93 | `requireEnterpriseTier`: resolver missing → 500 | `sso.go:87-90` |
| 94 | `createSSOHandler`: orgID missing → 400 | `sso.go:103-107` |
| 95 | `createSSOHandler`: encryption key error → 500 | `sso.go:135-140` |
| 96 | `createSSOHandler`: encrypt error → 500 | `sso.go:141-146` |
| 97 | `createSSOHandler`: store error → 500 | `sso.go:163-165` |
| 98 | `getSSOHandler`: orgID missing → 400 | `sso.go:203-207` |
| 99 | `getSSOHandler`: tier gating not directly tested on GET | `sso.go:208-210` |
| 100 | `getSSOHandler`: store error → 500 | `sso.go:213-216` |
| 101 | `getSSOHandler`: `ListSSOEmailDomains` error → 500 | `sso.go:225-229` |
| 102 | `patchSSOHandler`: orgID missing → 400 | `sso.go:253-257` |
| 103 | `patchSSOHandler`: tier gating not directly tested on PATCH | `sso.go:258-260` |
| 104 | `patchSSOHandler`: `GetSSOConnection` error → 500 | `sso.go:263-268` |
| 105 | `patchSSOHandler`: invalid JSON body → 400 | `sso.go:275-278` |
| 106 | `patchSSOHandler`: client_id merge not tested alone | `sso.go:289-292` |
| 107 | `patchSSOHandler`: encryption key error → 500 | `sso.go:296-300` |
| 108 | `patchSSOHandler`: encrypt error → 500 | `sso.go:301-306` |
| 109 | `patchSSOHandler`: scopes merge not tested alone | `sso.go:308-311` |
| 110 | `patchSSOHandler`: `UpdateSSOConnection` error → 500 | `sso.go:317-322` |
| 111 | `patchSSOHandler`: re-read after update error → 500 | `sso.go:330-335` |
| 112 | `patchSSOHandler`: `ListSSOEmailDomains` error → 500 | `sso.go:337-342` |
| 113 | `deleteSSOHandler`: orgID missing → 400 | `sso.go:387-391` |
| 114 | `deleteSSOHandler`: tier gating not directly tested on DELETE | `sso.go:392-394` |
| 115 | `deleteSSOHandler`: `GetSSOConnection` error → 500 | `sso.go:397-402` |
| 116 | `deleteSSOHandler`: `DeleteSSOConnection` error → 500 | `sso.go:404-408` |
| 117 | `putSSODomainsHandler`: orgID missing → 400 | `sso.go:427-431` |
| 118 | `putSSODomainsHandler`: tier gating not directly tested on PUT | `sso.go:432-434` |
| 119 | `putSSODomainsHandler`: `GetSSOConnection` error → 500 | `sso.go:437-442` |
| 120 | `putSSODomainsHandler`: invalid JSON body → 400 | `sso.go:449-452` |
| 121 | `putSSODomainsHandler`: `SetSSOEmailDomains` error → 500 | `sso.go:464-468` |
| 122 | `discoverHandler`: `LookupSSOByDomain` error → 500 | `sso.go:528-533` |

#### oauth_oidc.go Flow Branches (20)

| # | Gap | File:Line |
|---|-----|-----------|
| 123 | `getOIDCProvider`: discovery error | `oauth_oidc.go:38-39` |
| 124 | `oidcBuildOAuthConfig`: provider error → wrapped | `oauth_oidc.go:47-50` |
| 125 | `oidcBuildOAuthConfig`: encryption key error → wrapped | `oauth_oidc.go:51-54` |
| 126 | `oidcBuildOAuthConfig`: decrypt error → wrapped | `oauth_oidc.go:55-58` |
| 127 | `oidcInitRedirect`: build config error → 500 | `oauth_oidc.go:73-78` |
| 128 | `oidcVerifyCallback`: `GetSSOConnectionByID` error → 500 | `oauth_oidc.go:126-131` |
| 129 | `oidcVerifyCallback`: build OIDC config error → 500 | `oauth_oidc.go:142-147` |
| 130 | `oidcVerifyCallback`: code exchange failure → 400 | `oauth_oidc.go:150-156` |
| 131 | `oidcVerifyCallback`: claims extraction error → 500 | `oauth_oidc.go:174-179` |
| 132 | `oidcLoginHandler`: `GetSSOConnectionByID` error → 500 | `oauth_oidc.go:212-216` |
| 133 | `oidcCallbackHandler`: `GetUserByProviderID` error → 500 | `oauth_oidc.go:244-249` |
| 134 | `oidcCallbackHandler`: access token issue error → 500 | `oauth_oidc.go:258-263` |
| 135 | `oidcCallbackHandler`: refresh token issue error → 500 | `oauth_oidc.go:264-269` |
| 136 | `oidcCallbackHandler`: `CreateRefreshToken` error → 500 | `oauth_oidc.go:270-274` |
| 137 | `oidcLinkInitHandler`: `GetSSOConnection` error → 500 | `oauth_oidc.go:291-296` |
| 138 | `oidcLinkCallbackHandler`: `GetUserByProviderID` error → 500 | `oauth_oidc.go:336-340` |
| 139 | `oidcLinkCallbackHandler`: `UpsertUserIdentity` error → 500 | `oauth_oidc.go:348-352` |
| 140 | Expired state cookie (MaxAge=300) — expiry behavior untested | `oauth_oidc.go` |
| 141 | Invalid/expired authorization code exchange | `oauth_oidc.go:150-156` |
| 142 | Missing email claim in ID token — code proceeds with empty email | `oauth_oidc.go` |

#### Store + Mock (4)

| # | Gap | File:Line |
|---|-----|-----------|
| 143 | `GetSSOConnection`: other DB error (not ErrNoRows) | `store/sso.go:56-57` |
| 144 | `GetSSOConnectionByID`: nonexistent UUID | `store/sso.go:150-152` |
| 145 | Mock IdP: reject invalid authorization code mode | `mock_oidc.go` |
| 146 | Mock IdP: missing email claim mode | `mock_oidc.go` |

---

## Nice-to-Have Gaps (43)

### Tier (15)

| # | Gap | File |
|---|-----|------|
| 1 | `BoolFlag`: empty overrides map | `resolver.go` |
| 2 | `tierCache.Get`: exact TTL boundary (age == TTL) | `tier_cache.go` |
| 3 | `tierCache.Stop`: double-close panic | `tier_cache.go` |
| 4 | `tierCache.Invalidate`: non-existent org | `tier_cache.go` |
| 5 | `tierCache.cleanupLoop`: real ticker-driven cleanup | `tier_cache.go` |
| 6 | `tierCache.evictExpired`: empty map no-op | `tier_cache.go` |
| 7 | `orgRateLimiter.Stop`: never called in tests (goroutine leak) | `org_ratelimit.go` |
| 8 | `orgRateLimiter.cleanupLoop`: real ticker-driven cleanup | `org_ratelimit.go` |
| 9 | `orgRateLimiter.cleanupLoop`: done channel exit | `org_ratelimit.go` |
| 10 | `orgRateLimiter.evictIdle`: retention of non-idle entry | `org_ratelimit.go` |
| 11 | Enterprise channel creation not explicitly tested | integration |
| 12 | Override expanding watchlist limit | integration |
| 13 | `CountAlertRulesByOrg`: zero count | `store/org.go` |
| 14 | `CountWatchlistsByOrg`: zero count | `store/org.go` |
| 15 | `ListAllOrgs`: empty DB | `store/org.go` |

### Retention (15)

| # | Gap | File |
|---|-----|------|
| 16 | "retention cleanup started" log output not asserted | `runner.go` |
| 17 | "retention cleanup finished" log output not asserted | `runner.go` |
| 18 | `groupByRetentionDays` with empty orgs slice | `runner.go` |
| 19 | Multiple orgs same retention window grouped (distinct assertion) | `runner.go` |
| 20 | Per-table completion log not asserted | `runner.go` |
| 21 | Silent behavior when `totalDeleted == 0` | `runner.go` |
| 22-30 | Error paths for all 9 non-AI store cleanup methods | `store/retention.go` |
| 31 | `HasPendingOrRunningJob` query error | `store/jobs.go` |
| 32 | `EnqueueJob` with nil `lockKey` | `store/jobs.go` |
| 33 | `EnqueueJob` with non-nil `runAfter` | `store/jobs.go` |
| 34 | `EnqueueJob` error | `store/jobs.go` |

### Audit (8)

| # | Gap | File |
|---|-----|------|
| 35 | `isSensitiveKey` with empty string key | `redact.go` |
| 36 | `redactURL` with no-path URL | `redact.go` |
| 37 | `redactURL` with port in URL | `redact.go` |
| 38 | Audit log empty result set → `{"items":[]}` | `audit_log.go` |
| 39 | `limit=1` (minimum valid) pagination | `audit_log.go` |
| 40 | `ListAuditEntries` empty result | `store/audit.go` |
| 41 | null ActorEmail → empty string mapping | `store/audit.go` |

### SSO/OIDC (5)

| # | Gap | File |
|---|-----|------|
| 42 | `Encrypt`: `io.ReadFull(rand.Reader)` entropy exhaustion | `aes.go` |
| 43 | `Decrypt`: empty (0 bytes) ciphertext input | `aes.go` |
| 44 | `oidcInitRedirect`: state generation error | `oauth_oidc.go` |
| 45 | `oidcInitRedirect`: nonce generation error | `oauth_oidc.go` |

*(Note: nice-to-have items 22-30 are 9 individual store cleanup error paths counted as a range for readability.)*

---

## Key Observations

### 1. Mock IdP Lacks Adversarial Modes — Root Cause of 6 OIDC Security Gaps

`MockOIDC` always issues valid, correctly-signed tokens with all required claims. There is no mechanism to produce bad tokens (wrong key, wrong issuer, expired, missing claims, wrong nonce). This is the **single root cause** of 6 of the 11 OIDC security-critical gaps. The design doc explicitly listed `TestOIDCFlow_NonceMismatch` and `TestOIDCFlow_ExpiredCode` — never implemented.

**Fix:** Add configurable error modes: `mock.SetSigningKey(otherKey)`, `mock.SetIssuerOverride(...)`, `mock.SetExpiry(-1*time.Hour)`, `mock.OmitClaim("sub")`, `mock.SetNonceOverride("wrong")`, `mock.RejectCode(true)`.

### 2. Fail-Open Middleware Paths Are Unverified

Both `tierMiddleware` and `orgRateLimitMiddleware` silently pass requests when `ctxOrgID` is missing — they call `next.ServeHTTP` without injecting a resolver or rate limiting. Comments say "should not happen after RequireOrgRole," but no test proves this middleware ordering invariant. If middleware order changes, tier enforcement and rate limiting silently disappear.

### 3. "Resolver Missing → 500" Pattern Repeated 5 Times, Tested 0 Times

All 5 tier-gated handlers (alert_rules, channels, watchlists, orgs, org_tier) contain the same fail-closed check for missing resolver. None has a test. A single parameterized test calling each endpoint without the tier middleware would cover all 5.

### 4. Pro Tier Completely Untested for IntLimit Resources

Free tier boundaries and enterprise unlimited are well-tested. Pro tier is **never** tested at its boundary for any IntLimit resource (alert_rules=50, watchlists=20, members=25). Since pro is the most common paid tier, this is a significant gap.

### 5. Cross-Org Isolation Tests Missing at Store Level Across Multiple Domains

`CountAlertRulesByOrg`, `CountWatchlistsByOrg`, `CountMembersByOrg`, `ListAuditEntries`, and SSO store methods all use `withOrgTx` (RLS) but no store-level test creates data in org A and queries as org B. API-level tests exist for some, but store-level tests are the last line of defense — if RLS policy is misconfigured, no test catches it.

### 6. `oidcVerifyCallback` Has 2/12 Code Paths Tested

This function validates state, loads the connection, exchanges the code, verifies the token, extracts claims, and validates the nonce. Of its 12 distinct code paths, only state mismatch and the happy path have dedicated tests. This is the security core of the authentication flow and deserves the highest test density.

### 7. TOCTOU Windows in OIDC Callback Are Untested

Between redirect to IdP and callback processing, the SSO configuration can be modified or deleted. The code handles this correctly (connection not found → 404, disabled → 403), but no tests exercise these paths.

### 8. Audit Log Content on Tier Block Never Asserted

Three handlers write audit entries with `Success: false` when a tier limit blocks a mutation. The tier gating tests check for 403 status but never assert that the audit entry was written or contains the correct fields.

### 9. Same-Org Recent Data Preservation Tests Are Incomplete for Retention

`TestCleanupAlertEvents_OrgFilter` and `TestCleanupNotificationDeliveries_OrgFilter` prove cross-org isolation but do NOT insert recent rows for the cleaned org. `TestCleanupAuditLog_OrgFilter` correctly inserts both old and recent rows and verifies recent survives. The other two tests should follow the same pattern.

### 10. No Panic Recovery in Worker Ticker Loop

The worker's `Start` calls `scheduleRetention(ctx)` directly in the select loop. A panic would crash the entire worker goroutine, killing all tickers (claim, stuck-reset, recovery, digest, retention). This isn't unique to retention — it affects all tickers — but it's new Phase 5 code entering a crash-susceptible path.

### 11. Nonce Comparison Is Not Constant-Time

`oauth_oidc.go:191` uses `storedNonce != c.Nonce` (string equality). The state cookie comparison in `oauth_helpers.go:53` uses `subtle.ConstantTimeCompare`. While nonce timing attacks are impractical (one-time random value from a cookie), the inconsistency is worth noting for defense-in-depth.

---

## Appendix A: Tier Core — Per-Function Tables

### tier/resolver.go

#### `Resolver.IntLimit` (lines 12-28)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Overrides non-nil, key present, value is float64 → return override | 13-17 | Covered | — |
| Overrides non-nil, key present, value is NOT float64 → fall through | 15-17 | Covered | — |
| Overrides non-nil, key NOT present → fall through | 14 | Covered | — |
| Overrides nil → skip override block | 13 | Covered | — |
| Overrides non-nil but empty map → fall through | 13-14 | Covered | — |
| Tier == "free" → return free | 20, 26 | Covered | — |
| Tier == "pro" → return pro | 21-22 | Covered | — |
| Tier == "enterprise" → return enterprise | 23-24 | Covered | — |
| Tier == unknown → return free (default) | 25-26 | Covered | — |
| Override value is zero (valid override to 0) | 15-17 | Covered | — |
| Override value is negative (e.g., -1 for "unlimited") | 15-17 | GAP | correctness |

#### `Resolver.BoolFlag` (lines 31-47)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Overrides non-nil, key present, value is bool (true) | 33-35 | Covered | — |
| Overrides non-nil, key present, value is bool (false) | 33-35 | Covered | — |
| Overrides non-nil, key present, NOT bool → fall through | 34-35 | Covered | — |
| Overrides nil → skip block | 32 | Covered | — |
| Tier == "free" → return free | 39, 45 | Covered | — |
| Tier == "pro" → return pro | 40-41 | Covered | — |
| Tier == "enterprise" → return enterprise | 42-43 | Covered | — |
| Tier == unknown → return free | 44-45 | Covered | — |
| Overrides non-nil, empty map → fall through | 32-33 | GAP | nice-to-have |

### api/middleware_tier.go

#### `tierMiddleware` (lines 19-46)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| orgID missing → skip tier resolution, call next | 21-26 | GAP | security-critical |
| orgID present, cache hit → use cached values | 29-30 | GAP | correctness |
| orgID present, cache miss → call store.GetOrgTier | 31-32 | Covered (integration) | — |
| store.GetOrgTier returns error → 500 | 33-37 | GAP | correctness |
| store.GetOrgTier succeeds → set cache | 38-39 | GAP | correctness |
| Resolver injected into context | 42-44 | Covered (integration) | — |
| **Full chain: missing orgID → pass-through → handler 500** | 22-25 → handlers | GAP | security-critical |

#### `orgRateLimitMiddleware` (lines 50-76)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| orgID missing → skip rate limiting, call next | 52-55 | GAP | security-critical |
| Resolver missing → default ratePerMin=60 (free tier) | 59-61 | GAP | security-critical |
| Resolver present → resolves tier-specific rate | 60-61 | Covered | — |
| burst < 1 → clamped to 1 | 66-68 | GAP | correctness |
| orgRL.Allow returns true → pass through | 69 | Covered | — |
| orgRL.Allow returns false → 429 | 70-71 | Covered | — |
| Pro tier rate (300/min) | 61 | GAP | correctness |
| Enterprise tier rate (1000/min) | 61 | GAP | correctness |

### api/tier_cache.go

#### `tierCache.Get` (lines 46-58)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Not found → false | 50-52 | Covered | — |
| Found but expired → false | 54-56 | Covered | — |
| Found and valid → return cloned overrides | 57 | Covered | — |
| Exactly at TTL boundary | 54 | GAP | nice-to-have |
| nil overrides → maps.Clone(nil) = nil | 57 | Covered | — |

#### `tierCache.Set` (lines 63-72)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Stores entry with copied overrides | 67-71 | Covered | — |
| nil overrides | 69 | Covered | — |
| Overwrite existing entry for same orgID | 67 | GAP | correctness |

#### `tierCache.evictExpired` (lines 97-106)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Entry older than evictTTL → deleted | 101-103 | GAP | correctness |
| Entry within evictTTL → retained | 102 | GAP | correctness |
| Empty map → no-op | 101 | GAP | nice-to-have |

### api/org_ratelimit.go

#### `orgRateLimiter.Allow` (lines 45-56)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| New org → create limiter | 49-52 | Covered | — |
| Existing org, same rate → reuse | 50 | Covered | — |
| Rate changed → create new limiter | 50-52 | Covered | — |
| Burst changed but rate same → create new | 50-51 | GAP | correctness |
| Allow true (within burst) | 55 | Covered | — |
| Allow false (burst exhausted) | 55 | Covered | — |
| Different orgs independent | — | Covered | — |
| Rate downgrade → new limiter with lower rate | 50-52 | GAP | correctness |

---

## Appendix B: Retention — Per-Function Tables

### retention/runner.go

#### `Run` (line 51)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| cfg.Enabled == false → early return | 52-55 | Covered | — |
| Computes deadline from MaxRuntimeSeconds | 58 | Covered | — |
| cleanupTable for cve_raw_payloads | 62-64 | Covered | — |
| cleanupTable for feed_fetch_log | 66-68 | Covered | — |
| cleanupTable for job_queue | 70-72 | Covered | — |
| cleanupTable for refresh_tokens | 74-76 | Covered | — |
| cleanupTable for ai_request_log | 78-80 | Covered | — |
| cleanupTable for ai_cache | 82-84 | Covered | — |
| cleanupTable for ai_usage_counters | 86-88 | Covered | — |
| cleanupTierGated returns error → logged, run continues | 91-93 | GAP | correctness |
| Returns nil unconditionally | 97 | GAP | correctness |

#### `cleanupTierGated` (line 101)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| ListAllOrgs returns error → return immediately | 102-105 | GAP | correctness |
| Groups orgs by alert_events retention | 108-114 | Covered | — |
| Groups orgs by notification_deliveries retention | 117-123 | GAP | correctness |
| Groups orgs by audit_log retention | 126-132 | Covered | — |

#### `cleanupTable` (line 157)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Deadline exceeded on first check → return | 162-165 | Covered | — |
| Context cancelled → return | 167-169 | GAP | correctness |
| fn returns error → log, return | 172-176 | Covered | — |
| fn returns 0 rows → break | 179-181 | Covered | — |
| fn returns >0 rows → accumulate, loop | 178 | Covered | — |

---

## Appendix C: Audit — Per-Function Tables

### audit/redact.go

#### `redactSecrets` (lines 23-46)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| nil input → nil | 24-26 | Covered | — |
| key matches "secret" | 29-32 | Covered | — |
| key matches "password" | 29-32 | Covered | — |
| key matches "api_key" | 29-32 | Covered | — |
| key matches "token" | 29-32 | Covered | — |
| key matches "private_key" | 29-32 | Covered | — |
| key matches "key_hash" | 29-32 | Covered | — |
| case-insensitive matching | 29-32 | Covered | — |
| substring matching | 29-32 | Covered | — |
| entityType=="channel" + key=="url" → URL redacted | 33-37 | Covered | — |
| channel + url but value is non-string | 33-37 | GAP | correctness |
| non-channel + key=="url" → preserved | 33-37 | Covered | — |
| nested map → recursive | 39-42 | Covered | — |
| deeply nested (3+ levels) | 39-42 | GAP | correctness |

#### `redactURL` (lines 60-66)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| valid URL → scheme://host/*** | 64-65 | Covered | — |
| invalid URL → "[REDACTED]" | 62-63 | Covered | — |
| URL with query params (?token=abc) → params stripped | 64-65 | GAP | security-critical |
| URL with userinfo (user:pass@host) | 64-65 | GAP | security-critical |

### audit/writer.go

#### `Writer.Log` (lines 43-74)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| context.WithoutCancel detaches | 45 | GAP | correctness |
| panic recovery in goroutine | 50-53 | GAP | correctness |
| ActorEmail empty + ActorID non-nil → lookup | 57-62 | Covered | — |
| ActorEmail empty + ActorID nil → skip (system) | 57 | Covered | — |
| ActorEmail non-empty → skip lookup | 57 | Covered | — |
| GetUserByID returns error → empty email | 58-59 | GAP | correctness |
| GetUserByID returns nil → empty email | 59 | GAP | correctness |
| buildStoreEntry fails → logs error, entry dropped | 64-68 | GAP | security-critical |
| InsertAuditEntry fails → logs error | 70-72 | Covered | — |
| InsertAuditEntry succeeds | 70-72 | Covered | — |

---

## Appendix D: SSO/OIDC — Per-Function Tables

### crypto/aes.go

#### `Encrypt` (lines 15-33)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy path | 15-33 | Covered | — |
| io.ReadFull entropy exhaustion | 27-29 | GAP | nice-to-have |
| Empty plaintext | 15-33 | Covered | — |
| Nonce uniqueness | 26-32 | Covered | — |

#### `Decrypt` (lines 37-60)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy path | 37-60 | Covered | — |
| data shorter than nonce size | 49-51 | Covered | — |
| Wrong key → GCM auth fails | 37-57 | Covered | — |
| Tampered ciphertext → GCM auth fails | 54-57 | Covered | — |
| Nonce-only ciphertext (exactly 12 bytes) | 49-57 | GAP | security-critical |

### api/oauth_oidc.go — `oidcVerifyCallback` (lines 105-197)

This is the security core. 12 paths, 2 tested.

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| State param mismatch → 400 | 110-113 | Covered | — |
| Malformed state (no underscore) → 400 | 114-118 | GAP | security-critical |
| Invalid UUID in state → 400 | 119-123 | GAP | security-critical |
| GetSSOConnectionByID error → 500 | 126-131 | GAP | correctness |
| Connection not found (TOCTOU: deleted) → 404 | 132-135 | GAP | security-critical |
| Connection disabled (TOCTOU: disabled) → 403 | 136-139 | GAP | security-critical |
| Build OIDC config error → 500 | 142-147 | GAP | correctness |
| Code exchange failure → 400 | 150-156 | GAP | correctness |
| Missing id_token → 400 | 159-164 | GAP | security-critical |
| ID token verification failure → 400 | 166-171 | GAP | security-critical |
| Claims extraction error → 500 | 174-179 | GAP | correctness |
| Missing sub claim → 400 | 180-183 | GAP | security-critical |
| Nonce cookie missing → 400 | 186-190 | GAP | security-critical |
| Nonce mismatch → 400 | 191-194 | GAP | security-critical |
| Happy path: returns connID + claims | 196 | Covered | — |

### api/sso.go — Security Checklist

| Check | Status |
|-------|--------|
| Cross-org isolation | GAP — no API-level test |
| Unauthenticated → 401 | Covered via middleware |
| RBAC: only owner can configure SSO | Covered (TestSSOConnection_RBAC) |
| Client secret never returned (GET) | Covered (masked as "***") |
| Client secret redacted in audit logs | Covered ("[REDACTED]") |
| orgID fail-closed | Architecturally enforced via withOrgTx + RLS, no unit test |
| Tier gating: free/pro → 403 | Covered on POST, GAP on GET/PATCH/DELETE |

### store/sso.go — Security Checklist

| Check | Status |
|-------|--------|
| org_id always in WHERE (org-scoped methods) | Covered architecturally via withOrgTx |
| Cross-org isolation at store level | GAP — no two-org store test |
| GetSSOConnectionByID uses withBypassTx (public path) | Correct |
| LookupSSOByDomain uses withBypassTx (public path) | Correct |

---

## Appendix E: Integration Test Inventories

### tier_gating_test.go (12 tests)

| Test | Resource | Tier | Assertion |
|------|----------|------|-----------|
| TestTierGating_AlertRules_FreeLimit | Alert Rules | Free | 5 ok, 6th→403 |
| TestTierGating_Watchlists_FreeLimit | Watchlists | Free | 3 ok, 4th→403 |
| TestTierGating_Channels_FreeBlocksEmail | Channels | Free | webhook=201, email=403 |
| TestTierGating_Channels_ProAllowsEmail | Channels | Pro | email=201 |
| TestTierGating_Channels_OverrideAllowsEmail | Channels | Free+Override | email=201 |
| TestTierGating_AlertRules_OverrideExpandsLimit | Alert Rules | Free+Override | 6 rules (override=10) ok |
| TestTierGating_Members_FreeLimit | Members | Free | 5 members, invite→403 |
| TestTierGating_Members_PendingInvitationsConsumeSlots | Members | Free | 4+1 pending, 2nd invite→403 |
| TestTierGating_OrgRateLimit | Rate Limit | Free+Override | override=2/min, 429 |
| TestTierGating_AlertRules_EnterpriseUnlimited | Alert Rules | Enterprise | 10 ok |
| TestTierGating_Watchlists_EnterpriseUnlimited | Watchlists | Enterprise | 10 ok |
| TestTierGating_Members_EnterpriseUnlimited | Members | Enterprise | 10+ ok |

### audit_integration_test.go — Entity Coverage

| Entity Type | Create | Update | Delete | Tier-Denied |
|-------------|--------|--------|--------|-------------|
| alert_rule | Tested | Tested | Tested | Tested |
| channel | Tested (w/ redaction) | Tested | Tested | Tested |
| watchlist | Tested | Tested | Tested | Tested |
| org_member | Tested (invite) | Tested (role) | Tested (remove) | N/A |
| saved_search | Tested | Tested | Tested | N/A |
| sso_connection | Tested | Tested | Tested | N/A |
| **api_key** | **GAP** | N/A | **GAP** | N/A |

### SSO/OIDC Test Coverage

| Test | What it proves |
|------|----------------|
| TestSSOConnection_CRUD | Full lifecycle + secret masking + domain response |
| TestSSOConnection_TierGating | Free → 403 on POST |
| TestSSOConnection_RBAC | Member → 403 |
| TestSSOConnection_UniquePerOrg | Second connection → 409 |
| TestCreateSSO_FieldValidation | Empty fields → 422 |
| TestSSODomains_ValidatesFormat | Invalid domains → 422 |
| TestSSODomains_RFC1035Labels | 9 invalid + 4 valid labels |
| TestPatchSSO_EvictsOIDCProviderCache | Issuer change → cache evict |
| TestDeleteSSO_EvictsOIDCProviderCache | Delete → cache evict |
| TestDiscover_MatchingDomain | Enabled connection found |
| TestDiscover_DisabledConnection | Disabled → not returned |
| TestDiscover_UnknownDomain | No match → empty |
| TestDiscover_RateLimited | 429 after burst |
| TestOIDCFlow_Success | Full login flow with mock IdP |
| TestOIDCFlow_CSRFMismatch | State mismatch → 400 |
| TestOIDCFlow_NoIdentity | No linked identity → 403 |
| TestOIDCFlow_DisabledConnection | Disabled → 403 |
| TestOIDCLogin_InvalidConnectionID | Bad UUID → 400 |
| TestOIDCLogin_NonexistentConnectionID | Missing → 404 |
| TestIdentityLinking_Success | Link + login flow |
| TestIdentityLinking_AlreadyLinked | Different user → 409 |
| TestIdentityLinking_Idempotent | Re-link same user → ok |
| TestIdentityLinking_NoAuthCookie | Missing auth → 401 |
| TestIdentityLinking_InvalidJWT | Bad JWT → 401 |
| TestIdentityLinking_NoSSOConnection | No SSO → 404 |
| TestIdentityLinking_DisabledSSO | Disabled → 403 |
