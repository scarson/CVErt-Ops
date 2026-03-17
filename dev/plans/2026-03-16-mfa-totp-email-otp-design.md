# MFA Design: TOTP + Email OTP + Recovery Codes

**Date:** 2026-03-16
**Scope:** Multi-factor authentication for native accounts — TOTP, email OTP, one-time recovery codes, forced password reset, enforcement model
**Prerequisite:** Phase 2a auth system (JWT, OAuth, RBAC, account lockout)
**Companion doc:** Passkeys (WebAuthn/FIDO2) will be a separate design doc

---

## Decisions Made (Resolved in Brainstorming)

| Topic | Decision |
|---|---|
| MFA methods | TOTP + email OTP (no SMS — insecure). Passkeys deferred to separate design. |
| Method stacking | Users can enroll multiple methods simultaneously; choose at challenge time |
| Recovery codes | 10 one-time codes, `xxxxx-xxxxx` alphanumeric format, SHA-256 hashed, shown once on first MFA enrollment |
| TOTP algorithm | SHA-1 / 6 digits / 30s period — universal authenticator app compatibility (MS Authenticator, Duo, Authy silently fail on SHA-256) |
| MFA challenge flow | MFA pending token (short-lived JWT with `pending` array), not server-side session |
| OAuth users | No CVErt Ops MFA for OAuth-only users — enforce at IdP level |
| IdP MFA detection | Best-effort `amr` claim inspection (Okta, Google, Entra v1.0); not enforced (Entra v2.0 lacks `amr`) |
| API keys | Bypass MFA (separate auth mechanism, standard practice) |
| Remember device | Org-configurable, default 30 days (7–90 range), works for all methods equally |
| Admin password setting | Never — admins trigger resets, never set passwords directly |
| Forced password reset | Included in scope; shares restricted session infrastructure with MFA |

**Key references:**
- [TOTP authenticator compatibility testing (2025)](https://feeding.cloud.geek.nz/posts/totp-in-2025/)
- [5 Common TOTP Mistakes (Authgear)](https://www.authgear.com/post/5-common-totp-mistakes)
- [TOTP developer guide (Authgear)](https://www.authgear.com/post/what-is-totp)
- [Microsoft Entra ID token claims](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference) — v2.0 tokens lack `amr`
- [Okta AMR claims mapping](https://developer.okta.com/docs/guides/configure-amr-claims-mapping/main/)

---

## Data Model

### New Tables

#### `mfa_credentials` (global, no RLS)

One row per enrolled method per user. MFA is per-user identity, not per-org.

```sql
CREATE TABLE IF NOT EXISTS mfa_credentials (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method          TEXT NOT NULL,
    secret_enc      BYTEA,
    last_used_step  BIGINT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ,
    UNIQUE(user_id, method),
    CONSTRAINT mfa_cred_method      CHECK (method IN ('totp', 'email_otp')),
    CONSTRAINT mfa_cred_totp_secret CHECK (method != 'totp' OR secret_enc IS NOT NULL),
    CONSTRAINT mfa_cred_email_null  CHECK (method != 'email_otp' OR (secret_enc IS NULL AND last_used_step IS NULL))
);

GRANT SELECT, INSERT, UPDATE, DELETE ON mfa_credentials TO cvert_ops_app;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mfa_credentials_user_id ON mfa_credentials(user_id);
```

- `secret_enc`: AES-256-GCM encrypted TOTP shared secret using existing `SSOEncryptionKey` infrastructure
- `last_used_step`: TOTP replay prevention — last successfully verified time step
- Type-discriminated: TOTP requires `secret_enc`; email OTP must have both NULL
- `UPDATE` grant for `last_used_step` and `last_used_at`; `DELETE` for method removal

#### `mfa_recovery_codes` (global, no RLS)

Per-user, not per-method. 10 codes generated on first MFA enrollment.

```sql
CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash       TEXT NOT NULL,
    used_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, code_hash)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON mfa_recovery_codes TO cvert_ops_app;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mfa_recovery_codes_user_id ON mfa_recovery_codes(user_id);
```

- `code_hash`: SHA-256 (not argon2 — codes are high-entropy random, 128+ bits, brute-force infeasible)
- `used_at`: NULL = unused, timestamp = consumed. `UPDATE` grant for marking used.
- `DELETE` grant for regeneration (hard-delete old set, insert new)
- Recovery code format: `xxxxx-xxxxx` alphanumeric (a–z, 0–9)

#### `mfa_challenges` (global, no RLS)

Active email OTP codes and remember-device tokens. Authentication context, not org-scoped.

```sql
CREATE TABLE IF NOT EXISTS mfa_challenges (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    challenge_type  TEXT NOT NULL,
    token_hash      TEXT NOT NULL,
    attempts        INT NOT NULL DEFAULT 0,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT mfa_challenge_type CHECK (challenge_type IN ('email_otp', 'remember_device'))
);

GRANT SELECT, INSERT, UPDATE, DELETE ON mfa_challenges TO cvert_ops_app;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mfa_challenges_user_id ON mfa_challenges(user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mfa_challenges_expires ON mfa_challenges(expires_at);
```

- `token_hash`: SHA-256 of email OTP code (6-digit) or device token (high-entropy random)
- `attempts`: brute-force tracking for email OTP (max 3); unused for remember_device
- `expires_at`: 10 minutes for email OTP, org's `mfa_remember_device_days` for device tokens
- `expires_at` index supports periodic cleanup job
- `user_id` index sufficient for both email OTP and remember-device lookups (few rows per user)
- Email OTP resend: `DELETE WHERE user_id AND challenge_type = 'email_otp'` before inserting new challenge

#### `mfa_requirements` (org-scoped, RLS)

Per-member MFA mandates set by org owners/admins.

```sql
CREATE TABLE IF NOT EXISTS mfa_requirements (
    org_id          UUID NOT NULL,
    user_id         UUID NOT NULL,
    required_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id),
    FOREIGN KEY (org_id, user_id) REFERENCES org_members(org_id, user_id) ON DELETE CASCADE
);

ALTER TABLE mfa_requirements ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_requirements FORCE ROW LEVEL SECURITY;
CREATE POLICY mfa_requirements_policy ON mfa_requirements
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );

GRANT SELECT, INSERT, DELETE ON mfa_requirements TO cvert_ops_app;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mfa_requirements_user_id ON mfa_requirements(user_id);
```

- Composite FK to `org_members(org_id, user_id)` ensures requirements only exist for actual members; auto-cleanup on membership removal
- `required_by`: nullable — persists as audit trail if the admin who set it is deleted
- No `UPDATE` grant — add or remove only, no mutable columns
- `user_id` index supports cross-org mandate check at login (`withBypassTx`)

### Modifications to Existing Tables

```sql
-- Forced password reset flag (account-level)
ALTER TABLE users ADD COLUMN force_password_reset BOOLEAN NOT NULL DEFAULT FALSE;

-- Org-level MFA settings
ALTER TABLE organizations ADD COLUMN mfa_required_all BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE organizations ADD COLUMN mfa_remember_device_allowed BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE organizations ADD COLUMN mfa_remember_device_days INT NOT NULL DEFAULT 30
    CONSTRAINT mfa_remember_days_range CHECK (mfa_remember_device_days BETWEEN 7 AND 90);
```

### Design Decision: No `users.mfa_enabled` Flag

MFA enrollment status is derived at login from `EXISTS(SELECT 1 FROM mfa_credentials WHERE user_id = $1)`. A denormalized `mfa_enabled` boolean was considered and rejected — it creates sync liability (flag vs actual credentials) with negligible performance benefit (MFA check only happens at login, which already does argon2 hashing + DB queries).

### Site-Level Configuration (env vars)

```go
MFARequiredSiteAdmins   bool          `env:"MFA_REQUIRED_SITE_ADMINS" envDefault:"false"`
MFARequiredOrgOwners    bool          `env:"MFA_REQUIRED_ORG_OWNERS" envDefault:"false"`
MFAEmailOTPTTL          time.Duration `env:"MFA_EMAIL_OTP_TTL" envDefault:"10m"`
MFAEmailOTPMaxPerHour   int           `env:"MFA_EMAIL_OTP_MAX_PER_HOUR" envDefault:"5"`
MFAChallengeMaxAttempts int           `env:"MFA_CHALLENGE_MAX_ATTEMPTS" envDefault:"3"`
MFAPendingTokenTTL      time.Duration `env:"MFA_PENDING_TOKEN_TTL" envDefault:"5m"`
```

### Retention

`mfa_challenges` requires periodic cleanup: `DELETE FROM mfa_challenges WHERE expires_at < now()`. Run as a worker periodic task (hourly). Expired challenges are harmless until cleaned but consume space.

Recovery codes and credentials are cleaned up by application logic (CASCADE on user deletion, explicit DELETE on method removal / MFA reset).

---

## Authentication Flow

### Restricted Session Token (Pending Token)

A short-lived JWT issued when authentication is incomplete. Uses a `pending` array instead of a single `purpose` string to support composable multi-step requirements.

**Claims:**
```json
{
    "sub": "user-uuid",
    "tv": 42,
    "pending": ["mfa_challenge", "password_reset"],
    "methods": ["totp", "email_otp"],
    "exp": 1234567890
}
```

- `tv`: token_version — validated on every step completion; mismatch (e.g., admin force-reset during active challenge) → reject, force re-login
- `pending`: ordered array of requirements; first item = next gate to clear
- `methods`: only present when `pending` contains `"mfa_challenge"` (tells client which MFA options to show)
- TTL: 5 minutes per step (each completion reissues with fresh TTL and remaining items)

**Fixed completion order (most sensitive first):**
1. `mfa_challenge` — prove full identity before any account changes
2. `password_reset` — change compromised password
3. `mfa_enrollment_required` — set up MFA if mandated but not enrolled

**Valid combinations:**

| Has MFA? | MFA mandated? | Forced reset? | Pending array |
|----------|--------------|---------------|---------------|
| Yes | — | No | `["mfa_challenge"]` |
| Yes | — | Yes | `["mfa_challenge", "password_reset"]` |
| No | Yes | No | `["mfa_enrollment_required"]` |
| No | Yes | Yes | `["password_reset", "mfa_enrollment_required"]` |
| No | No | Yes | `["password_reset"]` |
| No | No | No | `[]` → full tokens immediately |

### Login Flow (Modified)

```
POST /api/v1/auth/login { email, password }
│
├─ Lockout check (existing)
├─ Password verification (existing)
├─ Account lockout recording (existing)
│
├─ Check: does user have MFA credentials?
│   EXISTS(SELECT 1 FROM mfa_credentials WHERE user_id = $1)
│
├─ If MFA enrolled:
│   ├─ Check: valid remember-device token in cookie?
│   │   Hash cookie → lookup WHERE user_id AND token_hash
│   │       AND challenge_type = 'remember_device' AND expires_at > now()
│   │   └─ If valid: skip MFA challenge (but still check forced reset)
│   └─ If no valid device token: add "mfa_challenge" to pending
│
├─ Check: force_password_reset flag → add "password_reset" to pending
│
├─ If no MFA enrolled:
│   └─ Check: is MFA required? (3-layer check) → add "mfa_enrollment_required" to pending
│
├─ If pending is empty: issue full access + refresh tokens (existing flow)
└─ If pending has items: issue restricted pending token + return { pending, methods }
```

### MFA Challenge Flow

```
POST /api/v1/auth/mfa/challenge { method: "email_otp" }
  Cookie: mfa_pending_token
│
├─ Validate pending token (not expired, tv matches, "mfa_challenge" is first pending item)
├─ If method = "email_otp":
│   ├─ Rate limit check (MFAEmailOTPMaxPerHour)
│   ├─ DELETE FROM mfa_challenges WHERE user_id AND challenge_type = 'email_otp'
│   ├─ Generate 6-digit numeric code
│   ├─ INSERT mfa_challenges (token_hash = SHA-256(code), expires_at = now() + MFAEmailOTPTTL)
│   └─ Queue email delivery to users.email (non-blocking)
└─ If method = "totp": return 200 (no server action needed)

POST /api/v1/auth/mfa/verify { method, code, remember_device: false }
  Cookie: mfa_pending_token
│
├─ Validate pending token (not expired, tv matches)
│
├─ If method = "totp":
│   ├─ Decrypt secret_enc from mfa_credentials
│   ├─ Verify code against current time step ± 1
│   ├─ Reject if last_used_step == current step (replay prevention)
│   ├─ UPDATE last_used_step, last_used_at
│   └─ On failure: increment lockout counter
│
├─ If method = "email_otp":
│   ├─ Lookup mfa_challenges WHERE user_id AND challenge_type = 'email_otp' AND expires_at > now()
│   ├─ Check attempts < MFAChallengeMaxAttempts, increment attempts
│   ├─ Compare SHA-256(code) with token_hash
│   ├─ On success: DELETE challenge row
│   └─ On 3rd failure: DELETE challenge (must request new code)
│
├─ If method = "recovery":
│   ├─ SHA-256(code) → lookup mfa_recovery_codes WHERE user_id AND code_hash AND used_at IS NULL
│   ├─ On match: UPDATE used_at = now()
│   └─ On failure: increment lockout counter
│
└─ On any success:
    ├─ Remove "mfa_challenge" from pending array
    ├─ If remember_device requested AND org allows it:
    │   ├─ Generate device token
    │   ├─ INSERT mfa_challenges(challenge_type='remember_device',
    │   │     token_hash=SHA-256(token), expires_at=now()+org.mfa_remember_device_days)
    │   └─ Set mfa_device_token cookie
    ├─ If pending still has items: reissue pending token with remaining items
    └─ If pending empty: issue full access + refresh tokens
```

### Password Reset Interaction

After a forgot-password flow completes (user proved identity via email token), MFA status is checked:
- Has MFA credentials → issue pending token with `["mfa_challenge"]`
- No MFA, mandated → issue pending token with `["mfa_enrollment_required"]`
- No MFA, not required → issue full tokens

This prevents password reset from being an MFA bypass. Users who've lost both their password AND MFA device use recovery codes. Users who've lost everything need an admin MFA reset.

### MFA Enrollment Flow

#### TOTP

```
POST /api/v1/auth/mfa/totp/setup
  Requires: access token OR restricted enrollment session
│
├─ Generate random 20-byte TOTP secret
├─ Build otpauth:// URI:
│   otpauth://totp/CVErt%20Ops:{email}?secret={base32}&issuer=CVErt%20Ops&algorithm=SHA1&digits=6&period=30
├─ Validate URI round-trips (parse back, verify secret intact)
├─ Encrypt secret, create enrollment token
├─ Set mfa_enrollment_token as HttpOnly cookie (path: /api/v1/auth/mfa, 5 min TTL)
└─ Return { qr_code_uri, secret } in response body

POST /api/v1/auth/mfa/totp/confirm { code }
  Cookies: access token or pending token + mfa_enrollment_token
│
├─ Decrypt secret from enrollment token cookie
├─ Verify code against secret (current time step ± 1)
├─ INSERT INTO mfa_credentials (method='totp', secret_enc=encrypt(secret))
├─ If first MFA method: generate 10 recovery codes
│   ├─ INSERT INTO mfa_recovery_codes (10 rows, SHA-256 hashed)
│   └─ Return codes in response body (shown once, never retrievable again)
├─ Clear enrollment token cookie
└─ If in restricted enrollment session: remove "mfa_enrollment_required" from pending
```

**Frontend requirement:** The TOTP setup screen MUST show both the QR code AND provide a "Can't scan? Show secret key" toggle that reveals the copyable base32 secret. This supports hardware tokens and authenticator apps that don't support QR scanning.

#### Email OTP

```
POST /api/v1/auth/mfa/email-otp/setup
  Requires: access token OR restricted enrollment session
│
├─ Send verification code to users.email (same challenge mechanism as login)
└─ Return 200

POST /api/v1/auth/mfa/email-otp/confirm { code }
│
├─ Verify code (same as login email OTP verification)
├─ INSERT INTO mfa_credentials (method='email_otp', secret_enc=NULL)
├─ If first MFA method: generate recovery codes (same as TOTP)
└─ If in restricted enrollment session: remove "mfa_enrollment_required" from pending
```

### MFA Management

```
DELETE /api/v1/auth/mfa/methods/{method} { current_password }
  Requires: access token + current_password for re-authentication
│
├─ Verify current_password
├─ Check: is this the last method AND is MFA mandated? → 403
├─ DELETE FROM mfa_credentials WHERE user_id AND method
├─ If no remaining credentials:
│   └─ DELETE FROM mfa_recovery_codes WHERE user_id
└─ Return 204

POST /api/v1/auth/mfa/recovery-codes/regenerate { current_password }
  Requires: access token + current_password + at least one MFA method enrolled
│
├─ Verify current_password
├─ Check: at least one MFA credential exists → 409 if not
├─ DELETE FROM mfa_recovery_codes WHERE user_id
├─ Generate 10 new codes, INSERT
└─ Return new codes (shown once)
```

### Forced Password Reset Flow

```
POST /api/v1/auth/password/change { current_password*, new_password }
│
├─ If full session: require current_password, verify it
├─ If restricted session (pending contains "password_reset"): skip current_password
│   (password may be compromised; restricted token proves prior auth)
├─ Hash new_password with argon2id
├─ UPDATE users SET password_hash, force_password_reset = false
├─ Increment token_version (invalidate other sessions)
├─ Reissue token: remove "password_reset" from pending, or full tokens if empty
└─ Log security events
```

---

## Enforcement Model

### Three Layers (evaluated at login, under `withBypassTx`)

```
Layer 1 — Site config (env vars, deploy-time):
  MFA_REQUIRED_SITE_ADMINS=true  → site admins must have MFA
  MFA_REQUIRED_ORG_OWNERS=true   → org owners must have MFA

Layer 2 — Org-wide (DB, managed by owners/admins):
  organizations.mfa_required_all=true → all org members must have MFA

Layer 3 — Per-member (DB, managed by owners/admins):
  mfa_requirements row for (org_id, user_id) → this member must have MFA
```

**Implementation note:** The MFA mandate check at login must use `withBypassTx` because it queries across org boundaries (`org_members`, `organizations`, `mfa_requirements` — all have RLS). Login is a pre-org-context operation.

### Enforcement Behavior

When MFA becomes required (org-level toggle or per-member), enforcement is **immediate**:
- Current access tokens remain valid until expiry (≤15 min)
- On next refresh token rotation, the user receives a restricted session
- No configurable grace period

### Dynamic Mandate Check

```go
func userMFARequired(ctx context.Context, userID uuid.UUID, isSiteAdmin bool, cfg Config) (bool, error) {
    // Layer 1: site config
    if cfg.MFARequiredSiteAdmins && isSiteAdmin { return true, nil }
    if cfg.MFARequiredOrgOwners {
        if isOwner, _ := store.IsOrgOwner(ctx, userID); isOwner { return true, nil }
    }
    // Layer 2: org-wide
    if has, _ := store.UserInMFARequiredOrg(ctx, userID); has { return true, nil }
    // Layer 3: per-member
    return store.UserHasMFARequirement(ctx, userID)
}
```

### "Can I Disable MFA?" Check

Dynamic, not a sticky flag. If the user leaves the org that mandated MFA (composite FK CASCADE cleans up `mfa_requirements`), the mandate disappears and they can disable MFA on themselves.

### Permission Matrix

| Action | Allowed by |
|--------|-----------|
| Enable MFA on self | Any user |
| Disable MFA on self | Only if no active mandate (all 3 layers) |
| Set `mfa_required_all` on org | Org owner or admin |
| Unset `mfa_required_all` on org | Org owner or admin |
| Add per-member MFA requirement | Org owner or admin |
| Remove per-member MFA requirement | Org owner or admin |
| Reset MFA for member/admin | Org owner |
| Reset MFA for owner | **Site admin only** (prevents lateral compromise) |
| Force password reset for member/admin | Org owner or admin |
| Force password reset for owner | **Site admin only** |
| Send password reset email | Org owner or admin (members/admins) or site admin (owners) |
| Configure remember-device settings | Org owner or admin |

### OAuth / Federated Users

- Native MFA is not required for OAuth-only users (no password to verify first factor)
- Best-effort `amr` claim inspection on OIDC login:
  - Okta, Google, Entra v1.0: `amr` present in ID token when MFA was used
  - Entra v2.0: `amr` **not available** (recommended endpoint for new apps)
  - GitHub: raw OAuth, no ID token, no `amr`
- If `amr` present and contains `"mfa"`: logged as confirmed federated MFA
- If absent: logged as indeterminate
- **No enforcement gate** — orgs should enforce MFA at the IdP level (Entra Conditional Access, Okta sign-on policies)
- Future consideration: `require_idp_mfa` org setting that rejects OIDC logins without `amr` containing `"mfa"` (with Entra v2.0 limitation clearly documented)

---

## Admin Actions

### MFA Reset

```
POST /api/v1/orgs/{org_id}/members/{user_id}/reset-mfa
  Requires: org owner (members/admins) or site admin (owners)
│
├─ Permission check per hierarchy
├─ DELETE FROM mfa_credentials WHERE user_id
├─ DELETE FROM mfa_recovery_codes WHERE user_id
├─ DELETE FROM mfa_challenges WHERE user_id
├─ Increment user.token_version (invalidate all sessions)
└─ Log security_event: mfa.admin_reset (severity: critical)
```

### Force Password Reset

```
POST /api/v1/orgs/{org_id}/members/{user_id}/force-password-reset
  Requires: org owner/admin (members/admins) or site admin (owners)
│
├─ Guard: user must have native identity (password_hash IS NOT NULL) → 400 if OAuth-only
├─ UPDATE users SET force_password_reset = true
├─ Increment token_version (force re-login)
├─ DELETE FROM mfa_challenges WHERE user_id AND challenge_type = 'remember_device'
└─ Log security_event: auth.password_reset_forced (severity: critical)
```

### Send Password Reset Email

```
POST /api/v1/orgs/{org_id}/members/{user_id}/send-password-reset
  Requires: org owner/admin (members/admins) or site admin (owners)
│
├─ Rate limit: same as user-initiated (3/hour per target user)
├─ Generate reset token, store SHA-256 hash (existing mechanism)
├─ Queue email delivery
└─ Log security_event: auth.password_reset_sent_by_admin
```

### User Management Integration

`GET /api/v1/orgs/{org_id}/members` — add `mfa_enrolled: bool` as a filterable property for admin visibility of who has/hasn't enrolled MFA.

---

## API Surface

### MFA Authentication (restricted session)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/auth/mfa/challenge` | Pending token | Request email OTP code or signal TOTP readiness |
| POST | `/api/v1/auth/mfa/verify` | Pending token | Submit MFA code + optional remember_device flag |

### MFA Enrollment (authenticated or restricted enrollment)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/auth/mfa/methods` | Access token | List enrolled methods, recovery codes remaining, enforcement reasons |
| POST | `/api/v1/auth/mfa/totp/setup` | Access/enrollment token | Generate TOTP secret + QR URI; enrollment token set as cookie |
| POST | `/api/v1/auth/mfa/totp/confirm` | Access/enrollment token + enrollment cookie | Verify code, finalize TOTP enrollment |
| POST | `/api/v1/auth/mfa/email-otp/setup` | Access/enrollment token | Send verification code to user's email |
| POST | `/api/v1/auth/mfa/email-otp/confirm` | Access/enrollment token | Verify code, finalize email OTP enrollment |
| DELETE | `/api/v1/auth/mfa/methods/{method}` | Access token | Remove method (requires `current_password` in body) |
| POST | `/api/v1/auth/mfa/recovery-codes/regenerate` | Access token | Regenerate codes (requires `current_password`, active MFA enrollment) |

### Password Management

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/auth/password/change` | Access or pending token | Change password; `current_password` required in full session, skipped in forced reset |

### Admin Actions (org-scoped)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `.../members/{user_id}/reset-mfa` | Owner or site admin | Delete all MFA state, invalidate sessions |
| POST | `.../members/{user_id}/force-password-reset` | Owner/admin or site admin | Set flag, invalidate sessions + device tokens |
| POST | `.../members/{user_id}/send-password-reset` | Owner/admin or site admin | Send reset email (rate-limited) |
| POST | `.../members/{user_id}/require-mfa` | Owner/admin | Add per-member MFA requirement |
| DELETE | `.../members/{user_id}/require-mfa` | Owner/admin | Remove per-member MFA requirement |
| PATCH | `/api/v1/orgs/{org_id}/settings` | Owner/admin | Update `mfa_required_all`, remember-device settings |

### Modified Existing Endpoints

| Endpoint | Change |
|----------|--------|
| `POST /auth/login` | Returns `pending` array + methods when MFA required; pending token cookie |
| `POST /auth/refresh` | Validates `tv` on pending tokens |
| `GET /auth/me` | Add `mfa_methods`, `mfa_required` |
| `GET /orgs/{org_id}/members` | Add `mfa_enrolled` filterable property |
| `POST /auth/password-reset` | Check MFA after reset → issue pending token if MFA enrolled |

### Response Shapes

```json
// POST /auth/login — full auth (no MFA)
{ "user_id": "...", "pending": [] }
// + Set-Cookie: access_token, refresh_token

// POST /auth/login — MFA required
{ "user_id": "...", "pending": ["mfa_challenge"], "methods": ["totp", "email_otp"] }
// + Set-Cookie: mfa_pending_token

// POST /auth/mfa/verify — success, more steps
{ "user_id": "...", "pending": ["password_reset"] }
// + Set-Cookie: mfa_pending_token (reissued)

// POST /auth/mfa/verify — success, complete
{ "user_id": "...", "pending": [] }
// + Set-Cookie: access_token, refresh_token
// + Set-Cookie: mfa_device_token (if remember_device requested and allowed)

// POST /auth/mfa/totp/setup
{ "qr_code_uri": "otpauth://totp/...", "secret": "JBSWY3DPEHPK3PXP" }
// + Set-Cookie: mfa_enrollment_token

// POST /auth/mfa/totp/confirm (first method)
{ "recovery_codes": ["ab3kx-9pm2f", "c7wnq-4ht8j", ...] }

// GET /auth/mfa/methods
{
    "methods": [
        { "method": "totp", "created_at": "...", "last_used_at": "..." },
        { "method": "email_otp", "created_at": "...", "last_used_at": "..." }
    ],
    "recovery_codes_remaining": 8,
    "required": true,
    "required_reasons": [
        { "source": "org_policy", "org_name": "Acme Corp" },
        { "source": "per_member", "org_name": "Acme Corp" }
    ]
}
```

### Cookie Specifications

| Cookie | Path | HttpOnly | Secure | SameSite | TTL |
|--------|------|----------|--------|----------|-----|
| `mfa_pending_token` | `/api/v1/auth` | Yes | Yes (configurable dev) | Lax | 5 min |
| `mfa_enrollment_token` | `/api/v1/auth/mfa` | Yes | Yes (configurable dev) | Lax | 5 min |
| `mfa_device_token` | `/api/v1/auth/login` | Yes | Yes (configurable dev) | Lax | org's `mfa_remember_device_days` |

### Middleware

Existing auth middleware extended to check `pending` array in JWT claims:
- `pending` empty or absent → normal session, proceed
- `pending[0] == "mfa_challenge"` → only allow `/auth/mfa/challenge`, `/auth/mfa/verify`
- `pending[0] == "password_reset"` → only allow `/auth/password/change`
- `pending[0] == "mfa_enrollment_required"` → only allow `/auth/mfa/*/setup`, `/auth/mfa/*/confirm`
- All other routes → 403

This is a single check in existing middleware, not a new middleware layer. The first item in `pending` determines which routes are accessible.

---

## Security Events (Audit Log)

All events logged to the `security_events` table. Every event includes `actor_ip`, `user_id`, `created_at`.

### Authentication Events

| Event type | When | Severity | Details |
|-----------|------|----------|---------|
| `mfa.challenge_requested` | Email OTP code sent | info | `{ method, user_id, email }` |
| `mfa.verify_success` | MFA code accepted | info | `{ method, user_id }` |
| `mfa.verify_failed` | MFA code rejected | warning | `{ method, user_id, reason }` |
| `mfa.challenge_exhausted` | 3 failed email OTP attempts invalidated challenge | warning | `{ user_id, method: "email_otp" }` |
| `mfa.email_otp_rate_limited` | Hourly email OTP limit reached | warning | `{ user_id }` |
| `mfa.remember_device_issued` | Device token created | info | `{ user_id, expires_at }` |
| `mfa.remember_device_used` | Device token bypassed MFA challenge | info | `{ user_id }` |

### Recovery Code Events (explicit audit of all generation and usage)

| Event type | When | Severity | Details |
|-----------|------|----------|---------|
| `mfa.recovery_codes_generated` | First enrollment or regeneration | info | `{ user_id, count: 10, trigger: "enrollment"\|"regeneration" }` |
| `mfa.recovery_code_used` | Recovery code accepted | warning | `{ user_id, codes_remaining: N }` |
| `mfa.recovery_code_failed` | Invalid recovery code submitted | warning | `{ user_id }` |

Recovery code usage is `warning` severity — it's inherently unusual and suggests the user has lost access to their primary MFA method.

### Enrollment / Management Events

| Event type | When | Severity | Details |
|-----------|------|----------|---------|
| `mfa.method_enrolled` | Setup confirmed | info | `{ user_id, method }` |
| `mfa.method_removed` | User removes a method | info | `{ user_id, method }` |
| `mfa.all_methods_removed` | Last method removed (MFA disabled) | warning | `{ user_id }` |
| `mfa.enrollment_failed` | Wrong code during setup confirm | warning | `{ user_id, method }` |
| `mfa.disable_blocked` | User tried to remove MFA but mandate prevents it | warning | `{ user_id, reason }` |

### Admin Action Events

| Event type | When | Severity | Details |
|-----------|------|----------|---------|
| `mfa.admin_reset` | Admin resets user's MFA | critical | `{ actor_id, target_user_id, org_id }` |
| `mfa.admin_require_member` | Per-member MFA requirement added | info | `{ actor_id, target_user_id, org_id }` |
| `mfa.admin_unrequire_member` | Per-member MFA requirement removed | info | `{ actor_id, target_user_id, org_id }` |
| `mfa.org_require_all_enabled` | Org-wide MFA requirement enabled | info | `{ actor_id, org_id }` |
| `mfa.org_require_all_disabled` | Org-wide MFA requirement disabled | warning | `{ actor_id, org_id }` |
| `auth.password_reset_forced` | Admin forces password reset | critical | `{ actor_id, target_user_id, org_id }` |
| `auth.password_reset_forced_completed` | User completes forced reset | info | `{ user_id }` |
| `auth.password_reset_sent_by_admin` | Admin triggers reset email | info | `{ actor_id, target_user_id, org_id }` |

### Severity Rationale

- **info** — normal operations, audit trail
- **warning** — unusual or concerning: recovery code usage, disabling MFA protections, failed attempts, rate limits
- **critical** — admin actions that reduce security posture (MFA reset, forced password reset)

### Anti-Enumeration

`mfa.verify_failed` and `mfa.recovery_code_failed` are logged regardless of whether the user exists or has MFA, consistent with the existing anti-enumeration pattern for `auth.login_failed`.

---

## System Logging (slog)

Independent of audit events. Structured slog entries for operational monitoring.

| Level | Event | Purpose |
|-------|-------|---------|
| ERROR | TOTP secret encryption/decryption failure | Key rotation issue or data corruption |
| ERROR | Email OTP delivery failure (SMTP error) | User stuck — can't receive code |
| ERROR | DB transaction failure during MFA operation | User may be in limbo |
| WARN | TOTP time step drift > ±1 detected | Server clock issue — NTP problem |
| WARN | Recovery codes remaining ≤ 2 | Operational signal |
| INFO | MFA verification latency | Performance baseline |
| INFO | Email OTP sent successfully | Delivery confirmation |
| DEBUG | TOTP validation details (time step, window) | Development only |

**Principles:**
- **Never log secrets, codes, or hashes** at any level
- Security events and slog fire independently — a DB failure writing the security event must not block the slog entry
- slog entries include structured fields (`user_id`, `method`, `error`) for log aggregation
- ERROR-level entries should be alertable in production monitoring

---

## TOTP Implementation Details

Per RFC 6238, following industry-standard parameters for universal authenticator compatibility:

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Algorithm | HMAC-SHA-1 | Universal support; MS Authenticator, Duo, Authy silently generate wrong codes with SHA-256 |
| Digits | 6 | Industry standard |
| Period | 30 seconds | Industry standard |
| Secret length | 20 bytes (160 bits) | RFC default, 32-char base32 encoding |
| Time window | ±1 step | Tolerates ~90s clock skew |
| Replay prevention | Track `last_used_step` per credential | Reject reuse within validity window |
| Secret storage | AES-256-GCM encrypted at rest | Uses existing `SSOEncryptionKey` |
| QR URI format | `otpauth://totp/CVErt%20Ops:{email}?secret={base32}&issuer=CVErt%20Ops&algorithm=SHA1&digits=6&period=30` | |
| URI validation | Parse generated URI back, verify secret intact before returning | Prevents encoding bugs |

**Key rotation:** When `SSOEncryptionKey` rotates (dual-key infrastructure), TOTP secrets must be re-encrypted: decrypt with old key, re-encrypt with new key. Low-volume batch operation.

---

## Email OTP Details

| Parameter | Value |
|-----------|-------|
| Code format | 6-digit numeric |
| TTL | 10 minutes (configurable) |
| Rate limit | 5 sends per hour per user |
| Max attempts per challenge | 3 (then challenge invalidated, must resend) |
| Delivery address | `users.email` (verified account email) |
| Single active code | Resend invalidates any outstanding code (DELETE before INSERT) |

---

## Recovery Code Details

| Parameter | Value |
|-----------|-------|
| Count | 10 codes |
| Format | `xxxxx-xxxxx` alphanumeric (a–z, 0–9) |
| Entropy | ~52 bits per code |
| Storage | SHA-256 hash (high-entropy random — argon2 unnecessary) |
| Display | Shown once on enrollment, never retrievable again |
| Regeneration | Full re-auth (current_password) + active MFA enrollment required |
| Brute force protection | Existing account lockout mechanism |

---

## Future Considerations

- **Passkeys (WebAuthn/FIDO2):** Separate design doc. Schema accommodates additional `mfa_credentials.method` values.
- **`require_idp_mfa` org setting:** Reject OIDC logins without `amr` containing `"mfa"`. Requires documenting Entra v2.0 limitation.
- **Device management UI:** `GET /auth/mfa/devices` + `DELETE /auth/mfa/devices/{id}` for self-service device token revocation.
- **TOTP algorithm upgrade:** When SHA-256 authenticator support becomes universal, the `method` CHECK constraint and `otpauth://` URI can be updated. Schema supports it without migration.
- **Entra `acr` integration:** Conditional Access evaluation as an alternative to `amr` for Entra v2.0 tenants.
