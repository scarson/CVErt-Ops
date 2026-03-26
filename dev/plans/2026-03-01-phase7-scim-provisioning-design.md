# Phase 7 — SCIM 2.0 User & Group Provisioning: Design

**Date:** 2026-03-01
**Scope:** SCIM 2.0 service provider for automated user/group provisioning from enterprise IdPs
**PLAN.md refs:** §7.2 (SSO), §6 (RLS/multi-tenancy), §7.3 (RBAC)
**Depends on:** Phase 5D (Generic OIDC — `sso_connections` table, tier gating, audit log)
**Library:** `marcelom97/scimgateway` v1.0.0 (MIT, embeddable `http.Handler`, slog integration)

**For Claude:** CRITICAL NOTE (2026-03-19): This design was never implemented and is maintained for historical reference only. It's superseded by dev\plans\2026-03-19-phase7-scim-provisioning-design-v2.md and dev\plans\2026-03-19-phase7-scim-implementation-plan-v2.md.

## Scope Decisions

| Item | Decision |
|------|----------|
| Library choice | `marcelom97/scimgateway` — most feature-complete Go SCIM library, v1.0 shipped Feb 2026, slog integration matches stack. Switching cost low if maintainer disappears (clean handler boundary). |
| SCIM + invitations | SCIM bypasses invitation system. SCIM-provisioned users are auto-created and added to org directly. Invitations remain for non-SCIM orgs. |
| Deprovisioning | Soft-deactivate: `org_members.deactivated_at` timestamp. User can't access org but data associations preserved. Re-provisioning reactivates. |
| User deactivation scope | General feature, not SCIM-exclusive. Admins can manually deactivate/reactivate via member PATCH. SCIM automates it. |
| Group mapping | Separate `scim_groups` table with optional role mapping (`mapped_role`) and notification group mapping (`mapped_group_id`). IdP group structure preserved independently. |
| Role mapping model | Apply-on-write: role updated on `org_members.role` when SCIM group membership or role mapping changes. Not periodically re-evaluated. |
| Default SCIM role | `viewer` (least privilege). Configurable per org on `scim_configs.default_role`. |
| Owner protection | SCIM cannot set role to `owner`. Cannot deactivate sole active owner (returns SCIM 400 error). |
| SCIM exemption | `org_members.scim_exempt` flag. Exempt users' state is not modified by SCIM. Operations return success silently (prevents IdP retry storms). For break-glass accounts. |
| Notification group sync | Included. `group_members.scim_managed` flag tracks source. SCIM removal only affects SCIM-managed memberships. |
| User identity matching | `externalId` is the durable key (via `user_identities`). Email is a one-time initial matching heuristic only. |
| Tier gating | Enterprise-only (same gate as SSO). |

---

## 1. Schema

### New Tables

```sql
-- SCIM provisioning config, 1:1 with organizations (via sso_connections)
CREATE TABLE IF NOT EXISTS scim_configs (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            UUID NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    sso_connection_id UUID NOT NULL UNIQUE REFERENCES sso_connections(id) ON DELETE CASCADE,
    enabled           BOOLEAN NOT NULL DEFAULT false,
    token_hash        TEXT NOT NULL,          -- sha256 of bearer token
    token_prefix      TEXT NOT NULL,          -- first 8 chars for display/identification
    default_role      TEXT NOT NULL DEFAULT 'viewer'
                      CHECK (default_role IN ('viewer', 'member')),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS scim_configs_token_hash_idx
    ON scim_configs (token_hash);

ALTER TABLE scim_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_configs FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON scim_configs
    USING (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid)
    WITH CHECK (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON scim_configs TO cvert_ops_app;


-- IdP groups with optional role + notification group mappings
CREATE TABLE IF NOT EXISTS scim_groups (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    external_id      TEXT,                   -- IdP's externalId for the group
    display_name     TEXT NOT NULL,
    mapped_role      TEXT CHECK (mapped_role IN ('viewer', 'member', 'admin')),
    mapped_group_id  UUID REFERENCES groups(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, display_name)
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS scim_groups_org_id_idx
    ON scim_groups (org_id);
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS scim_groups_org_external_id_idx
    ON scim_groups (org_id, external_id) WHERE external_id IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS scim_groups_mapped_group_id_idx
    ON scim_groups (mapped_group_id);

ALTER TABLE scim_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_groups FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON scim_groups
    USING (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid)
    WITH CHECK (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON scim_groups TO cvert_ops_app;


-- SCIM group membership (denormalized org_id for RLS)
CREATE TABLE IF NOT EXISTS scim_group_members (
    scim_group_id UUID NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scim_group_id, user_id)
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS scim_group_members_org_id_idx
    ON scim_group_members (org_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS scim_group_members_user_id_idx
    ON scim_group_members (user_id);

ALTER TABLE scim_group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_group_members FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON scim_group_members
    USING (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid)
    WITH CHECK (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid);

GRANT SELECT, INSERT, DELETE ON scim_group_members TO cvert_ops_app;
```

### Existing Table Modifications

```sql
-- org_members: deactivation + SCIM exemption
ALTER TABLE org_members ADD COLUMN deactivated_at TIMESTAMPTZ;
ALTER TABLE org_members ADD COLUMN scim_exempt BOOLEAN NOT NULL DEFAULT false;

-- group_members: SCIM sync source tracking
ALTER TABLE group_members ADD COLUMN scim_managed BOOLEAN NOT NULL DEFAULT false;
```

### Schema Design Notes

- `scim_configs` is 1:1 with `sso_connections` — SCIM requires SSO. Token stored separately from API keys (different auth semantics: no user, no RBAC role, SCIM-specific middleware).
- `scim_groups` references `organizations(id)` directly, NOT `scim_configs(id)`. If SCIM config is deleted (via SSO connection cascade), admin-configured group mappings survive for potential re-setup.
- `org_members.deactivated_at` is a general feature — admin-settable via member PATCH, SCIM-automatable. `RequireOrgRole` middleware checks `deactivated_at IS NULL`.
- `org_members.scim_exempt` prevents SCIM from modifying the user's membership state. Admin-managed only.
- `group_members.scim_managed` tracks whether a notification group membership was created by SCIM sync. SCIM removal only deletes `scim_managed = true` rows; manually-added memberships are preserved.
- `mapped_role` excludes `owner` — owner assignment is always manual.

---

## 2. SCIM Authentication

### Token Lifecycle

1. Org owner creates SCIM config via `POST /api/v1/orgs/{org_id}/sso/scim` (Enterprise-only, tier-gated, requires active SSO connection).
2. Server generates token: `cvert_scim_` prefix + 32 random bytes (hex-encoded). Distinct prefix from API keys (`cvo_`) for human identification in logs and IdP config UIs.
3. `sha256(token)` stored in `scim_configs.token_hash`, first 8 chars in `token_prefix`. Raw token returned once, never stored.
4. Admin enters token + SCIM endpoint URL into IdP provisioning config.

### SCIM Auth Middleware (`requireSCIMAuth`)

Mounted on `/api/v1/orgs/{org_id}/scim/v2/*` only. Separate from `RequireAuthenticated` — SCIM has no human actor, no `ctxUserID`, no RBAC role. Machine-to-machine provisioning channel.

```
1. Extract org_id from URL path
2. Extract Bearer token from Authorization header (401 if missing)
3. Hash token with sha256
4. Lookup scim_configs by token_hash (withBypassTx — pre-context)
5. subtle.ConstantTimeCompare on hash (401 if mismatch)
6. Verify config.org_id == URL org_id (401 — defense-in-depth)
7. Verify config.enabled == true (403 if disabled)
8. Inject org_id and scim_config_id into request context (downstream handlers need config_id for identity provider string 'scim:{config_id}' and audit logging)
```

### Rate Limiting

Separate SCIM rate limiter: 50 req/sec per org. Not shared with per-org API rate limiter (which is 1-17 req/sec depending on tier — below Entra ID's 25 req/sec gallery minimum).

### Token Rotation

`POST /api/v1/orgs/{org_id}/sso/scim/rotate-token` — overwrites `token_hash` immediately. Single active token, no grace period. IdP retries on 401; admin updates IdP config.

### Audit Logging

SCIM operations: `actor_id = NULL`, `actor_email = NULL` (system action). SCIM context in `metadata` JSONB: `{"source": "scim", "scim_config_id": "<uuid>"}`.

For exempt user suppression: `metadata` includes `{"source": "scim", "suppressed": true, "reason": "scim_exempt"}`.

### Lifecycle Edge Cases

- **SCIM disabled** (`enabled = false`): 403 on all SCIM endpoints. Users keep current roles/state. Re-enable restores sync with same token.
- **SSO connection deleted**: `scim_configs` cascade-deletes (token invalidated). `scim_groups` survive (reference org directly). Users keep current roles. Group mappings preserved.
- **SCIM re-enabled after disable**: Same token works. IdP resumes sync on next cycle (~40 min).

---

## 3. SCIM Operations Mapping

### 3.1 Supported SCIM Attributes

Our Schema endpoint declares exactly what we support. IdPs only send attributes listed in our schema — omitting attributes prevents "IdP sends, we discard, IdP resends" loops.

**User:**

| SCIM Attribute | Maps to | Mutability | Notes |
|---|---|---|---|
| `id` | `users.id` (UUID) | read-only | Server-assigned |
| `externalId` | `user_identities.provider_user_id` | read-write | IdP's stable identifier — durable key |
| `userName` | `users.email` | read-write | Must be valid email, globally unique |
| `displayName` | `users.display_name` | read-write | |
| `active` | `org_members.deactivated_at IS NULL` | read-write | |
| `meta` | computed | read-only | resourceType, created, lastModified, location |

Not advertised (IdPs won't send): `name.givenName`, `name.familyName`, `emails[]`, `phoneNumbers[]`, Enterprise User extension.

**Group:**

| SCIM Attribute | Maps to | Mutability |
|---|---|---|
| `id` | `scim_groups.id` (UUID) | read-only |
| `externalId` | `scim_groups.external_id` | read-write |
| `displayName` | `scim_groups.display_name` | read-write |
| `members` | `scim_group_members` | read-write |
| `meta` | computed | read-only |

### 3.2 Identity Matching

Two distinct concerns:

**Ongoing identity (all operations after initial provisioning):** `user_identities(provider='scim:{config_id}', provider_user_id=externalId)`. The `externalId` is the IdP's stable identifier (ObjectID, UPN, SID, employee number — whatever the IdP sends). Once linked, email is just a mutable attribute.

**Initial matching (first SCIM sync for a user who may already have a CVErt Ops account):** Email is a one-time heuristic. See POST /Users flow below — email lookup only happens when no SCIM identity link exists yet.

**Email change:** Arrives as PATCH to `userName`. User found by `externalId` (via `user_identities`), not by email. `users.email` updated. Identity link unaffected.

**Email recycling (employee leaves, new hire gets same email):** Old user deactivated via SCIM DELETE. New user POST has different `externalId` → no identity match → falls through to email lookup → email conflict with deactivated user → 409. Admin resolves by updating old user's email or removing them.

### 3.3 User Operations

**`POST /Users` — Provision**

```
Input: externalId, userName (email), displayName, active

1. Check user_identities for provider='scim:{config_id}', provider_user_id=externalId
   → If found AND org member is active:
       return existing user (200). Idempotent — initial sync hits this.
   → If found AND org member is deactivated:
       if scim_exempt → return existing (200), log suppression
       reactivate membership (clear deactivated_at), return user (200)
   → If not found, continue to step 2.

2. Lookup users by email:
   → If found AND already active member of this org:
       link SCIM identity (withBypassTx: create user_identities record), return user (200)
   → If found AND deactivated member:
       if scim_exempt → return existing (200), log suppression
       withBypassTx: link SCIM identity; withOrgTx: reactivate membership (clear deactivated_at), return user (200)
   → If found but NOT a member of this org:
       check tier member limit (count active members only)
       withBypassTx: link SCIM identity; withOrgTx: create org_members (role = default_role), return user (201)
   → If not found, continue to step 3.

3. Create new user:
   check tier member limit (count active members only)
   Tx 1 (withBypassTx): create users record + user_identities record
   Tx 2 (withOrgTx): create org_members (role = default_role)
   Return user (201)
```

Transaction note: steps 2 and 3 split writes across two transactions because `users` and `user_identities` are global tables (no RLS) while `org_members` is org-scoped. If the org-scoped transaction fails after the bypass transaction, we have an orphaned user/identity record — harmless (no org access), consistent with existing registration flow.

**`GET /Users/{id}` — Read**

```
1. Lookup org_members by user_id = {id} (withOrgTx, RLS-scoped)
2. Join users + user_identities (provider = 'scim:{config_id}')
3. Return SCIM User (including deactivated — active attribute shows state)
4. Not found → 404
```

**`GET /Users` — List with filtering**

```
1. List org_members for org (withOrgTx), including deactivated
2. Apply SCIM filters — supported operators: eq, and
   Supported filter attributes:
     userName eq "email"    → WHERE users.email = $1
     externalId eq "ext"    → WHERE user_identities.provider_user_id = $1
     id eq "uuid"           → WHERE org_members.user_id = $1
     active eq true/false   → WHERE deactivated_at IS [NOT] NULL
   Unsupported operator → 400: scimType "invalidFilter"
3. Index-based pagination (SQL OFFSET/LIMIT from startIndex + count)
4. Return SCIM ListResponse {totalResults, itemsPerPage, startIndex, Resources[]}
```

Index-based pagination is required by SCIM spec. Org member counts are typically < 10K; OFFSET/LIMIT is acceptable.

**`PUT /Users/{id}` — Replace**

PUT is a full resource replacement per SCIM spec. Omitted mutable attributes are reset to defaults. This is Okta's primary update path (Okta uses PUT for attribute updates, PATCH only for activation/deactivation).

```
1. Lookup org_members by user_id (withOrgTx)
2. Not found → 404
3. If scim_exempt → return current state (200), log suppression
4. Update users:
   - email: use provided userName (409 if uniqueness conflict)
   - display_name: use provided displayName, or fall back to userName (email) if omitted
5. Update user_identities: externalId if changed (uniqueness check → 409 if already linked to different user)
6. Update org_members: deactivated_at based on active flag
   → If deactivating: check sole-owner protection → 400 if sole active owner
7. Return updated SCIM User (200)
```

**Omitted attribute defaults:** `displayName` falls back to `userName` (email) if not provided — a human-readable default that avoids blank display names in the UI. `externalId` is preserved if omitted (not nulled — it's our identity link). `active` defaults to `true` if omitted.

**`PATCH /Users/{id}` — Partial update**

```
1. Lookup org_members by user_id (withOrgTx)
2. Not found → 404
3. If scim_exempt → return current state (200), log suppression
4. For each operation in Operations[] (single transaction — atomic):
   op: case-insensitive (accept "Replace", "replace", etc.)
   value: coerce string booleans ("False" → false, "True" → true)

   Attribute mapping:
     "active"      → org_members.deactivated_at
                     if deactivating: sole-owner check → 400
     "userName"    → users.email (uniqueness check → 409)
     "displayName" → users.display_name
     "externalId"  → user_identities.provider_user_id (uniqueness check → 409 if already linked to different user)

5. Return updated SCIM User (200)
```

**`DELETE /Users/{id}` — Deprovision**

```
1. Lookup org_members by user_id (withOrgTx)
2. Not found → 204 (idempotent)
3. If scim_exempt → 204, log suppression
4. Sole-owner check → 400 if sole active owner
5. Set deactivated_at = now()
6. Return 204
```

User record, user_identities, and org_members preserved. Re-provisioning via POST reactivates.

### 3.4 Group Operations

**`POST /Groups` — Create**

```
1. Create scim_groups record (org_id, display_name, external_id)
2. If members[] provided:
   For each member:
     INSERT scim_group_members
     If user is NOT scim_exempt AND group has mapped_role:
       recompute effective role (§3.6)
     If group has mapped_group_id:
       sync to notification group (§3.7)
3. Return SCIM Group (201)
```

**`GET /Groups/{id}` — Read**

```
1. Lookup scim_groups by id (withOrgTx)
2. Load scim_group_members with user references
3. Map to SCIM Group schema
4. Not found → 404
```

**`GET /Groups` — List with filtering**

```
Supported filters: displayName eq, externalId eq, id eq
Unsupported → 400: scimType "invalidFilter"
Index-based pagination.
```

**`PATCH /Groups/{id}` — Partial update**

```
1. Lookup scim_groups by id (withOrgTx)
2. Not found → 404
3. For each operation (single transaction — atomic):

   op: "add", path: "members", value: [{value: "user-uuid"}, ...]
     → INSERT scim_group_members for each
     → For non-exempt users: recompute role (§3.6), sync notification group (§3.7)

   op: "remove", path: "members[value eq \"user-uuid\"]"
     — also accept: op: "remove", path: "members", value: [{value: "user-uuid"}]
       (Entra ID sends value array instead of path filter — see §4.2)
     → DELETE FROM scim_group_members
     → For non-exempt users: recompute role (§3.6), unsync notification group (§3.7)

   op: "replace", path: "displayName", value: "new name"
     → UPDATE scim_groups.display_name

4. Return updated SCIM Group (200)
```

**`PUT /Groups/{id}` — Replace**

```
1. Lookup scim_groups by id (withOrgTx)
2. Not found → 404
3. Update display_name, external_id
4. Diff current members vs new members:
   Added → INSERT scim_group_members, recompute roles, sync notification group
   Removed → DELETE scim_group_members, recompute roles, unsync notification group
5. Return updated SCIM Group (200)
```

**`DELETE /Groups/{id}` — Remove**

```
1. Lookup scim_groups by id (withOrgTx)
2. Not found → 204 (idempotent)
3. Collect affected non-exempt users
4. DELETE scim_groups (CASCADE deletes scim_group_members)
5. Recompute effective role for affected non-exempt users
6. Do NOT remove users from mapped notification group (too aggressive — could cause
   missed notifications; admin cleans up manually or remaps a new SCIM group)
7. Return 204
```

### 3.5 Discovery Endpoints (static)

**`GET /ServiceProviderConfig`:**

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
  "patch": {"supported": true},
  "bulk": {"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
  "filter": {"supported": true, "maxResults": 200},
  "changePassword": {"supported": false},
  "sort": {"supported": false},
  "etag": {"supported": false},
  "authenticationSchemes": [{
    "type": "oauthbearertoken",
    "name": "Bearer Token",
    "description": "Authentication via org-scoped SCIM bearer token"
  }]
}
```

**`GET /Schemas`** — User and Group schema definitions listing only attributes from §3.1.

**`GET /ResourceTypes`** — Metadata for User and Group resources with schema refs and endpoint paths.

### 3.6 Role Recomputation

Called whenever SCIM group membership changes for a non-exempt user, or when a group's `mapped_role` is changed via the admin mapping endpoint (recompute for all current non-exempt members of that group):

```
1. If current org_members.role == 'owner' → skip (owner is always manual)
2. Load all scim_groups the user belongs to (via scim_group_members)
3. Collect non-null mapped_role values
4. Effective role = max(mapped_roles) or scim_configs.default_role if empty
5. Role hierarchy: admin > member > viewer
6. If computed role != current org_members.role → UPDATE org_members
```

Owner guard (step 1) prevents SCIM from downgrading a manually-assigned owner to admin/member/viewer. Owner assignment and removal are always manual operations.

### 3.7 Notification Group Sync

When a SCIM group has a non-null `mapped_group_id`, membership changes propagate to the notification `groups`/`group_members` table. Also triggered when a group's `mapped_group_id` is changed via the admin mapping endpoint — all current members are synced to the new notification group (and scim_managed memberships in the old notification group are cleaned up per the removal rules below).

**Source tracking:** `group_members.scim_managed BOOLEAN NOT NULL DEFAULT false` tracks whether a notification group membership was created by SCIM sync.

**Sync rules:**

| Event | Action |
|-------|--------|
| SCIM adds user to group with `mapped_group_id` | If user not in notification group: INSERT `group_members` with `scim_managed = true`. If already a member with `scim_managed = false`: no-op (manual membership takes precedence). |
| SCIM removes user from group | If `scim_managed = true` AND no other SCIM group with same `mapped_group_id` includes user: DELETE from notification group. If `scim_managed = false`: no-op (admin owns it). |
| Admin manually adds user to notification group | INSERT with `scim_managed = false`. If already exists from SCIM: no change to flag. |
| Admin manually removes user from notification group | DELETE regardless of `scim_managed` (admin override). |
| SCIM group deleted | Do NOT remove users from mapped notification group. |

**Multi-mapping edge case:** Two SCIM groups may map to the same notification group. Before removing a SCIM-managed membership, check if any other SCIM group with the same `mapped_group_id` still includes the user:

```sql
SELECT COUNT(*) FROM scim_group_members sgm
  JOIN scim_groups sg ON sgm.scim_group_id = sg.id
  WHERE sgm.user_id = $1
    AND sg.mapped_group_id = $2
    AND sg.id != $3
```

If count > 0, keep the notification group membership.

**Why no removal on SCIM group delete:** Deleting a SCIM group is often an IdP restructuring event, not a "revoke access" intent. Removing notification group membership could cause missed vulnerability alerts. Admin can clean up manually.

---

## 4. Microsoft Entra ID Compatibility

### 4.1 SCIM Error Response Format

All SCIM endpoints return errors using RFC 7644 §3.12 format, NOT our normal RFC 9457 Problem Details. The scimgateway library handles the response envelope; our handler code returns appropriate status codes and detail messages.

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "409",
  "scimType": "uniqueness",
  "detail": "userName already exists in this organization"
}
```

**Error mapping:**

| Condition | HTTP Status | scimType | Detail |
|-----------|------------|----------|--------|
| Email uniqueness violation | 409 | `uniqueness` | userName already exists |
| externalId collision | 409 | `uniqueness` | externalId already linked to different user |
| Unsupported filter operator | 400 | `invalidFilter` | Unsupported operator: {op} |
| Missing required attribute | 400 | `invalidValue` | {attribute} is required |
| Sole-owner protection | 400 | `invalidValue` | Cannot deactivate the sole owner of this organization |
| Tier member limit exceeded | 403 | — | Organization member limit reached |
| Invalid PATCH path | 400 | `invalidPath` | Unrecognized attribute path: {path} |
| SCIM config disabled | 403 | — | SCIM provisioning is disabled for this organization |
| Auth failure | 401 | — | Invalid or missing bearer token |

### 4.2 IdP Behavioral Differences

| Aspect | Microsoft Entra ID | Okta |
|--------|-------------------|------|
| **PATCH op casing** | Capitalized: `"Replace"`, `"Add"`, `"Remove"` | Lowercase: `"replace"`, `"add"`, `"remove"` (spec-compliant) |
| **Boolean values** | String: `"False"`, `"True"` | JSON boolean: `false`, `true` (spec-compliant) |
| **User deactivation** | DELETE or PATCH `active=false` | PATCH `active=false` only — Okta **never** sends DELETE |
| **User attribute updates** | Primarily PATCH | Primarily PUT (PATCH only for active/password) |
| **Filter operators** | `eq`, `and` | `eq` primarily; `sw` for user import searches |
| **Test connection** | `GET /Users?filter=id eq "{random-guid}"` → expects 200 with empty list | `GET /Users?startIndex=1&count=1` → expects 200 with pagination envelope |
| **Group member removal** | Multiple formats (value array OR path filter expression) | Standard path filter format |
| **Sync cycle** | ~40-minute incremental sync | Event-driven (near-real-time for user changes) |
| **Multi-attribute PATCH** | Separate operation per attribute | N/A (uses PUT for multi-attribute updates) |

**Our handling:** Case-insensitive op comparison. Boolean coercion from strings. Both DELETE and PATCH `active=false` produce the same outcome (soft-deactivate). PUT handler is a full implementation, not a PATCH wrapper — critical for Okta compatibility.

### 4.3 Filter Operator Support

| Operator | Required by | SQL mapping | Notes |
|----------|------------|-------------|-------|
| `eq` | Both | `WHERE col = $1` | Core — every provisioning operation uses this |
| `and` | Both | `AND` | Compound queries |
| `sw` | Okta (import) | `WHERE col LIKE $1 \|\| '%'` | Deferred from MVP (§8). Documented here for reference. Uses BTREE index. Okta can fall back to `eq`, but supporting `sw` avoids user import edge cases. |

Unsupported operators (`ne`, `co`, `ew`, `gt`, `ge`, `lt`, `le`, `or`, `not`, `pr`) return 400 with `scimType: "invalidFilter"`. None are required by Entra ID or Okta for provisioning workflows.

### 4.4 Test Connection Behavior

Both IdPs validate connectivity before enabling provisioning:

- **Entra ID:** `GET /Users?filter=id eq "{random-guid}"` — must return 200 with `{"totalResults": 0, "Resources": []}`. Returning 404 fails the test.
- **Okta:** `GET /Users?startIndex=1&count=1` — must return 200 with pagination envelope. An empty org returns `{"totalResults": 0, "Resources": []}`.

Both patterns work against our GET /Users implementation with no special-casing.

### 4.5 Data Fidelity

Values stored as received. No normalization:
- Email casing preserved (no `strings.ToLower`)
- displayName whitespace preserved
- externalId is opaque — could be a GUID, UPN, SID, employee number

### 4.6 Performance

| Context | Requirement | Our limit |
|---------|------------|-----------|
| Entra ID gallery app | 25 req/sec minimum | 50 req/sec |
| Entra ID custom enterprise app | No published minimum | 50 req/sec |
| Okta (any) | No published minimum | 50 req/sec |

The 25 req/sec requirement only applies to Entra ID gallery-listed apps. Self-hosted CVErt Ops deployments configure SCIM as a custom enterprise app. Our 50 req/sec limit provides headroom for both.

### 4.7 Customer Configuration Guidance

**Entra ID:** Recommend customers append `?aadOptscim062020` to the SCIM endpoint URL in their tenant config. This enables more spec-compliant behavior (lowercase ops, proper booleans, standard group member removal format). Our implementation handles both modes, but the flag reduces quirk surface.

**Okta:** Ensure SCIM 2.0 (not 1.1) is selected during integration setup. Use "HTTP Header" authentication type and enter the SCIM bearer token.

**Both:** The SCIM endpoint URL is `https://{host}/api/v1/orgs/{org_id}/scim/v2`. The `org_id` UUID is visible in org settings.

---

## 5. API Endpoints

### SCIM Endpoints (mounted under org path, SCIM auth middleware)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/orgs/{org_id}/scim/v2/Users` | GET | List/filter users |
| `/api/v1/orgs/{org_id}/scim/v2/Users` | POST | Provision user |
| `/api/v1/orgs/{org_id}/scim/v2/Users/{id}` | GET | Get user |
| `/api/v1/orgs/{org_id}/scim/v2/Users/{id}` | PUT | Replace user |
| `/api/v1/orgs/{org_id}/scim/v2/Users/{id}` | PATCH | Partial update user |
| `/api/v1/orgs/{org_id}/scim/v2/Users/{id}` | DELETE | Deprovision user |
| `/api/v1/orgs/{org_id}/scim/v2/Groups` | GET | List/filter groups |
| `/api/v1/orgs/{org_id}/scim/v2/Groups` | POST | Create group |
| `/api/v1/orgs/{org_id}/scim/v2/Groups/{id}` | GET | Get group |
| `/api/v1/orgs/{org_id}/scim/v2/Groups/{id}` | PUT | Replace group |
| `/api/v1/orgs/{org_id}/scim/v2/Groups/{id}` | PATCH | Update group |
| `/api/v1/orgs/{org_id}/scim/v2/Groups/{id}` | DELETE | Delete group |
| `/api/v1/orgs/{org_id}/scim/v2/ServiceProviderConfig` | GET | Capabilities |
| `/api/v1/orgs/{org_id}/scim/v2/Schemas` | GET | Schema definitions |
| `/api/v1/orgs/{org_id}/scim/v2/ResourceTypes` | GET | Resource metadata |

All SCIM endpoints require `requireSCIMAuth` middleware. Response `Content-Type: application/scim+json`. Input accepts both `application/scim+json` and `application/json` (Entra ID sends the latter).

**Routing boundary:** SCIM endpoints are mounted as a raw `http.Handler` via scimgateway — they live outside huma's OpenAPI spec generation. SCIM discovery (ServiceProviderConfig, Schemas, ResourceTypes) serves that role instead. Admin management endpoints below go through huma normally.

**Middleware error format:** `requireSCIMAuth` generates 401/403 responses before scimgateway runs. These must use SCIM error format (RFC 7644 §3.12), not huma's RFC 9457 Problem Details. The middleware is responsible for formatting its own error responses with `Content-Type: application/scim+json`.

### Admin SCIM Management Endpoints (standard auth + RBAC)

| Endpoint | Method | RBAC | Description |
|----------|--------|------|-------------|
| `/api/v1/orgs/{org_id}/sso/scim` | POST | owner | Create SCIM config (returns token once). Requires active SSO connection (400 if none). 409 if config already exists. |
| `/api/v1/orgs/{org_id}/sso/scim` | GET | admin+ | Get SCIM config (token masked) |
| `/api/v1/orgs/{org_id}/sso/scim` | PATCH | owner | Update SCIM config (enable/disable, default_role) |
| `/api/v1/orgs/{org_id}/sso/scim` | DELETE | owner | Delete SCIM config. SCIM groups and memberships survive (§2 lifecycle). 204. |
| `/api/v1/orgs/{org_id}/sso/scim/rotate-token` | POST | owner | Rotate SCIM token |
| `/api/v1/orgs/{org_id}/sso/scim/groups` | GET | admin+ | List SCIM groups with current mappings |
| `/api/v1/orgs/{org_id}/sso/scim/groups/{id}/mapping` | PATCH | admin+ | Set mapped_role and/or mapped_group_id. App-layer validation: `mapped_group_id` must belong to same org (FK bypasses RLS). |

All admin endpoints are Enterprise-only (tier-gated). SCIM config read and group listing are admin+ — admins managing group mappings need visibility into SCIM status. Config creation, mutation, deletion, and token rotation are owner-only (security-critical).

**Admin endpoint response schemas:**

- `POST /sso/scim` → `{id, org_id, enabled, default_role, token_prefix, token, created_at}` — `token` returned in cleartext this one time only, never stored or retrievable again. 201.
- `GET /sso/scim` → `{id, org_id, enabled, default_role, token_prefix, created_at, updated_at}` — no `token` field.
- `PATCH /sso/scim` → returns updated config (same shape as GET). 200.
- `DELETE /sso/scim` → 204, no body. Idempotent (204 even if config doesn't exist).
- `POST /sso/scim/rotate-token` → `{token, token_prefix}` — new token in cleartext, same one-time-show pattern as POST creation. 200.
- `GET /sso/scim/groups` → `{items: [{id, external_id, display_name, mapped_role, mapped_group_id, member_count, created_at}]}` — includes resolved member count for admin context.
- `PATCH /sso/scim/groups/{id}/mapping` → returns updated SCIM group (same shape as GET groups item). 200.

### Existing Endpoint Modifications

| Endpoint | Change |
|----------|--------|
| `PATCH /api/v1/orgs/{org_id}/members/{user_id}` | Add `active` (bool) and `scim_exempt` (bool) as patchable fields. `active` sets/clears `deactivated_at`. Both require admin+ role. |
| `GET /api/v1/orgs/{org_id}/members` | Response includes `active` (bool), `deactivated_at` (nullable), `scim_exempt` (bool) fields. |
| `RequireOrgRole` middleware | Add `deactivated_at IS NULL` check. Deactivated members get 403 with detail: "Your membership in this organization has been deactivated." |

**Manual deactivation vs. SCIM reactivation:** If an admin deactivates a SCIM-provisioned user via the member PATCH without also setting `scim_exempt=true`, the next IdP sync will reactivate them (POST /Users is idempotent and clears `deactivated_at`). This is correct — SCIM is the source of truth for provisioning state. Admins who need manual override must set `scim_exempt=true`.

---

## 6. Structured Logging (slog)

**SCIM protocol operations:**

| Level | Event | Fields |
|-------|-------|--------|
| `Info` | SCIM user provisioned | `org_id`, `user_id`, `external_id`, `method` (created/linked/reactivated) |
| `Info` | SCIM user deactivated | `org_id`, `user_id`, `external_id`, `source` (patch/put) |
| `Info` | SCIM user reactivated | `org_id`, `user_id`, `external_id`, `source` (patch/put) |
| `Info` | SCIM user attributes updated | `org_id`, `user_id`, `external_id`, `source` (patch/put), `changed_fields` (email/display_name/external_id) |
| `Info` | SCIM user deprovisioned | `org_id`, `user_id`, `external_id` |
| `Info` | SCIM group created | `org_id`, `scim_group_id`, `display_name` |
| `Info` | SCIM group deleted | `org_id`, `scim_group_id`, `display_name`, `affected_user_count` |
| `Info` | SCIM group membership changed | `org_id`, `scim_group_id`, `user_id`, `action` (add/remove) |
| `Info` | Role recomputed from SCIM groups | `org_id`, `user_id`, `old_role`, `new_role` |
| `Info` | Notification group membership synced | `org_id`, `user_id`, `group_id`, `action` (add/remove), `scim_group_id` |
| `Warn` | SCIM operation suppressed (exempt user) | `org_id`, `user_id`, `operation`, `scim_config_id` |
| `Warn` | SCIM sole-owner protection triggered | `org_id`, `user_id`, `operation` |
| `Warn` | SCIM auth failed | `org_id`, `reason` (invalid_token/disabled/org_mismatch) |
| `Debug` | SCIM request received | `org_id`, `method`, `path`, `scim_config_id` |

**Admin management actions:**

| Level | Event | Fields |
|-------|-------|--------|
| `Info` | SCIM config created | `org_id`, `scim_config_id`, `actor_id` |
| `Info` | SCIM config enabled/disabled | `org_id`, `scim_config_id`, `enabled`, `actor_id` |
| `Info` | SCIM config updated | `org_id`, `scim_config_id`, `changes`, `actor_id` |
| `Info` | SCIM config deleted | `org_id`, `scim_config_id`, `actor_id` |
| `Info` | SCIM token rotated | `org_id`, `scim_config_id`, `actor_id` |
| `Info` | SCIM group mapping updated | `org_id`, `scim_group_id`, `mapped_role`, `mapped_group_id`, `actor_id` |

**Audit log:** Both categories generate audit log entries. SCIM protocol operations use `actor_id = NULL` with `metadata: {"source": "scim", "scim_config_id": "<uuid>"}` (system action, per §2). Admin management actions use the authenticated user's `actor_id` and standard audit log context (no `metadata.source: "scim"`).

---

## 7. Test Coverage Plan

### SCIM Auth

| Test | Validates |
|------|-----------|
| `TestSCIMAuth_ValidToken` | Bearer token accepted, org context set |
| `TestSCIMAuth_InvalidToken` | Wrong token → 401 |
| `TestSCIMAuth_OrgMismatch` | Token for org A used on org B endpoint → 401 |
| `TestSCIMAuth_Disabled` | Disabled config → 403 |
| `TestSCIMAuth_MissingHeader` | No Authorization header → 401 |
| `TestSCIMAuth_ConstantTimeCompare` | Timing-safe comparison (verified by code review) |
| `TestSCIMAuth_RateLimit` | SCIM rate limit independent of org API rate limit |
| `TestSCIMAuth_TokenRotation` | Old token rejected after rotation |
| `TestSCIMAuth_ErrorFormat` | Auth failures return SCIM error JSON (RFC 7644 §3.12), not RFC 9457 |

### User Provisioning

| Test | Validates |
|------|-----------|
| `TestSCIMCreateUser_NewUser` | Creates user + identity + membership, returns 201 |
| `TestSCIMCreateUser_ExistingByExternalId_Active` | Returns existing, 200 (idempotent) |
| `TestSCIMCreateUser_ExistingByExternalId_Deactivated` | Reactivates, returns 200 |
| `TestSCIMCreateUser_ExistingByEmail_OrgMember` | Links SCIM identity, returns 200 |
| `TestSCIMCreateUser_ExistingByEmail_NotMember` | Links identity + creates membership, 201 |
| `TestSCIMCreateUser_ExistingByEmail_Deactivated` | Reactivates + links identity, 200 |
| `TestSCIMCreateUser_EmailConflict` | Email in use by different user → 409 |
| `TestSCIMCreateUser_ExternalIdConflict` | externalId linked to different user → 409 |
| `TestSCIMCreateUser_TierMemberLimit` | Exceeds limit → 403 |
| `TestSCIMCreateUser_SCIMExempt_Deactivated` | Exempt user not reactivated, 200 returned |
| `TestSCIMCreateUser_DefaultRole` | New user gets scim_configs.default_role |

### User Read/List

| Test | Validates |
|------|-----------|
| `TestSCIMGetUser_Found` | Returns SCIM User with correct attributes |
| `TestSCIMGetUser_Deactivated` | Returns user with active=false |
| `TestSCIMGetUser_NotFound` | 404 |
| `TestSCIMGetUser_CrossOrg` | Cannot read user from different org |
| `TestSCIMListUsers_All` | Returns all members including deactivated |
| `TestSCIMListUsers_FilterByUserName` | eq filter on email |
| `TestSCIMListUsers_FilterByExternalId` | eq filter on externalId |
| `TestSCIMListUsers_FilterById` | eq filter on id (Entra ID test connection) |
| `TestSCIMListUsers_FilterByActive` | eq filter on active |
| `TestSCIMListUsers_FilterAnd` | Compound filter (userName eq X and active eq true) |
| `TestSCIMListUsers_UnsupportedFilter` | Unsupported operator → 400 invalidFilter |
| `TestSCIMListUsers_Pagination` | startIndex + count produce correct pages |
| `TestSCIMListUsers_EmptyResult` | 200 with empty Resources[] (not 404) |

### User Update

| Test | Validates |
|------|-----------|
| `TestSCIMReplaceUser_Success` | PUT updates all attributes |
| `TestSCIMReplaceUser_EmailConflict` | New email already exists → 409 |
| `TestSCIMReplaceUser_SCIMExempt` | Returns current state, no modification |
| `TestSCIMReplaceUser_Deactivate` | active=false sets deactivated_at |
| `TestSCIMReplaceUser_SoleOwner` | Deactivate sole owner → 400 |
| `TestSCIMReplaceUser_NotFound` | 404 |
| `TestSCIMReplaceUser_Reactivate` | active=true clears deactivated_at |
| `TestSCIMReplaceUser_OmittedDisplayName` | Falls back to userName (email) per §3.3 defaults |
| `TestSCIMPatchUser_ReplaceActive` | PATCH active=false deactivates |
| `TestSCIMPatchUser_CaseInsensitiveOp` | "Replace" and "replace" both work |
| `TestSCIMPatchUser_StringBoolean` | "False" coerced to false |
| `TestSCIMPatchUser_MultipleOps` | Multiple ops in single PATCH, atomic |
| `TestSCIMPatchUser_SCIMExempt` | Returns current state, no modification |
| `TestSCIMPatchUser_SoleOwner` | Cannot deactivate sole owner |
| `TestSCIMPatchUser_InvalidPath` | Unrecognized attribute path → 400 invalidPath |
| `TestSCIMUpdateUser_AttributeChangeLogged` | PUT/PATCH attribute changes (email, displayName) produce Info-level "SCIM user attributes updated" log with changed_fields |

### User Deprovision

| Test | Validates |
|------|-----------|
| `TestSCIMDeleteUser_Success` | Sets deactivated_at, returns 204 |
| `TestSCIMDeleteUser_AlreadyDeactivated` | Idempotent, returns 204 |
| `TestSCIMDeleteUser_NotFound` | Returns 204 (idempotent) |
| `TestSCIMDeleteUser_SCIMExempt` | Returns 204, no modification |
| `TestSCIMDeleteUser_SoleOwner` | Cannot deactivate sole owner → 400 |
| `TestSCIMDeleteUser_PreservesData` | User record, identity, membership row still exist |

### Group Operations

| Test | Validates |
|------|-----------|
| `TestSCIMCreateGroup_Basic` | Creates group, returns 201 |
| `TestSCIMCreateGroup_WithMembers` | Creates group + memberships, roles recomputed |
| `TestSCIMGetGroup_WithMembers` | Returns group with member list |
| `TestSCIMListGroups_FilterByDisplayName` | eq filter works |
| `TestSCIMPatchGroup_AddMembers` | Adds members, recomputes roles |
| `TestSCIMPatchGroup_RemoveMembers` | Removes members, recomputes roles |
| `TestSCIMPatchGroup_UpdateDisplayName` | Updates name |
| `TestSCIMReplaceGroup_MemberDiff` | Correctly diffs and syncs membership |
| `TestSCIMDeleteGroup_CascadesMembers` | scim_group_members deleted |
| `TestSCIMDeleteGroup_RecomputesRoles` | Affected users' roles recomputed |
| `TestSCIMPatchGroup_EntraIdMemberRemoveFormat` | Value array format for member removal (Entra ID quirk) |
| `TestSCIMDeleteGroup_Idempotent` | Already-deleted group returns 204 |

### Role Recomputation

| Test | Validates |
|------|-----------|
| `TestRoleRecompute_SingleGroup` | User gets mapped_role |
| `TestRoleRecompute_MultipleGroups_HighestWins` | admin > member > viewer |
| `TestRoleRecompute_NoMappedGroups` | Falls back to default_role |
| `TestRoleRecompute_NeverSetsOwner` | Owner role never assigned by SCIM |
| `TestRoleRecompute_SCIMExempt_Skipped` | Exempt user's role unchanged |
| `TestRoleRecompute_RemovedFromAllGroups` | Falls back to default_role |
| `TestRoleRecompute_OwnerNotDowngraded` | Existing owner role preserved through recomputation |
| `TestRoleRecompute_MappingChange_ImmediateEffect` | Admin changes mapped_role → existing members' roles recomputed immediately |

### Notification Group Sync

| Test | Validates |
|------|-----------|
| `TestNotifSync_Add_NewMember` | Inserts with scim_managed=true |
| `TestNotifSync_Add_AlreadyManualMember` | No change (manual takes precedence) |
| `TestNotifSync_Remove_SCIMManaged` | Deletes scim_managed=true row |
| `TestNotifSync_Remove_ManualMember` | No-op (admin owns it) |
| `TestNotifSync_Remove_MultiMapping` | Keeps membership if other SCIM group maps same |
| `TestNotifSync_AdminRemove_OverridesSCIM` | Admin delete removes regardless of scim_managed |
| `TestNotifSync_GroupDelete_NoRemoval` | SCIM group delete does not remove notification members |
| `TestNotifSync_ExemptUser_Skipped` | Exempt user not synced |
| `TestNotifSync_MappingChange_ImmediateSync` | Admin sets mapped_group_id → existing members synced immediately |
| `TestNotifSync_MappingChanged_OldGroupCleanedUp` | mapped_group_id changed → scim_managed members removed from old group, added to new |

### SCIM Config Management

| Test | Validates |
|------|-----------|
| `TestSCIMConfig_Create` | Owner creates, token returned once |
| `TestSCIMConfig_Create_RequiresSSO` | Fails without sso_connection |
| `TestSCIMConfig_Create_EnterprisOnly` | Non-Enterprise → 403 |
| `TestSCIMConfig_Get_TokenMasked` | Token not in GET response |
| `TestSCIMConfig_Enable_Disable` | PATCH enabled flag works |
| `TestSCIMConfig_Delete` | Removes config, SCIM auth fails |
| `TestSCIMConfig_Delete_GroupsSurvive` | scim_groups not cascade-deleted |
| `TestSCIMConfig_RotateToken` | New token works, old rejected |
| `TestSCIMConfig_RBAC` | Non-owner → 403 for mutation; admin can GET |
| `TestSCIMConfig_Create_Duplicate` | Second POST → 409 |
| `TestSCIMConfig_Delete_Idempotent` | DELETE when no config → 204 |

### Group Mapping Admin

| Test | Validates |
|------|-----------|
| `TestGroupMapping_SetRole` | mapped_role applied immediately to existing group members |
| `TestGroupMapping_SetNotificationGroup` | mapped_group_id triggers immediate sync for existing members |
| `TestGroupMapping_ClearMapping` | Null mapped_role stops role influence, roles recomputed to default |
| `TestGroupMapping_AdminRBAC` | Requires admin+ |
| `TestGroupMapping_CrossOrgGroupId` | mapped_group_id from different org → 400/404 |
| `TestGroupMapping_ListGroups` | GET /sso/scim/groups returns groups with mappings and member counts |

### Deactivation (General Feature)

| Test | Validates |
|------|-----------|
| `TestDeactivate_AdminManual` | PATCH active=false via member endpoint |
| `TestDeactivate_Reactivate` | PATCH active=true clears deactivated_at |
| `TestDeactivate_BlocksAccess` | Deactivated member gets 403 on org endpoints |
| `TestDeactivate_SoleOwnerProtection` | Cannot deactivate sole active owner |
| `TestDeactivate_SCIMExempt_ManualStillWorks` | Admin can deactivate exempt user manually |
| `TestMemberList_ShowsActiveStatus` | Response includes active, deactivated_at, scim_exempt |

### Cross-Cutting

| Concern | How handled |
|---------|------------|
| RLS isolation | Every org-scoped test includes cross-org check |
| testcontainers-go | All Postgres integration tests |
| Pristine output | SCIM errors captured and validated; suppression warnings expected and verified |
| Test data isolation | Each test creates own org/user/data |
| Audit logging | SCIM operations produce audit entries with correct metadata |
| Content-Type | All SCIM responses use `application/scim+json` |

---

## 8. Carry-Forward / Future Items

| Item | Status |
|------|--------|
| SCIM bulk operations | Not supported (no major IdP requires). ServiceProviderConfig declares unsupported. |
| SCIM sorting | Not supported. |
| SCIM ETags | Not supported. |
| Additional filter operators (sw, co, or) | MVP supports eq + and only. `sw` SQL mapping already documented in §4.3 — implementation-ready when needed. Add if Okta import feature requires. |
| Enterprise User schema extension | Not advertised. Add if customer demand exists. |
| SAML 2.0 NameID matching | Deferred with SAML support (Phase 5 carry-forward). |
| Domain ownership verification for SCIM | Deferred to SaaS phase (same as OIDC). |
| scimgateway library replacement | If maintainer abandons: switch to elimity-com/scim or build from scratch. Handler boundary is clean. |
| SCIM changePassword | Not planned. CVErt Ops uses OIDC/SSO for authentication, not passwords. ServiceProviderConfig declares unsupported. |
| SCIM token expiration / TTL | Tokens currently never expire. Add configurable TTL or forced rotation policy for security hardening. Not MVP (adds IdP setup friction). |
| SCIM provisioning observability | Add `last_sync_at` timestamp to config (updated on each SCIM request) and `provisioned_user_count`. Helps admins verify SCIM is working without digging through audit logs. |
| Admin filter by provisioning source | `GET /members?provisioned_by=scim` — helps admins troubleshoot sync issues. Not needed for MVP. |

---

## 9. Schema Review Findings (pre-resolved)

| # | Issue | Resolution |
|---|-------|------------|
| 1 | All tables missing explicit RLS DDL | Full ENABLE/FORCE/CREATE POLICY on all three tables |
| 2 | No IF NOT EXISTS on CREATE TABLE | Added to all |
| 3 | No GRANT statements | Added per-table with correct verbs |
| 4 | scim_groups CASCADE from scim_configs loses mappings | Reference organizations(id) directly |
| 5 | Missing partial unique on scim_groups(org_id, external_id) | Added WHERE external_id IS NOT NULL |
| 6 | Missing FK on scim_groups.org_id | Added REFERENCES organizations(id) |
| 7 | Missing FK on scim_group_members.org_id | Added REFERENCES organizations(id) |
| 8 | No explicit indexes | Added all FK + query-pattern indexes |
| 9 | Missing index on scim_groups(mapped_group_id) FK | Added BTREE index |
