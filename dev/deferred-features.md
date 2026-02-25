# CVErt Ops — Deferred Features Research Notes

> **Date:** 2026-02-22
> **Source:** Gemini Pro architectural review rounds 46–52 of PLAN.md
> **Purpose:** Capture research findings and design sketches for features that are explicitly deferred from MVP (Phase 0–5). These are not implementation requirements — they are recorded to preserve design thinking and prevent re-research.

---

## How to Use This Document

These notes are reference material for when deferred features are prioritized. Each section describes:
- **The feature** — what it is and why it was proposed
- **Design notes** — key decisions and pitfalls identified during review
- **Findings from review** — traps to avoid when implementing

Nothing in this document is required for MVP. When a section is promoted to active development, migrate its relevant decisions and pitfalls into PLAN.md and implementation-pitfalls.md.

---

## 1. Frontend UI/UX

*Corresponds to PLAN.md §20 (Frontend Deferred). These notes extend §20.3 (Provisional Page Inventory) with design detail.*

### 1.1 CVE List View — Information Density

**Design:** Use a dense data-grid primary view (e.g., TanStack Table) rather than card-based layouts. Every row should be actionable without a page transition.

**Key features identified:**
- **Sparklines in rows:** Show EPSS score trend for the last 7 days alongside each CVE. A rising trend indicates an actively exploited or newly-publicized vulnerability. The underlying data (daily EPSS snapshots) needs a `epss_history` table if this is implemented — `cves.epss_score` is only the current value.
- **Contextual hover popover:** Hovering over a CVE ID renders a "Quick-Peek" overlay (summary, affected CPEs, primary exploit link) without navigation. Requires a lightweight API endpoint returning only the fields needed for the popover — not the full CVE detail.
- **Deep-linking / URL-state serialization:** Every filter, search term, and sort order must be mirrored in URL query parameters (e.g., `?search=exchange&min_score=9.0`). Shareable links preserve exact state across users and sessions. Implement before adding any filter UI; retrofitting is painful.

### 1.2 CVSS v3.1 / v4.0 Dual-Score Visualization

**Design:** Split-color severity badge — left half represents CVSS v3.1, right half CVSS v4.0. Visual delta indicator (pulse or high-contrast border) when v4.0 elevates severity tier above v3.1.

**Key feature:** "Human-Readable Vector Map" — clicking the badge expands a decoded view translating `CVSS:4.0/AV:N/AC:L/AT:N...` into plain English. Backend already stores `cvss_v3_vector` and `cvss_v4_vector`; the decoder lives entirely in the frontend.

**Pitfall:** The `cves` table stores both scores but not the historical delta. If this feature needs to show when a score *changed* (e.g., "upgraded from High to Critical"), the merge pipeline needs to emit a score-change event or the frontend needs to diff against `alert_events`.

### 1.3 CPE Wildcard Builder (Search UX)

**Design:** Tokenized faceted search bar for CPE queries. The user selects vendor → product → version using autocomplete, rather than typing raw CPE strings.

**Key features:**
- Autocomplete pulls from the `cve_affected_cpes` column data — need a vendor/product facet API backed by a distinct-values query with caching.
- Wildcard `*` rendered as a distinct "Any Version" tag to prevent wildcard blindness.
- The NVD CPE dictionary (separate from `cwe_dictionary`) would power full autocomplete. If not ingested, autocomplete can only offer values already in the corpus.

### 1.4 Alert Rule Dry-Run Sidebar

**Design:** Real-time dry-run feedback as the user types a rule. Frontend polls a preview endpoint and displays: "This rule would have triggered N alerts in the last 48 hours. [See samples]."

**API dependency:** `POST /api/v1/orgs/{org_id}/alert-rules/validate` already planned (PLAN.md Appendix B). The dry-run response would need to include sample matching CVEs with estimated count for the sidebar to work. The dry-run endpoint (`POST .../dry-run`) returns this — the sidebar just needs to call it with a debounce (300ms after last keystroke).

**Pitfall (already in PLAN.md §10.6):** Dry-run must execute in a rolled-back transaction. Never commit to `alert_events`.

### 1.5 Notification Dead-Letter Office (Actionable Audit Center)

**Design:** A "System Health" persistent indicator in the global navigation. If any background delivery has failed, a non-intrusive alert icon appears. Clicking opens a dead-letter view showing: exact failed payload, error from the destination server, and a one-click Retry button.

**API dependency:** `GET /api/v1/orgs/{org_id}/channels/{id}/deliveries?status=dead` and `POST .../deliveries/{id}/replay` are already planned (Appendix B). The UI just needs to surface them prominently.

**Pitfall:** The global navigation icon requires a lightweight "health summary" API endpoint (e.g., `GET /api/v1/orgs/{org_id}/health`) returning the count of dead-letter deliveries. Polling the full delivery list is too expensive for a nav badge.

### 1.6 Protocol / Security Health Check on Login Screen

**Design:** Before the login form renders, JavaScript checks `window.location.protocol`. If it is `http:` and the host is not `localhost`, display a warning banner: *"Warning: You are accessing this over an insecure connection. Session cookies may be blocked by your browser."*

**Rationale:** Self-hosted operators frequently skip TLS configuration and then report "I can't log in" bugs. This surfacing prevents most such support tickets (see PLAN.md §7.1 for the `COOKIE_SECURE` env var requirement — this UI warning is the frontend complement).

### 1.7 Critical Revocation Double-Confirmation

**Design:** Destructive actions on "live" resources (deleting an active API key, removing an alert rule) require the user to type the key's name or the word `REVOKE` to confirm. Standard confirm dialogs are clicked through without reading.

**Scope:** API key deletion, active alert rule deletion, org member removal. NOT required for deletion of drafts or inactive resources.

---

## 2. SBOM (Software Bill of Materials) Support

*This is a post-MVP feature track. No SBOM support is included in Phases 0–5.*

### 2.1 Why SBOMs

SBOMs transform CVErt Ops from reactive search to proactive continuous monitoring. Instead of a user searching for "Log4j," the system already knows they have it and alerts the moment a new CVE is published. As of 2026, SBOMs are a compliance requirement in many regulated industries (US Executive Order 14028, EU Cyber Resilience Act).

### 2.2 Format Support

**CycloneDX (primary):** OWASP standard, security-focused. Native support for VEX (Vulnerability Exploitability eXchange), which declares whether a vulnerability is actually reachable in deployed code. Parse as CycloneDX JSON.

**SPDX (secondary):** Linux Foundation standard, compliance/legal focused. ISO standard, required for large enterprise procurement. Provide a conversion wrapper from SPDX 3.0 to the internal normalized format rather than a full native parser.

### 2.3 Identity: PURL vs. CPE Dual-Stack Matching

**The problem:** CPEs are the language of NVD; PURLs (`pkg:npm/lodash@4.17.21`) are the language of developers and the OSV database. Modern SBOMs often omit CPEs. Old vulnerability databases often omit PURLs.

**Design:** "Precision-first" dual-stack matching:
1. Extract both PURLs and CPEs from the SBOM.
2. Attempt PURL match against `cve_affected_packages` first (OSV-sourced data; high precision for ecosystem packages).
3. Fall back to CPE fuzzy match against NVD-sourced `cve_affected_cpes` if no PURL match.

**Pitfall:** PURL matching requires normalizing package names (lowercase, stripping namespace separators, etc.) against the `cve_affected_packages.package_name` field. The normalization rules differ per ecosystem (npm is case-insensitive, Go module paths are case-sensitive, PyPI normalizes `_` and `-` as equivalent).

### 2.4 VEX Reachability Engine

**Design:** If an uploaded CycloneDX SBOM includes VEX statements (`status: not_affected`), those CVEs are suppressed in the UI and excluded from alert delivery for that asset.

**UI treatment:** "Dim" or strikethrough suppressed vulnerabilities; add a toggle "Show only exploitable components" that hides VEX-suppressed rows entirely. This reduces a list of 500 alerts to ~5 actionable items.

**Backend table:** `sbom_vex_suppressions(asset_id, cve_id, vex_status, justification_text, ingested_at)`. Alert delivery checks this table before fanning out.

### 2.5 Asset Version Tracking (SBOM Drift)

**The problem:** CI/CD pipelines upload a new SBOM on every build. Without version tracking, the database accumulates thousands of "assets" (one per build), making the dashboard unusable within weeks.

**Design:** `software_assets` table with a stable `asset_key` (e.g., `org-name/service-name`) plus a version sequence. All uploads for the same `asset_key` are versions of the same asset.

```sql
CREATE TABLE software_assets (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid NOT NULL REFERENCES organizations(id),
    asset_key   text NOT NULL,           -- stable: "repo/service"
    display_name text NOT NULL,
    current_version_id uuid NULL,        -- FK to software_asset_versions
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE(org_id, asset_key)
);

CREATE TABLE software_asset_versions (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id    uuid NOT NULL REFERENCES software_assets(id),
    version_tag text NOT NULL,           -- CI build tag, git SHA, semver, etc.
    sbom_format text NOT NULL,           -- 'cyclonedx', 'spdx'
    sbom_sha256 text NOT NULL,           -- content hash; dedup re-uploads
    component_count int NOT NULL,
    ingested_at timestamptz NOT NULL DEFAULT now()
);
```

The UI defaults to showing the `current_version_id` stats. A "History" toggle shows version-over-version vulnerability delta (did we fix the Log4Shell? did we introduce a new critical?).

**Pitfall — ephemeral build name collision:** If users tag SBOMs with CI build IDs as the asset name (e.g., `build-1234`), every commit creates a new asset. The UI enforces that `asset_key` must be a stable identifier. The CLI should enforce this with a `--asset-key` required flag (not `--name`), with documentation explaining the distinction.

**State transfer on version upgrade:** When `production-v2.sbom` is ingested, any "Acknowledged" or "Ignored" status for a component that hasn't changed carries forward to v2 automatically. This prevents analysts from re-triaging hundreds of unchanged low-priority CVEs after every release.

### 2.6 Dependency Tree (Ghost Dependency Forensics)

**Design:** In the CVE detail view for a matched SBOM component, show the full dependency lineage: `Your App → Web Framework → JSON Parser → VULNERABLE LIBRARY`. This tells an engineer whether they need to update the vulnerable library directly, or a parent dependency that bundles it.

**Backend dependency:** CycloneDX SBOMs include `dependencies` elements mapping each component to its dependents. This needs to be stored and queryable — a `sbom_dependency_graph(version_id, component_purl, depends_on_purl)` edge table. Graph traversal to find the path from the root to a vulnerable leaf.

### 2.7 `cvert-cli` — Companion CLI Specification

A single statically-linked Go binary for SBOM ingestion from CI/CD pipelines.

**Tech stack:** Cobra (subcommands) + Viper (`.cvert.yaml` config + env var support).

**Commands:**

`cvert-cli auth login`
- Initiates OAuth2 Device Code flow (browser-based).
- Stores tokens in OS keychain (`keybase/go-keychain` or `zalando/go-keyring`).
- Silently refreshes tokens mid-operation without failing the build.

`cvert-cli upload [FILE]`
- Flags: `--asset-key` (required, stable identifier), `--env` (prod/staging), `--format` (auto-detected if omitted), `--api-key` (for CI; alternative to keychain auth).
- Calculates SHA-256 of file before upload; server deduplicates by hash.
- Streams upload; no buffering into memory.

`cvert-cli scan [FILE]`
- "Dry run" — sends SBOM to ephemeral `/api/v1/sboms/scan` endpoint (not persisted).
- Returns JSON or table-formatted list of matched CVEs.
- Intended for pre-commit hooks.
- Exit codes: `0` = success (no criticals found), `1` = criticals found (break the build), `2` = network/API error (build continues, team alerted).

**CI/CD example (GitHub Actions):**
```yaml
- name: CVErt Ops SBOM Scan
  run: |
    cvert-cli upload ./bom.json \
      --asset-key "myorg/api-service" \
      --api-key ${{ secrets.CVERT_KEY }} \
      --fail-on "critical"
```

**Pitfall — log redaction:** The CLI must redact `Authorization`, `token`, `key`, and `secret` fields from all debug/verbose output, even at the highest log level. Engineers routinely paste `--debug` output into public GitHub Issues. Replace sensitive field values with `[REDACTED]` at the logger level, not per-call-site.

**Pitfall — chunked bulk uploads:** Enterprise SBOMs (monolithic Java app with 10,000+ components) can exceed a few MB. The CLI must use multipart streaming upload rather than buffering the file in memory. The API's global 1MB request body limit (see PLAN.md §18.3) needs a separate `/api/v1/sboms/upload` endpoint with a higher limit (configurable, e.g., 50MB) specifically for SBOM ingestion.

---

## 3. Admin & Governance UI

*These are the Org Admin and Global Admin UI pages referenced in PLAN.md §20.3.*

### 3.1 Org Admin: Permission Matrix View

**Design:** Replace simple role dropdowns with a visual grid mapping roles to functional areas ("Can Edit Alert Rules", "Can Upload SBOMs", "Can Manage API Keys"). Each cell is a ✓/✗.

**"Effective Permissions" view:** Clicking on any user shows their resolved permission set — what they can do right now, accounting for their role and any group memberships. Useful for security audits ("does this contractor actually have access to alert rules?").

### 3.2 Org Admin: Staging SSO Validator

**Design:** A "Test Configuration" button on the SSO setup page opens a popup that initiates a mock SAML/OIDC flow *without saving the configuration*. Displays the raw attributes returned by the IdP (`email`, `groups`, `first_name`, etc.) and shows how they map to CVErt Ops roles under the current mapping logic.

**Why critical:** One wrong Entity ID or ACS URL locks out the entire team. Testing before committing eliminates the most common SSO onboarding incident.

### 3.3 Global Admin: Background Worker Observatory

**Design:** Dedicated admin page showing the health of background workers:
- **Live queue visualization:** Real-time graph (`pending` vs. `processing` vs. `failed` jobs) for the last 24 hours. Backed by the `job_queue` table.
- **Worker heartbeat table:** Every active worker process with its current memory/CPU (via `/debug/pprof` or GOMEMLIMIT stats), and the specific job it is executing right now. Requires the worker to update a heartbeat row in a `worker_heartbeats` table every N seconds.
- **Feed kill switch:** A global button to pause feed syncing (sets a `feed_sync_paused` flag in a `system_config` table). Used during NVD outages to prevent IP bans from retry storms.

### 3.4 Global Admin: Feed Integrity Traffic Light

**Design:** Status board for each upstream feed: name, last-sync timestamp, last-sync status, and a traffic-light indicator (🟢 healthy / 🟡 delayed / 🔴 failing). "Delayed" triggers when the last successful sync was >2× the expected cadence. "Failing" triggers when `consecutive_failures > 0` in `feed_sync_state`.

This is largely already plannable from `feed_sync_state.last_success_at`, `consecutive_failures`, and `last_error` — the API endpoint is simple; the UI just needs to surface it.

### 3.5 Audit Log: Timeline View with Diff

**Design:** Chronological timeline grouped by entity (e.g., "User X edited Alert Rule Y at 14:32"). For any change to a rule, channel, or org setting, the timeline entry expands to a side-by-side JSON diff: "Old CVSS threshold: 7.0 → New CVSS threshold: 8.5."

**Pitfall — secret leak in audit log (Round 51):** The diff viewer must redact fields tagged as sensitive (Secrets, API keys, passwords). The audit logging engine must be secret-aware at write time — never record the raw new secret value, only `[REDACTED]`. If the audit log records "Old Secret: X → New Secret: Y", it turns the audit log into a credential treasure map.

---

## 4. Findings Captured from These Reviews

These review findings from rounds 46–52 are specific enough to record even though the features they apply to are deferred:

| ID | Area | Finding | Severity |
|---|---|---|---|
| F-1 | Frontend | URL state not serialized → filter state not shareable; deep links don't preserve context | Medium |
| F-2 | Frontend | CPE autocompletion needs an indexed vendor/product facet endpoint — not just a text search | Medium |
| F-3 | Frontend | `window.location.protocol` check on login prevents 90% of "can't log in" self-hosted support tickets | Low |
| F-4 | SBOM | PURL normalization rules differ per ecosystem; case-insensitive matching for npm, case-sensitive for Go modules | High |
| F-5 | SBOM | Ephemeral CI build IDs as asset names → 5,000 "assets" within a month; enforce stable `asset_key` | High |
| F-6 | SBOM | CLI debug/verbose logs print `Authorization` header → leaked API key in public bug reports; redact at logger level | Critical |
| F-7 | SBOM | Large SBOM uploads (>1MB) hit API body limit; need separate endpoint with higher limit | Medium |
| F-8 | Admin | Org Admin can downgrade or delete themselves → no remaining admin → org permanently locked | High |
| F-9 | Admin | User invitations with no expiry sit in email archives indefinitely; 72-hour hard expiry required | High |
| F-10 | Admin | Audit log records raw new secret value in diffs → credentials exposed in audit trail | Critical |
| F-11 | Admin | SSO config saved before test → one wrong field locks out entire org | High |
| F-12 | Frontend | `IN ($1...$N)` for watchlist/SBOM matching panics pgx at 65,536 items → use `ANY($1::text[])` | Critical |
| F-13 | Admin | Filter state in admin audit log / CVE list fires N separate API requests per state change; debounce 300ms | Low |

### Notes on Critical Findings

#### F-8: Last Admin Self-Revocation (Round 49)

The API must prohibit an Org Admin from changing their own role to a lower role, or deleting their own account, if they are the sole remaining admin or owner of the organization. Without this guard, a single misclick on the "Users" page can permanently lock the organization (no admin → can't invite new admins → org is stranded).

**Required API behavior:**
- `PATCH /api/v1/orgs/{org_id}/members/{user_id}` where `user_id = caller's user_id`: check if the org would have zero owners/admins after the change. If yes, return `409 Conflict` with a message explaining the constraint.
- `DELETE /api/v1/orgs/{org_id}/members/{user_id}` where `user_id = caller's user_id`: same check.
- The check must be a DB-level count — not a cached role — to handle concurrent operations.

#### F-9: Invitation Phantom (Round 50)

User invitations contain sensitive tokens (used to accept membership without a separate registration flow). Invitations that sit unaccepted for weeks or months represent long-lived secrets in email archives and corporate mail appliances.

**Required behavior:**
- All invitations have a 72-hour TTL. After expiry, the token is invalid and the invitation shows "Expired" status in the UI.
- "Resend" generates a fresh token (new UUID, new 72-hour TTL) and invalidates the old token. The invitation row is updated in-place; a new row is not created.
- The invite endpoint checks token validity before showing the acceptance page — return `410 Gone` for expired tokens, not `401`.

#### F-10: Secret Leak in Audit Log (Round 51)

The audit diff system must never record the raw value of secret fields. When an admin updates a webhook signing secret, the diff should read:
```
Before: signing_secret = [REDACTED]
After:  signing_secret = [REDACTED]
```
Not the actual values. Fields requiring redaction: any field named or tagged as `secret`, `password`, `api_key`, `token`, `private_key`. Redaction must happen at audit-log write time, not at read time — once written to the DB in plaintext, the log is already compromised.

#### F-12: `IN` Clause Overflow (covered in implementation-pitfalls.md §2.12)

This finding applies to MVP as well (large watchlists), not just SBOM features. See [implementation-pitfalls.md §2.12](implementation-pitfalls.md) for the full write-up. Summary: use `WHERE col = ANY($1::text[])` for all user-provided list membership checks; never build dynamic `IN ($1, $2, ..., $N)` clauses.
