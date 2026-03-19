# Wave 2: Master Consolidation & Editorial Decisions

**Date:** 2026-03-18
**Purpose:** Blueprint for the reorganized implementation-pitfalls.md. This document synthesizes all 10 Wave 1 agent reports into editorial decisions and the final document structure.

---

## Part 1: Document Structure

### Proposed Sections (Domain-Organized)

| # | Section | Reader Context | Approx Pitfalls |
|---|---------|---------------|-----------------|
| 1 | Feed Adapters & Data Ingestion | "I'm building or reviewing a feed adapter" | 22 |
| 2 | Database & Query Patterns | "I'm writing store methods, migrations, or SQL" | 25 |
| 3 | Authentication & Security | "I'm working on auth, OAuth, JWT, API keys, or MFA" | 25 |
| 4 | API Design & HTTP | "I'm writing or reviewing HTTP handlers or middleware" | 16 |
| 5 | Notification & Alert Evaluation | "I'm working on alerts, delivery, or webhooks" | 20 |
| 6 | Architecture & Operations | "I'm working on startup, config, deployment, scheduling" | 22 |

Plus:
- **Front matter:** How to Read This Document (audience-aware), relationship to testing-pitfalls.md
- **Appendix A:** Historical Changelog (provenance, validation dates, meta-observations)
- **Appendix B:** Summary Table (unified, replacing the three fragmented tables)

### Front Matter Design

Three audiences, three reading modes:
1. **Implementing agents** → go to your domain section, read the "When X, do Y" rules
2. **Reviewing agents** → go to your domain section, use the review checklist at the end
3. **Documentation-maintaining agents** → check Appendix A for provenance and validation status

---

## Part 2: Existing Pitfall Disposition

### Duplicates to Merge
| Keep | Remove | Reason |
|------|--------|--------|
| 1.8 (defer in loop) | 6.3 (Rounds 24-52 duplicate) | Identical finding |
| 2.12 (Dynamic IN 65k) | 12.1 (Rounds 24-52 duplicate) | Identical finding |

### Numbering Collisions to Resolve
The Rounds 24-52 table uses IDs 6.x-12.x that collide with later section numbers 8, 9, 10, 13. In the reorganized document, all findings get new domain-prefixed IDs (e.g., FEED-1, DB-1, AUTH-1, etc.) eliminating the collision entirely.

### Pitfalls to Update (code diverged from prescription)

| ID | Current Description | Update Needed |
|---|---|---|
| 5.8 | TRUSTED_PROXIES CIDR env var for XFF | Code uses chi's RealIP middleware instead — update to reflect actual implementation (which is good) |
| 1.7 | Polymorphic JSON fields | Mark as "preventive guidance" — not needed yet due to spec-compliant feeds. Keep the pattern but note YAGNI applies currently |
| 5.12 | Semver version range matching | Mark as "future work" — Masterminds/semver not in go.mod. Keep as guidance for when version ranges are added |

### Pitfalls to Strengthen

| ID | Enhancement |
|---|---|
| 1.1 | Add streaming decoder error recovery guidance (from NP-E3): don't `continue` after Decode error |
| 1.5 | Add goroutine lifecycle management: join points + resource controls for WithoutCancel (from NP-H2, NP-H3) |
| 2.17 | Add "never bypass store abstraction" guidance (from NP-H4): business logic must not duplicate transaction helpers |
| 5.14 | Add persistence/normalization requirements (from NP-5, NP-E10, NP-E11): in-memory security state must survive restart and normalize keys |
| 9.1 | Note the specific gap: auth paths catch 23505→409, but channels/rules/reports do NOT |
| 9.2 | Add whitespace validation examples (from NP-E16, NP-E18) |
| 13.1 | Emphasize this is STILL an active gap — Docker Compose still connects as superuser |

### Pitfalls Unchanged (VALIDATED, keep as-is)
106 pitfalls are VALIDATED and their descriptions accurately match the code. These transfer to the reorganized document with minimal rewriting — primarily reformatted into the new structure.

### Items Needing Verification (deferred to author)
| ID | What to check | Section writers should verify |
|---|---|---|
| 5.17 | Child table upsert sort order | Check merge pipeline for explicit sort before batch upsert |
| 10.3s | Nullable int zero-value handling | Check ai_request_log token count types |
| 10.1t | Digest DST drift | Trace digest scheduling through timezone arithmetic |
| 10.3t | Digest heartbeat | Check zero-match digest behavior |
| 10.4t | Missed-run catch-up | Trace catch-up policy implementation |
| 13.4 | Resource lifecycle completeness | Audit all New*() vs defer Close() in main.go |

---

## Part 3: New Pitfall Candidates — Deduplicated

After merging 47 raw candidates from three harvest agents, these are the **genuinely new patterns** to add:

### New Pitfall 1: Feature Flags Must Be Checked at Every Enforcement Point
**Sources:** harvest-late NP-1, NP-3, NP-4; harvest-early NP-E9 (related)
**Domain:** Section 6 (Architecture & Operations)
**Pattern:** Admin control flag exists in migration, store, and API — but the component that triggers the automatic behavior (scheduler, login handler) never reads it. Feature appears to work in the UI but has no effect.
**Examples:** Scheduler ignoring `paused_at`, login not checking `disabled_at`, `force_password_reset` never enforced
**Lesson:** After implementing any admin control flag, trace the flow to every enforcement point. Test by setting the flag and confirming the gated behavior stops.

### New Pitfall 2: Admin API Must Discover Resources Dynamically
**Sources:** harvest-late NP-2
**Domain:** Section 4 (API Design & HTTP)
**Pattern:** Admin endpoints iterate a hardcoded list of known resources, excluding user-configured items from listing and management.
**Example:** Feed admin endpoints gate on `IsKnownFeed(feedName)` which excludes generic feeds loaded from YAML.
**Lesson:** When resources can be extended by users (config files, plugins), admin endpoints must query the source of truth, not a compile-time constant.

### New Pitfall 3: Infrastructure Must Be Connected to Consumers
**Sources:** harvest-late NP-6, NP-7, NP-8
**Domain:** Section 6 (Architecture & Operations)
**Pattern:** Config reload pipeline, feature flag system, or integration infrastructure is built and tested, but the consumers (handlers, workers) still read from the old source. Operators see "success" but the new config/feature isn't active.
**Examples:** Hot-reload ConfigHolder updated but all 30+ call sites read startup `srv.cfg`; SIEM syslog writer implemented but never instantiated; partial secrets file zeros fields not in the file.
**Lesson:** After building any "reload" or "feature flag" infrastructure, grep for the static/old source across all files. Each hit is a consumer that needs updating. Infrastructure without consumers is dead code that creates false confidence.

### New Pitfall 4: Silent Error Suppression on Success Paths
**Sources:** harvest-early NP-E2, NP-E21, NP-E26
**Domain:** Section 6 (Architecture & Operations)
**Pattern:** `_ = criticalStateWrite()` on success paths discards errors from cursor persistence, sync state, or other critical writes. The job reports success but state is lost.
**Examples:** Feed cursor write fails silently → next run re-processes entire window; email verification resend claims "sent" when SMTP failed; sendInvitationEmail returns nil on nil org without logging.
**Lesson:** On success paths, critical state writes MUST propagate errors. Best-effort writes (logging) MUST at minimum log at ERROR level. `_ =` is acceptable only for truly non-critical side effects.

### New Pitfall 5: Internal Pagination Defeats Crash Recovery
**Sources:** harvest-early NP-E4
**Domain:** Section 1 (Feed Adapters & Data Ingestion)
**Pattern:** Adapter loops through all upstream API pages internally and returns `LastPage: true` with all results combined, defeating the handler's pagination recovery mechanism.
**Example:** GHSA adapter fetches all GitHub API pages in one Fetch() call. Crash on page 50 of 100 loses all work from pages 1-49.
**Lesson:** Always return one logical page per adapter Fetch() call. Let the handler persist progress between pages. Internal pagination is an anti-pattern that defeats crash recovery and causes unbounded memory growth.

### New Pitfall 6: Atomic Token Consumption
**Sources:** harvest-early NP-E12, NP-E19
**Domain:** Section 3 (Authentication & Security)
**Pattern:** One-time-use tokens (password reset, invitation accept) are consumed non-atomically: read token in one transaction, perform action in another, mark used in a third. Concurrent requests both pass the read gate.
**Example:** Two concurrent password reset requests with the same token both succeed; two concurrent invitation accepts produce 500 from constraint violation.
**Lesson:** One-time-use tokens MUST be marked consumed in the same transaction as the action they authorize. Use SELECT FOR UPDATE or ON CONFLICT DO NOTHING for idempotent acceptance.

### New Pitfall 7: Security-Critical Code Must Not Be Copy-Pasted
**Sources:** harvest-health NP-H5
**Domain:** Section 3 (Authentication & Security)
**Pattern:** Security logic (JWT parsing, HMAC verification, key rotation) copy-pasted across multiple functions. A fix to one instance must be applied to all — and the missed instance is an auth bypass.
**Example:** Four JWT parse functions with identical dual-key rotation logic. A security fix applied to 3 of 4 creates an authentication vulnerability.
**Lesson:** Security-critical logic MUST use shared helpers. If you find yourself copying auth/crypto/validation code, stop and extract. The risk of duplication is not code quality — it's a security incident from a missed update.

### New Pitfall 8: Configuration Constants With Ordering Invariants
**Sources:** harvest-health NP-H7
**Domain:** Section 6 (Architecture & Operations)
**Pattern:** Two timeout/threshold constants that must maintain a relationship (e.g., staleThreshold >= maxJobDuration) are set independently. One is changed without updating the other.
**Example:** `staleThreshold = 5m` and `maxJobDuration = 10m` — legitimate 7-minute jobs are reclaimed as stale, causing duplicate processing.
**Lesson:** When two constants have an ordering invariant, document it explicitly and consider deriving one from the other. Add a comment at the definition site: `// INVARIANT: staleThreshold must be >= maxJobDuration`.

### New Pitfall 9: Enumeration-Safe Endpoints Must Audit Every Error Path
**Sources:** harvest-early NP-E15
**Domain:** Section 3 (Authentication & Security)
**Pattern:** Endpoint designed to return 200 for all inputs (anti-enumeration) has error paths that only execute for existing users, leaking existence via 500 vs 200.
**Example:** `forgotPasswordHandler` returns 200 for unknown emails but 500 on DB errors in user-specific queries (CreatePasswordResetToken only runs for existing users).
**Lesson:** In enumeration-safe endpoints, every error path must be audited for existence-conditioning. A single conditional error leaks the guarantee. Return the same status for all errors, or wrap all user-conditional operations in the same error handling.

### New Pitfall 10: Response Body Must Be Drained After json.Decoder
**Sources:** harvest-early NP-E8; extends existing 9.6 (webhook body)
**Domain:** Section 1 (Feed Adapters & Data Ingestion)
**Pattern:** `json.NewDecoder(resp.Body).Decode(&v)` reads only enough bytes to decode one value. Remaining response bytes prevent TCP connection reuse.
**Example:** Red Hat detail fetches open new TCP+TLS connections for each of 100+ requests because the decoder doesn't consume the full body.
**Fix:** After Decode, call `io.Copy(io.Discard, resp.Body)` before Close.
**Lesson:** json.Decoder doesn't consume the entire body. Always drain responses before closing, even after successful Decode. This applies to ALL outbound HTTP, not just webhooks.

---

## Part 4: Pitfall-to-Section Assignment

### Section 1: Feed Adapters & Data Ingestion

**From existing pitfalls:**
- 1.1 JSON Wire Format (+ strengthen with decoder error recovery NP-E3)
- 1.2 archive/zip Seekable Reader
- 1.6 Timestamp Fallback Parser
- 1.7 Polymorphic JSON Fields (mark as preventive)
- 1.8 defer in Loop (merge 6.3)
- 1.9 URL Query + Encoding
- 1.10 OSV ZIP Pre-filter
- 5.2 Bulk Import Required
- 5.3 NVD 120-Day Window
- 5.4 NVD Dual Rate Limits
- 5.13 OSV/GHSA Alias PK Resolution
- 7.1 NVD API Key Header
- 7.2 NVD Overlap Cursor Gap
- 7.3 NVD Cursor Upper Bound
- 7.4 Withdrawn Field Check
- 7.5 Late-binding Alias Split-brain
- 7.6 GHSA Rate Limiting
- 6.2 strings.Clone for JSON Buffers

**New pitfalls:**
- NP-5 Internal Pagination Defeats Crash Recovery
- NP-10 Response Body Drain After json.Decoder

### Section 2: Database & Query Patterns

**From existing pitfalls:**
- 2.1-2.17 (all existing DB pitfalls, unchanged)
- 11.1-11.5 (schema pitfalls from Rounds 24-52)
- 12.1 (merge into 2.12 — duplicate)

**Strengthen:**
- 2.17 with NP-H4 (store abstraction bypass guidance)

### Section 3: Authentication & Security

**From existing pitfalls:**
- 1.3, 1.4 (GitHub OAuth)
- 3.1-3.12 (all security pitfalls)
- 8.1-8.8 (Rounds 24-52 security findings)
- 13.5 (config defaults)

**New pitfalls:**
- NP-6 Atomic Token Consumption
- NP-7 Security-Critical Code No Copy-Paste
- NP-9 Enumeration-Safe Error Path Audit

**Strengthen:**
- 5.14 with in-memory lockout persistence/eviction/normalization (NP-E10, NP-E11) → move to this section since it's about security state
- 8.8 with note about remediation status

### Section 4: API Design & HTTP

**From existing pitfalls:**
- 1.5 (r.Context + WithoutCancel) → strengthen with NP-H2/H3 goroutine lifecycle
- 1.11 (PATCH pointer types)
- 3.7, 3.8 (request body, Slowloris)
- 5.8 (IP rate limiter — update to reflect chi RealIP)
- 5.18 (keyset pagination)
- 5.19 (pgx SimpleProtocol)
- 9.1 (unique constraint → 409) — note the gap
- 9.2 (PATCH re-validates) — strengthen with whitespace examples
- 13.3 (API contract consistency)

**New pitfalls:**
- NP-2 Admin API Dynamic Resource Discovery

### Section 5: Notification & Alert Evaluation

**From existing pitfalls:**
- 4.1-4.14 (all operational pitfalls)
- 6.4 (errgroup fan-out)
- 9.3-9.8 (Rounds 24-52 notification findings, minus 9.5 Slack which is unimplemented)

### Section 6: Architecture & Operations

**From existing pitfalls:**
- 5.1, 5.5-5.7, 5.9-5.12, 5.15-5.17 (architecture decisions)
- 6.1 (time.After leak)
- 10.1-10.10 from Rounds 24-52 table (digest, connection pool, etc.)
- 10.1s-10.5s from Phase 4 AI Gateway (shared columns, LLM schema, lazy init, cache/quota)
- 13.1-13.4 (cross-cutting enforcement)
- Section 8 Process Guardrails (8.1-8.6 from Phase 2a review)

**New pitfalls:**
- NP-1 Feature Flag Enforcement Points
- NP-3 Infrastructure Connected to Consumers
- NP-4 Silent Error Suppression on Success Paths
- NP-8 Configuration Constants Synchronization

---

## Part 5: Review Checklists (end of each section)

Each domain section should end with a brief checklist for code reviewers. Examples:

**Section 1 (Feed) checklist:**
- [ ] Does the adapter use Token()+More() for streaming? (Never Decode(&slice))
- [ ] Does ZIP processing use temp file bridging? (Never io.ReadAll)
- [ ] Are timestamps parsed via feed.ParseTime, not time.Parse directly?
- [ ] Does the adapter return one page per Fetch() call? (No internal pagination)
- [ ] Are null bytes stripped via StripNullBytes?
- [ ] Is the response body drained after json.Decoder?
- [ ] Are CVE aliases checked via ResolveCanonicalID?
- [ ] Are array fields sorted before material_hash?
- [ ] See testing-pitfalls.md §9 for test scenarios

**Section 3 (Auth) checklist:**
- [ ] JWT: WithValidMethods([]string{"HS256"}) + WithExpirationRequired()?
- [ ] API keys: opaque, sha256 stored, subtle.ConstantTimeCompare?
- [ ] OAuth: random state, SameSite=Lax, constant-time compare, OIDC nonce verified?
- [ ] Argon2: non-blocking semaphore, defer release?
- [ ] One-time tokens: consumed in same transaction as authorized action?
- [ ] Enumeration-safe endpoints: every error path returns same status?
- [ ] See testing-pitfalls.md §11 for security enforcement tests

---

## Part 6: Historical Appendix Content

### What to Preserve
- Original review round dates and source (Gemini Pro rounds 1-52)
- Post-implementation discovery dates and sources (Phase 2a review, Phase 3b audit, etc.)
- Meta-observations on the review process (both sets — rounds 1-23 and 24-52)
- Validation status per finding (from this Wave 1 audit)

### What NOT to Preserve
- The three fragmented summary tables (replaced by unified Appendix B)
- The Rounds 24-52 table-only findings (expanded into full entries in domain sections)
- Duplicate entries (6.3, 12.1)

### Appendix Structure
```
Appendix A: Historical Changelog
  A.1 Pre-Implementation Review (2026-02-21) — Rounds 1-52
  A.2 Post-Implementation Findings — Phase 2a through Phase 11
  A.3 Meta-Observations on the Review Process
  A.4 Validation Audit (2026-03-18) — Wave 1 Results

Appendix B: Unified Summary Table
  All pitfalls by domain, with status and severity
```

---

## Part 7: Cross-Reference Plan

Add to front matter: "This document specifies implementation patterns. For test verification strategies, see `dev/testing-pitfalls.md`. Key cross-references are noted inline."

Per-section cross-references (from xref agent):
- Section 1 (Feed) → testing-pitfalls.md §9 (Feed Data Quality)
- Section 2 (Database) → testing-pitfalls.md §7 (Transaction & Store), §10 (RLS)
- Section 3 (Auth) → testing-pitfalls.md §11 (Security Enforcement)
- Section 4 (API) → testing-pitfalls.md §4 (Validation Symmetry), §3 (Error Paths)
- Section 5 (Notify) → testing-pitfalls.md §8 (External Dependencies), §14 (Delivery)
- Section 6 (Arch) → testing-pitfalls.md §5 (Configuration), §13 (Feature Flags)

---

## Part 8: Final Decisions (Post-Review with Sam)

### Section Assignment Adjustments
1. **Split 1.5 (r.Context):** Handler-side "use WithoutCancel" stays in Section 4 (API). Goroutine lifecycle extensions (join points, shutdown coordination, semaphore controls from NP-H2/H3) go to Section 6 (Architecture).
2. **Move 4.3 (token_version global logout)** → Section 6 (Architecture). Documented system limitation, not notification-specific.
3. **Move 4.11 (LLM prompt injection)** → Section 6 (Architecture). AI integration concern.

### Cross-Reference Approach
Each section gets a **"See Also" block** after the last entry, before the review checklist. Max 3-5 entries. One line each using stable domain-prefixed IDs. Low-maintenance fixed block.

Example:
```
### See Also
- AUTH agents spawning background work: see API-3 (r.Context background goroutines)
- DB transaction helpers used in handlers: see DB-17 (transaction helper selection)
```

### Table-Only Finding Expansion: Tiered Approach
- **Full Flaw/Why/Fix/Lesson:** When the failure mode is non-obvious or the fix requires architectural understanding (e.g., alias split-brain, webhook redirect SSRF, EPSS staging lifecycle, concurrent refresh theft detection)
- **Condensed paragraph:** When the fix is a one-line pattern substitution and the why is self-evident (e.g., "use time.NewTicker not time.After", "JWT_SECRET missing must fatal", "pg_trgm extension required")

Heuristic: if an implementing agent could correctly apply the fix from just the table row without understanding the failure mode, condensed is fine. If they'd need to understand WHY to apply it correctly, expand fully.

### Verification Items
6 items dispatched to targeted verification agents. Results will be folded into final section content.
