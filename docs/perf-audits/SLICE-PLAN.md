# Whole-Repo Performance Audit — Slice Plan & Progress Ledger

ABOUTME: The reviewed partition of CVErt-Ops into bounded perf-audit slices, the disjoint
ABOUTME: coverage ledger, cross-slice frequency map, and the resumable progress ledger.

**Method:** `performance-audit-cycle` → `whole-repo-scoping.md` (full method: survey → hot-path
map → slice → cross-slice frequency calibration → depth tiers → **review-gate-before-spend** → run
cycle per slice with a resumable ledger). **Planning commit:** see `git log` for the commit that
introduced this file (the planning SHA the coverage ledger is reconciled against).

**Plugin/version:** `superpowers-plus@0.2.0` (vendored into `.claude/skills/`; version per source repo).
**Dispatch model requested:** Claude Code Agent tool, `opus` (latest) for FULL/REDUCED slices,
`sonnet` for COLD sweeps; **reasoning_effort:** `default (harness exposes no knob)`.

---

## 1. Survey & measured production LOC

Excludes `*_test.go`, sqlc-generated `internal/store/generated/**` (9.0k, audited via its `.sql`
sources), `internal/testutil/**` (test support), `web` tests/specs/`*.d.ts`. Tool: `wc -l` with
generated-banner and test-suffix exclusion (no `tokei` in container).

| Area | Lang | Prod LOC | Purpose |
|---|---|---:|---|
| internal/merge | Go | 1014 | CVE canonical-row merge (JCS + sha256, full recompute per source write) |
| internal/alert (+dsl) | Go | 1642 | Alert DSL compile + 3-path evaluator (realtime/batch/EPSS) |
| internal/feed/** | Go | 5375 | 10 feed adapters (NVD/MITRE/GHSA/OSV/KEV/EPSS/MSRC/RedHat/CSAF/generic) — streaming parse |
| internal/ingest | Go | 748 | Feed ingestion orchestrator |
| internal/store (hand-written) | Go | 7096 | Repository layer (sqlc wrappers + squirrel DSL) |
| internal/store/queries/*.sql | SQL | 32 files | Hand-written query sources (sqlc input) |
| migrations/*.sql | SQL | 2137 | 45 migrations — schema/DDL, indexes, RLS |
| internal/notify | Go | 1179 | Notification channels + fan-out delivery |
| internal/secure | Go | 616 | Async security-event writer + rate limiting |
| internal/worker | Go | 320 | Job queue + goroutine pool |
| internal/ai | Go | 410 | Gemini client + quota + sanitization |
| internal/{audit,auth,tier,config,crypto,doctor,metrics,retention,dbutil,log} | Go | 2509 | Cross-cutting subsystems |
| internal/api (hand-written handlers) | Go | 17698 | huma+chi HTTP handlers + middleware |
| internal/api/openapi_spec.go | Go | 1734 | Spec-only Huma op declarations (glue) |
| cmd/** | Go | 1408 | cobra entry points + healthcheck |
| web/src (Vue/TS) | Vue/TS | 9214 | Vue 3 SPA (views 4472, components 4066, stores/composables/router/lib/layouts ~676) |

**Go production total ≈ 42k LOC; Vue/TS ≈ 9.2k LOC. Two ecosystems, one deployable.**
Raw→prod delta is large for Go (heavy `_test.go` + 9.0k generated excluded), as the method warns.

## 2. One program or many?

**One deployable** — a single binary running HTTP server + worker (cobra subcommands), serving an
**embedded** Vue SPA (`web/embed.go`). The backend↔SPA divide is a **process boundary** handled by
one-primary-ecosystem slicing (a Go slice family + a Vue slice), **not** a service-monorepo split.
No shared-lib-audited-once case applies (single module).

## 3. Workload shape & hot-path map (cheap, structural; verified against code)

**Shape: IO-bound service + batch ingestion worker.** "Hot" = DB round-trips, query shapes &
indexes, N+1/unbatched access, merge recomputation, alert evaluation over the corpus, feed
streaming parse, notification fan-out, FTS — sized by request/ingest rate, **not** inner CPU loops.
CPU-bound pockets that genuinely matter: JCS canonicalization + sha256 in merge, DSL regex /
postfilter evaluation, keyset-pagination + FTS query construction.

| Region | Class | Why (code-grounded) |
|---|---|---|
| merge pipeline | **HOT** | Re-reads *all* `cve_sources` rows and recomputes the canonical `cves` row from scratch on **every** source write; per-field precedence; FTS document rebuild. Ingest fan-in drives frequency. |
| alert evaluator + DSL | **HOT** | Realtime path fires on every CVE upsert where `material_hash` changes; regex rules scan up to a 5,000-candidate cap; batch + EPSS paths sweep the corpus by cursor. |
| feed adapters + ingest | **HOT (IO)** | Streaming `json.Decoder` Token/More over large upstream feeds; per-adapter rate limiters; EPSS two-statement + FNV advisory lock. |
| search / CVE read / watchlist | **HOT (read)** | FTS on a separate 1:1 `cve_search_index` (GIN); keyset pagination composite cursor; facets; watchlist matching. |
| notify delivery + worker pool | **WARM** | Fan-out `sync.WaitGroup`; webhook HTTP (network is the real cost — orchestration here); job-queue goroutine pool. |
| security-event pipeline + rate limit | **WARM** | Per-request rate-limit check + async event writer (runs on the request path, bounded work). |
| reports / AI / retention | **WARM** | Scheduled-report aggregation queries; LLM calls (external-process boundary → orchestration); retention batch deletes. |
| frontend hot views/components | **WARM** | CVE list/table rendering over large result sets; data-fetch + reactivity; `components/ui/**` shadcn primitives are **cold** glue. |
| auth/SCIM/OAuth/admin/infra glue | **COLD** | CRUD, token verification, DI/middleware wiring, config, crypto setup, doctor checks — no load-scaling work. The bulk of `internal/api` by LOC. |

"No hot path" is **not** the outcome here — this is a real IO service with a genuine hot core
(merge/alert/feed/search) and a large cold-glue tail (auth/SCIM/admin), exactly the shape the COLD
SWEEP exists for.

## 4. Slice partition (disjoint coverage at file granularity)

Tiers: **FULL** = 6 core lanes (algorithmic, memory, data-access, concurrency, idiom-currency,
cost-map). **REDUCED** = algorithmic, memory, data-access, concurrency (+ idiom-currency where a
framework surface exists). **COLD SWEEP** = algorithmic, memory, data-access over batched glue.
SQL companion pack loads alongside data-access for every Go slice touching `store`/queries/DDL.

| Slice | Tier | Primary scope (owned files) | Adjacent context |
|---|---|---|---|
| **S1 Merge & corpus write** | FULL | `internal/merge/**`, `internal/store/cve.go` | `queries/cves.sql`, `queries/vendor_enrichment.sql`, migrations DDL for `cves`/`cve_sources`/`cve_search_index`/`epss_staging` |
| **S2 Alert engine** | FULL | `internal/alert/**`, `internal/alert/dsl/**`, `internal/store/{alert_rule,dsl_executor,alert_rule_channel}.go` | `queries/alert_rules.sql`, `queries/alert_rule_channels.sql` |
| **S3 Feed ingestion & adapters** | FULL | `internal/feed/**`, `internal/ingest/**`, `internal/store/feed.go` | `queries/feed.sql`; adapters audited as a **pattern family** (2–3 representative + the shared `feed` base + `generic`) |
| **S4 Search, CVE read & watchlist** | FULL | `internal/api/{cves,saved_searches,alert_events,watchlists,alert_rules}.go`, `internal/store/{saved_search,watchlist}.go` | `queries/{cves(read),saved_searches,watchlist}.sql`, FTS/keyset indexes in migrations |
| **S5 Async delivery & per-request overhead** | REDUCED | `internal/{notify,worker,secure}/**`, `internal/store/{notification_channel,notification_delivery,report_channel,jobs,security_events}.go`, `internal/api/{deliveries,channels,ratelimit,org_ratelimit,scim_ratelimit,lockout,admin_security_events,admin_deliveries}.go` | `queries/{notification_channels,notification_deliveries,report_channels,jobs,security_events}.sql` |
| **S6 Reports / AI / retention** | REDUCED | `internal/{ai,retention}/**`, `internal/store/{scheduled_report,ai,retention}.go`, `internal/api/{reports,ai}.go` | `queries/{scheduled_reports,ai_cache,ai_request_log,ai_usage,retention}.sql` |
| **S7 Frontend (Vue SPA)** | REDUCED | `web/src/**` **except** `web/src/components/ui/**` | `web/src/components/ui/**` (shadcn primitives — **cold sub-region**, sweep-lite); `vite.config.ts` |
| **S8 AuthN/MFA/SSO/OAuth glue** | COLD SWEEP | `internal/api/{auth,auth_mfa,auth_password_reset,auth_email_verification,sso,oauth_oidc,oauth_github,oauth_google,oauth_helpers,apikeys,lockout,middleware_auth,middleware_apikey_query,middleware_csrf}.go`, `internal/auth/**`, `internal/store/{auth,mfa,apikey,sso,password_reset,email_verification}.go` | `queries/{auth,mfa,apikeys,sso,password_reset,email_verification}.sql` |
| **S9 Org/SCIM/admin/tenant glue** | COLD SWEEP | `internal/api/{orgs,groups,org_tier,scim_users,scim_groups_handler,scim_admin,scim_types,scim_discovery,scim_roles,scim_notif_sync,middleware_scim,admin_users,admin_orgs,admin_mfa,admin_system,admin_version,admin_reload,admin_doctor,audit_log,tier_cache,org_ratelimit?,middleware_rbac,middleware_site_admin,middleware_tier,org_tier,role}.go`, `internal/{audit,tier}/**`, `internal/store/{org,group,scim_groups,scim_config,admin_org,admin_user,admin_delivery,admin_system,audit}.go` | `queries/{org,groups,scim_groups,scim_config,admin_orgs,admin_users,admin_deliveries,admin_system,audit_log}.sql` |
| **S10 Platform/infra glue** | COLD SWEEP | `cmd/**`, `internal/{config,crypto,doctor,metrics,dbutil,log}/**`, `internal/api/{server,cors,readyz,spa,contract,metrics_middleware,log_middleware,middleware_cache,context,feeds,ingest,openapi_spec}.go` | — |
| **O1 Ingest→merge→alert→notify** | OVERLAY (analysis-only) | the end-to-end ingest pipeline spanning S3→S1→S2→S5 | not a coverage unit; runs after its members |

**Coverage reconciliation:** every `*.go` production file and `web/src` file maps to exactly one
of S1–S10. `internal/api/org_ratelimit.go` is assigned to **S9** (org-scoped) and removed from S5's
list to keep disjoint (S5 keeps the generic `ratelimit.go` + `scim_ratelimit.go`). The
file-by-file reconciliation is run at the start of each slice (`git ls-files` vs the owned globs);
drift (renames/adds since the planning SHA) is re-homed, not dropped.

**Out of scope (explicit):** `internal/testutil/**`, `internal/store/generated/**` (generated —
covered via its `.sql` sources in the owning slice's adjacent context), `*_test.go`, `web` test
files, `openapi.json`/`openapi/` artifacts, `docker/`, `deploy/`, `.github/`.

## 5. Cross-slice frequency calibration (demand-driven, fail-safe)

Triggered only where a slice's hot symbol is *driven* from another slice:

| Impl (slice) | Frequency driver (slice) | Class | Mitigation |
|---|---|---|---|
| `store/cve.go` upsert + merge (S1) | ingest loop in `internal/ingest` (S3) | per-source-row, per-feed-batch | **Order S3-adjacent map before S1**; pass ingest fan-in rate as adjacent context to S1 |
| alert realtime eval (S2) | merge upsert emitting `material_hash` change (S1) | per-changed-CVE | S1 runs before S2; note "fires per upsert with changed hash" to S2 |
| notify fan-out (S5) | alert event insert (S2) | per-alert-event per-channel | note to S5; alert→notify is the O1 overlay's spine |
| rate-limit check (S5) | every API request (all API slices) | per-request | tag S5 rate-limit finding **assume-hot** (per-request) |

No unresolved out-of-tree driver is ranked top without the roll-up surfacing it for confirmation.

## 6. Execution order (hottest first; frequency-establishers before impl; overlay after members)

`S3 → S1 → S2 → S4 → S5 → S6 → S7 → O1 → S8 → S9 → S10 → roll-up`

(S3 ingest establishes S1's frequency; S1 establishes S2's; S2 establishes S5's notify frequency;
O1 after S1/S2/S3/S5; cold sweeps S8–S10 last; roll-up conditionally REQUIRED — the request is a
**posture** question ("audit the whole repo"), so the cross-slice roll-up is required.)

## 7. Verification mode

**Static-only / deferred** for all slices in this run: the container has Go 1.26 but integration
tests + the `dynamic` lane need Docker/testcontainers (per CLAUDE.md, a hard blocker when absent)
and a production-like corpus/load that does not exist locally. Fix plans therefore rely on
**complexity/allocation arguments**, never fabricated numbers. `go build`/`go vet`/`golangci-lint`
*are* available for correctness guards. This is recorded so no finding claims `Measured` it can't back.

---

## 8. Progress ledger (resumable — the job must survive a container restart)

**How to resume:** read this plan + the ledger below; pick the first slice whose state ≠ DONE; run
`performance-audit` at its tier (lanes write to `docs/perf-audits/`); cross-validate; write the
validated report; flip the row to DONE with artifact paths; commit. After the last slice, write the
roll-up. Run ledger: `docs/perf-audits/runs.jsonl` (one line per executed run).

| Slice | Tier | State | Artifacts |
|---|---|---|---|
| S3 Feed ingestion & adapters | FULL | **DONE** | `2026-06-05-s3-feed-ingest-consolidated.md` + 6 lane reports + bug-hunt-kickoff |
| S1 Merge & corpus write | FULL | **DONE** | `2026-06-05-s1-merge-consolidated.md` + 6 lane reports |
| S2 Alert engine | FULL | **DONE** | `2026-06-05-s2-alert-consolidated.md` + 6 lane reports + bug-hunt-kickoff |
| S4 Search, CVE read & watchlist | FULL | **DONE** | `2026-06-05-s4-search-consolidated.md` + 6 lane reports + bug-hunt-kickoff |
| S5 Async delivery & per-request overhead | REDUCED | **DONE** | `2026-06-05-s5-delivery-consolidated.md` + 4 lane reports + bug-hunt-kickoff |
| S6 Reports / AI / retention | REDUCED | **DONE** | `2026-06-05-s6-reports-consolidated.md` + 4 lane reports + bug-hunt-kickoff |
| S7 Frontend (Vue SPA) | REDUCED | **DONE** | `2026-06-05-s7-frontend-consolidated.md` + 5 lane reports + bug-hunt-kickoff |
| O1 Ingest→merge→alert→notify | OVERLAY | PENDING | |
| S8 AuthN/MFA/SSO/OAuth glue | COLD | **DONE** | `2026-06-05-s8-authglue-consolidated.md` + 3 lane reports |
| S9 Org/SCIM/admin/tenant glue | COLD | **DONE** | `2026-06-05-s9-orgglue-consolidated.md` + 3 lane reports |
| S10 Platform/infra glue | COLD | **DONE** | `2026-06-05-s10-infraglue-consolidated.md` + 3 lane reports |
| Roll-up | — | PENDING | |

---

## 9. Adversarial partition review (≥3 rounds — slice count is 10+overlay, the 6–12 band requires a
partition-design lens; Sam additionally mandated ≥3 rounds)

Each round attacks the partition grounded in the actual inventory above. Revisions applied inline to
§4–§6; the round notes below record what changed and why.

### Round 1 — general + sizing lens
- **Attack: S3 (feed+ingest ≈ 6.3k) exceeds the Go band (2–6k).** Real concern. **Resolution:** the
  10 adapters are a **homogeneous pattern family** (~400–600 LOC each, same `FeedAdapter` shape), so
  per the split/keep rule they KEEP together and the lanes sample 2–3 representative adapters + the
  shared base + `generic` rather than walking all ten — this is pattern-level auditing, not a
  per-adapter sweep. Kept as one FULL slice; flagged for mid-execution re-slice (split adapters from
  ingest) only if the run reports it too big.
- **Attack: store (7.1k) is sliced by domain across S1/S2/S4/S5/S6/S8/S9 — risk of double-count or
  gap.** **Resolution:** added the file-granularity reconciliation rule (§4) and assigned each
  `store/*.go` to exactly one slice by its primary frequency driver; `org_ratelimit.go` de-duped to
  S9. Coverage ledger is disjoint.
- **Attack: S7 frontend (9.2k) is >2× the TS band.** **Resolution:** carved `components/ui/**`
  (shadcn primitives, cold glue) into a cold sub-region inside S7; the audited app surface (views +
  stores + composables + real components) is ~5–6k, REDUCED tier. Pre-split documented; further
  split available mid-run.

### Round 2 — hot-path accuracy lens (verify/refute imaginary, find missed)
- **Attack: is "merge is hot" verified against code, or inferred from the name?** **Resolution:**
  grounded in CLAUDE.md's code-level architecture note ("merge re-reads all `cve_sources` and
  recomputes from scratch on every source write — not incremental") + the `internal/merge` LOC and
  `store/cve.go` presence. This is a structural certainty, not a name guess. Confirmed HOT.
- **Attack: missed hot path?** Reconsidered `internal/secure` rate limiting — it runs on **every API
  request**, hotter than its WARM tier suggests. **Resolution:** kept S5 REDUCED (bounded per-request
  work) but added the cross-slice frequency note tagging the rate-limit finding **assume-hot
  (per-request)** so it isn't under-ranked. Also confirmed FTS/keyset (S4) is genuinely hot-read, not
  cold CRUD — split it OUT of the cold API sweep into its own FULL slice.
- **Attack: is the AI subsystem mis-tiered?** LLM latency dominates but is an **external-process
  boundary** — the Go code is orchestration. **Resolution:** S6 REDUCED with an explicit
  external-process note (audit the orchestration/batching/caching, not the model latency). Correct.

### Round 3 — partition-design lens (REQUIRED at this slice count): cross-slice calibration the
hot-path rounds miss
- **Attack: S1 (merge impl) and S3 (ingest, its frequency driver) are split — S1 will under-rank its
  own findings because it can't see ingest fan-in.** This is exactly the defect a hot-path-only review
  misses. **Resolution:** added §5 cross-slice frequency map; **reordered execution so S3 precedes
  S1** and S1 receives the ingest fan-in rate as adjacent context. Same fix chains S1→S2 (merge
  drives realtime alert) and S2→S5 (alert drives notify fan-out).
- **Attack: the alert→notify→delivery hot spine is spread across S2 and S5 — a buffering/batching
  theme there is invisible in any single slice.** **Resolution:** added **O1 overlay** (analysis-only,
  after members) to recover the end-to-end ingest→merge→alert→notify cost, plus the §9 roll-up to
  surface cross-slice themes (this is a posture question → roll-up is REQUIRED).
- **Attack: language mis-bucketing — SQL is split from its Go drivers.** **Resolution:** per the
  one-primary-ecosystem rule, hand-written SQL stays **with its Go driver slice** as adjacent context
  (SQL companion sub-lane on the data-access lane), never carved into a separate slice. DDL/indexes in
  `migrations/` are pulled into whichever slice queries those tables. No separate SQL slice.
- **Residual nits only** (e.g., exact home of `org_ratelimit.go`) — resolved inline. Partition
  **finalized**; further re-slicing only via the mid-execution one-shot rule, recorded in the ledger.

**Verdict:** partition is disjoint, hot-core-accurate, cross-slice-calibrated, and resumable.
Proceeding to execution in the §6 order.
