# Health Review Remediation — Agent Team Starting Prompt

> **Usage:** Copy everything below the line into a fresh Claude Code session to kick off the remediation run.

---

## Starting Prompt

I need you to execute the health review remediation plan at `dev/plans/2026-03-10-health-review-remediation.md`. This addresses 45 findings from the project health review at `dev/health-reviews/2026-03-10-project-health-review.md`.

### Context

- We're on the `dev` branch. Create a working branch `health-review-remediation` before starting.
- The plan has 6 phases, all fully detailed with exact code, files, tests, and commit messages.
- Execute in 4 rounds. Each round uses an Agent Team for parallel work, then the lead runs integration checks before the next round.
- Task 5A is superseded — skip it. Task 6C is deferred — skip it. Task 6D is invalidated — skip it.

---

### Round 1: Phase 1 — Quick Wins

Create an agent team with **4 teammates**:

| Teammate | Name | Tasks | Owns (exclusive files) |
|----------|------|-------|----------------------|
| 1 | `fixes-core` | 1.1, 1.2, 1.3, 1.4 | `cmd/cvert-ops/main.go` |
| 2 | `fixes-cleanup` | 1.5, 1.6, 1.7, 1.8 | `evaluator.go`, `cve.go`, `dsl_executor.go`, `store_test.go` |
| 3 | `fixes-test-api` | 1.9, 1.10 | `feed/util.go`, `feed/util_test.go`, `api/cves.go` |
| 4 | `fixes-refactor` | 1.11, 1.12 | `sqlc.yaml`, `dbutil/` (new), `ai.go`, `watchlist.go` |

#### Instructions for ALL teammates (applies to every round)

1. **Read the full task section** from the plan before starting each task.
2. **Read the "Subagent Execution Guidance" section** at the top of the plan — 7 rules to follow.
3. **Follow TDD** where the plan specifies it: write the failing test first, run it, see it fail, then implement.
4. **One commit per task** with the exact commit message from the plan.
5. **Run only the test commands specified** in each task — not `go test ./...`.
6. **Match existing code style**: tabs, lowercase error messages, `// ` comments with a space.
7. **Don't change anything not specified** in your task.
8. **When the plan says "delete," delete.** Don't comment out.
9. **Read referenced files before editing.** Line numbers may shift from other teammates' commits.
10. After completing all assigned tasks, message the lead to report completion.

#### Round 1 warnings

- **`fixes-refactor` (Task 1.11):** sqlc `Cfe` → `CVE` rename has **large blast radius**. Search exhaustively, verify with `go build ./...`.
- **`fixes-refactor` (Task 1.12):** Only extract the duplicated helpers listed in the plan, not single-use helpers.
- **TDD tasks:** 1.3 (`fixes-core`), 1.7 (`fixes-cleanup`), 1.10 (`fixes-test-api`).

#### After Round 1 (lead coordinates)

```bash
go build ./...
golangci-lint run
go test ./...
```
Resolve conflicts (Task 1.11 sqlc rename may conflict with generated type references). Commit fixups.

---

### Round 2: Phase 2 — Security + Alert Pipeline

Create an agent team with **2 teammates**:

| Teammate | Name | Tasks | Execution | Owns (exclusive files) |
|----------|------|-------|-----------|----------------------|
| 1 | `security` | 2A.1, 2A.2 | Parallel (independent) | `docker/init.sql`, `docker/compose.yml`, `rls_test.go` |
| 2 | `alerts` | 2B.1 → 2B.2 → 2C.1 → 2C.2 | Sequential (dependency chain) | `evaluator.go`, `dsl_executor.go`, `scheduler.go`, `handler.go`, `main.go` |

#### Round 2 notes

- **`alerts` teammate:** Execute tasks in strict order. 2B.1 before 2B.2 (post-filter extraction before merge). 2B before 2C (evaluator ready before wiring). Check if Phase 8B Observe added metrics near `applyPostFilters` or `queryCandidates` — preserve them.
- **`security` teammate:** Task 2A.1 is security-critical. Do NOT touch the migrate service's DATABASE_URL.
- **Critical constraint for 2C.2:** Alert evaluation failures must NOT fail feed ingestion — log and continue.

#### After Round 2 (lead coordinates)

```bash
go build ./...
golangci-lint run
go test ./...
```

---

### Round 3: Phase 3 — Chi→Huma Migration

**Step 1: Lead executes Task 3.0 (Groups reference migration) alone.** This establishes the exact pattern all subsequent migrations follow. No team for this step.

Read the **"Key Decisions" section** at the top of Phase 3 in the plan before starting. These 8 decisions are locked in and non-negotiable.

After 3.0 is committed and verified (`go build`, `go test ./internal/api/`, `cd web && npm run type-check`), proceed to Step 2.

**Step 2: Create an agent team with 4 teammates** for the remaining 12 handler migrations:

| Teammate | Name | Tasks | Handler Files |
|----------|------|-------|---------------|
| 1 | `migrate-simple` | 3.1, 3.2, 3.3 | `saved_searches.go`, `apikeys.go`, `channels.go` |
| 2 | `migrate-paginated` | 3.4, 3.5, 3.6 | `watchlists.go`, `alert_rules.go`, `deliveries.go` |
| 3 | `migrate-complex` | 3.7, 3.8, 3.9 | `reports.go`, `orgs.go`, `members.go`, `invitations.go` |
| 4 | `migrate-admin` | 3.10, 3.11, 3.12 | `audit_log.go`, `admin_*.go` |

#### Round 3 instructions (in addition to the general instructions above)

- **Before starting your first task**, read the completed Task 3.0 (Groups) commit to understand the exact reference pattern. Every migration follows it.
- **Each migration is one commit** including both the Go handler rewrite AND the frontend store update.
- **server.go contention:** Each teammate adds `registerXxxRoutes` calls to `server.go`. These are independent lines in the route registration block. If you get a merge conflict on `server.go`, pull the latest and re-add your lines. Do NOT modify another teammate's registration.
- **Frontend type regeneration:** After adding huma operations, the OpenAPI types should be regenerated. Each teammate should run `cd web && npm run type-check` after their migration to verify.
- The **Key Decisions** section in the plan has exact patterns for: RBAC middleware, error codes, list response shape, pagination cursor, PATCH pointer types, Location headers, and frontend migration. Follow them exactly.

#### Round 3 warnings

- **`migrate-paginated` (Task 3.4):** Watchlists already have pagination — migrate to the standard cursor pattern.
- **`migrate-paginated` (Task 3.5):** Alert rules create returns 202 (async activation).
- **`migrate-paginated` (Task 3.6):** Delivery cursor is broken (Finding 43) — fix during migration.
- **`migrate-complex` (Task 3.8):** Tier limit 403 → use `type: "urn:cvert-ops:error:tier-limit-exceeded"` (Finding 34).

#### After Round 3 (lead coordinates)

```bash
go build ./...
golangci-lint run
go test ./...
cd web && npm run test:unit && npm run type-check && npm run lint
```

Then execute the **post-migration cleanup** (delete `orgFetch.ts`, delete `writeJSON`, regenerate OpenAPI types). Commit cleanup separately.

---

### Round 4: Phases 4+5+6 — Ops, Tests, Architecture

These 9 tasks are independent across phases. Run them as one team round, grouped by file ownership to eliminate merge conflicts.

Create an agent team with **4 teammates**:

| Teammate | Name | Tasks | Execution | Owns (exclusive files) |
|----------|------|-------|-----------|----------------------|
| 1 | `notify-arch` | 4D → 6B → 6A | Sequential | `notify/worker.go`, `notify/worker_test.go`, `api/server.go`, `cmd/main.go` |
| 2 | `eval-config` | 4E | Single task | `config/config.go`, `config/config_test.go`, `store/timeout.go` (new), `alert/evaluator.go` |
| 3 | `tests` | 5B, 5C, 5D | Parallel | `ingest/handler_integration_test.go` (new), `testutil/smtp.go`, `notify/email_test.go`, `merge/pipeline_integration_test.go` |
| 4 | `store-merge` | 6E, 6F | Parallel | `merge/store.go` (new), `merge/pipeline.go`, `ingest/handler.go`, `store/org.go` |

#### Round 4 notes

- **`notify-arch`:** Execute 4D first (semaphore eviction), then 6B (health reporting — also modifies `worker.go`), then 6A (ServerDeps — modifies `main.go` and `server.go`). These MUST be sequential within this teammate.
- **`eval-config`:** Task 4E modifies `evaluator.go`, which was already modified by Phase 2B. Read the current state before editing.
- **`tests`:** All 3 tasks create or modify test files only. They need Docker for testcontainers. If Docker is unavailable, skip this teammate's tasks and report it.
- **`store-merge`:** Task 6E modifies `ingest/handler.go` (MergeFunc type), which was modified by Phase 2C.2. Read the current state. Task 6F modifies `store/org.go` independently.

#### After Round 4 — Final Verification (lead coordinates)

```bash
go build ./...
golangci-lint run
go test ./...
cd web && npm run test:unit && npm run type-check && npm run lint
```

Use `superpowers:verification-before-completion` before claiming done.

---

### Key Files Reference

| File | Tasks |
|------|-------|
| `dev/plans/2026-03-10-health-review-remediation.md` | The plan — read each task section before executing |
| `dev/health-reviews/2026-03-10-project-health-review.md` | Original findings with evidence and context |
| `cmd/cvert-ops/main.go` | 1.1, 1.2, 1.3, 1.4, 2C.1, 6A, 6B |
| `internal/alert/evaluator.go` | 1.5, 2B.1, 2B.2, 4E |
| `internal/api/server.go` | Phase 3, 6A |
| `internal/api/groups.go` | 3.0 (reference migration) |
| `internal/api/cves.go` | 1.10, Phase 3 reference |
| `internal/config/config.go` | 4E |
| `internal/ingest/handler.go` | 2C.2, 5B, 6E |
| `internal/ingest/scheduler.go` | 2C.1 |
| `internal/merge/pipeline.go` | 1.12, 2C.2, 6E |
| `internal/merge/pipeline_integration_test.go` | 5D |
| `internal/notify/worker.go` | 4D, 6B |
| `internal/notify/email_test.go` | 5C |
| `internal/store/cve.go` | 1.6 |
| `internal/store/dsl_executor.go` | 1.7, 2B.1 |
| `internal/store/org.go` | 6F |
| `internal/store/store.go` | 4E |
| `internal/store/store_test.go` | 1.8 |
| `internal/testutil/smtp.go` | 5C |
| `docker/init.sql` + `docker/compose.yml` | 2A.1 |
| `sqlc.yaml` | 1.11 |

### What NOT to Do

- Don't run `go test ./...` during individual tasks — only the specific test commands
- Don't modify files not listed in your task
- Don't add comments explaining that code was "refactored" or "improved"
- Don't skip TDD steps — write the failing test first where specified
- Don't amend commits — one new commit per task
- Don't change the migrate service's DATABASE_URL in Task 2A.1
- Don't push to remote — leave that for Sam to review first
- Don't execute Task 5A (superseded), Task 6C (deferred), or Task 6D (invalidated)
- Don't modify files owned by another teammate — if you need a file another teammate owns, wait for them to finish and pull their changes
