# Health Review Remediation — Agent Team Starting Prompt

> **Usage:** Copy everything below the line into a fresh Claude Code session to kick off the remediation run.

---

## Starting Prompt

I need you to execute the health review remediation plan at `dev/plans/2026-03-10-health-review-remediation.md`. This addresses 45 findings from the project health review at `dev/health-reviews/2026-03-10-project-health-review.md`.

### Context

- We're on the `dev` branch. Create a working branch `health-review-remediation` before starting.
- The plan has 6 phases, all fully detailed with exact code, files, tests, and commit messages.
- Execute phases in order. Each phase has its own execution strategy below.
- Task 5A is superseded by a separate plan — skip it.
- Task 6C is deferred (depends on Phase 3) — skip it.
- Task 6D is invalidated — skip it.

### Phase 1: Agent Team (parallel)

Create an agent team with **4 teammates** to execute Phase 1 in parallel:

| Teammate | Name | Tasks | Focus |
|----------|------|-------|-------|
| 1 | `fixes-core` | 1.1, 1.2, 1.3, 1.4 | `cmd/cvert-ops/main.go` changes (server close, DB close, cookie validation, worker context) |
| 2 | `fixes-cleanup` | 1.5, 1.6, 1.7, 1.8 | Dead code removal, comment fix, test assertion, test error handling |
| 3 | `fixes-test-api` | 1.9, 1.10 | Test state mutation fix, API parameter validation |
| 4 | `fixes-refactor` | 1.11, 1.12 | sqlc rename (large blast radius), toNullString dedup |

#### Instructions for ALL teammates

1. **Read the full task section** from `dev/plans/2026-03-10-health-review-remediation.md` before starting each task. The plan has exact code, exact files, and exact test commands.
2. **Read the "Subagent Execution Guidance" section** at the top of the plan — it has 7 rules you must follow.
3. **Follow TDD** where the plan specifies it (Tasks 1.3, 1.7, 1.10): write the failing test first, run it, see it fail, then implement.
4. **One commit per task** with the exact commit message from the plan. Don't batch commits.
5. **Run only the test commands specified** in each task — not `go test ./...`.
6. **Match existing code style**: tabs, lowercase error messages, `// ` comments with a space.
7. **Don't change anything not specified** in your task. Don't "improve" surrounding code.
8. **When the plan says "delete," delete.** Don't comment out or rename with underscore.
9. **Read referenced files before editing.** Line numbers may have shifted from prior teammates' commits.
10. After completing all your assigned tasks, message the lead to report completion.

#### Teammate-specific warnings

- **`fixes-refactor` (Tasks 1.11, 1.12):** Task 1.11 (sqlc `Cfe` → `CVE` rename) has a **large blast radius**. Every file referencing `generated.Cfe` types must be updated. Search exhaustively and verify with `go build ./...` before committing. Task 1.12 creates a new file `internal/dbutil/null.go` — only extract the duplicated helpers listed in the plan, not single-use helpers like `toNullFloat64`.
- **`fixes-core` (Task 1.3):** This is a TDD task. Write the failing test first, confirm it fails, then implement the validation.
- **`fixes-cleanup` (Task 1.7):** This is a TDD task. Write the assertion test first, confirm it fails, then add the assertion.
- **`fixes-test-api` (Task 1.10):** This is a TDD task. Write the failing validation test first, then implement.

#### After Phase 1 (lead coordinates)

Once all 4 teammates report completion:

1. **Integration check** — run these in sequence:
   ```bash
   go build ./...
   golangci-lint run
   go test ./...
   ```
2. **Resolve any conflicts.** Task 1.11 (sqlc rename) may conflict with tasks that touch generated types. If so, re-run `sqlc generate` and update references.
3. **Commit any fixups** needed from integration.

---

### Phase 2: Lead executes sequentially

Phase 2 has dependencies between tasks, so execute sequentially as the lead — no teammates needed.

**Phase 2A — RLS Security Fix** (independent, do first):
- Task 2A.1: Switch app service to `cvert_ops_app` role (security-critical — don't touch migrate service)
- Task 2A.2: Write RLS cross-tenant integration test

**Phase 2B — Alert Evaluator Refactoring** (can overlap with 2A):
- Task 2B.1: Extract shared post-filter logic to `dsl.ApplyPostFilters` (TDD)
- Task 2B.2: Merge `queryCandidates` and `queryCandidatesAll` (depends on 2B.1)
- Check if Phase 8B Observe added metric instrumentation near `applyPostFilters` or `queryCandidates`. If so, preserve metrics in the refactored code.

**Phase 2C — Wire Alert Evaluation** (depends on 2B):
- Task 2C.1: Register batch/EPSS/zombie-sweep as scheduled worker jobs
- Task 2C.2: Wire `EvaluateRealtime` as post-merge hook (must fire AFTER merge transaction commits)
- **Critical constraint:** Alert evaluation failures must NOT fail feed ingestion — log and continue

**Final verification after Phase 2:**
```bash
go build ./...
golangci-lint run
go test ./...
```

---

### Phase 3: Chi→Huma Migration (sequential, lead executes)

This is the largest phase. Execute Task 3.0 (Groups reference migration) first — it establishes the exact pattern. Then migrate each subsequent handler file one at a time following the reference.

**Read the "Key Decisions" section** at the top of Phase 3 in the plan before starting. These 8 decisions are locked in and apply to every handler migration. Do NOT deviate.

**Execution order:** 3.0 (Groups), then 3.1–3.12 in the order listed. Each migration is one commit. Each includes the frontend update in the same commit.

**After each handler migration:**
```bash
go build ./...
go test ./internal/api/ -v -count=1
cd web && npm run type-check
```

**After all handlers are migrated,** execute the post-migration cleanup (delete orgFetch, delete writeJSON, regenerate types).

---

### Phase 4: Ops Hardening (sequential, lead executes)

Two independent tasks:
- Task 4D: Notification worker semaphore eviction
- Task 4E: Configurable long-operation statement timeout

Both are detailed with exact code in the plan.

---

### Phase 5: Test Quality (sequential, lead executes)

Three tasks (skip 5A — it's superseded by the fixture corpus plan):
- Task 5B: Ingest handler integration test (real merge + real DB)
- Task 5C: Email testcontainer with header injection verification
- Task 5D: Advisory lock concurrency test

All need Docker for testcontainers. If Docker is unavailable, skip this phase and report it.

---

### Phase 6: Architecture (sequential, lead executes)

Four tasks (skip 6C and 6D):
- Task 6A: Replace Set*Deps with ServerDeps options struct
- Task 6B: Add health reporting to notification worker
- Task 6E: Extract MergeStore interface
- Task 6F: Refactor BootstrapFirstUserOrg to use withBypassTx

Execute in order. Each is one commit.

**Final verification after Phase 6:**
```bash
go build ./...
golangci-lint run
go test ./...
cd web && npm run test:unit && npm run type-check && npm run lint
```

---

### Key Files Reference

| File | Tasks |
|------|-------|
| `dev/plans/2026-03-10-health-review-remediation.md` | The plan — read each task section before executing |
| `dev/health-reviews/2026-03-10-project-health-review.md` | Original findings with evidence and context |
| `cmd/cvert-ops/main.go` | 1.1, 1.2, 1.3, 1.4, 2C.1, 2C.2, 6A |
| `internal/alert/evaluator.go` | 1.5, 2B.1, 2B.2, 4E |
| `internal/store/cve.go` | 1.6 |
| `internal/store/dsl_executor.go` | 1.7, 2B.1 |
| `internal/store/store_test.go` | 1.8 |
| `internal/feed/util.go` + `util_test.go` | 1.9 |
| `internal/api/cves.go` | 1.10, Phase 3 reference |
| `sqlc.yaml` | 1.11 |
| `internal/merge/pipeline.go` | 1.12, 2C.2, 6E |
| `internal/store/ai.go` | 1.12 |
| `internal/store/watchlist.go` | 1.12 |
| `docker/init.sql` + `docker/compose.yml` | 2A.1 |
| `internal/ingest/scheduler.go` | 2C.1 |
| `internal/ingest/handler.go` | 2C.2, 5B |
| `internal/api/groups.go` | 3.0 (reference migration) |
| `internal/api/server.go` | 3.0–3.12, 6A |
| `internal/notify/worker.go` | 4D, 6B |
| `internal/config/config.go` | 4E |
| `internal/store/store.go` | 4E, 6F |
| `internal/notify/email_test.go` | 5C |
| `internal/testutil/smtp.go` | 5C |
| `internal/merge/pipeline_integration_test.go` | 5D |
| `internal/store/org.go` | 6F |

### What NOT to Do

- Don't run `go test ./...` during individual Phase 1 tasks — only the specific test commands in each task
- Don't modify files not listed in a task
- Don't add comments explaining that code was "refactored" or "improved"
- Don't skip TDD steps — write the failing test first where specified
- Don't amend commits — one new commit per task
- Don't change the migrate service's DATABASE_URL in Task 2A.1
- Don't push to remote — leave that for Sam to review first
- Don't execute Task 5A (superseded), Task 6C (deferred), or Task 6D (invalidated)
