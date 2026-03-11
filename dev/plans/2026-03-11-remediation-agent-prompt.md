# Health Review Remediation — Agent Team Starting Prompt

> **Usage:** Copy everything below the line into a fresh Claude Code session to execute the remediation plan.

---

## Starting Prompt

I need you to execute the health review remediation plan at `dev/plans/2026-03-10-health-review-remediation.md`. This addresses 45 findings from the project health review at `dev/health-reviews/2026-03-10-project-health-review.md`.

### Context

- We're on the `dev` branch. All Phase 8 worktrees have been merged.
- The plan has 6 phases. **Phase 1** (12 independent quick-fix tasks) and **Phase 2** (critical security + alert pipeline) are fully detailed with code. Phases 3-6 are outlined and need their own detailed plans when we reach them.
- **Phase 1 tasks are fully independent** — dispatch all 12 as parallel subagents using `superpowers:dispatching-parallel-agents`.
- **Phase 2 has dependencies:** 2A (RLS) is independent. 2B.1 must complete before 2B.2. 2C depends on 2B being done. 2A can run in parallel with 2B.

### Execution Strategy

**Step 1: Create a worktree** for remediation work using `superpowers:using-git-worktrees`. Branch name: `health-review-remediation`.

**Step 2: Execute Phase 1** — Use `superpowers:dispatching-parallel-agents` to run all 12 tasks in parallel. Each task is self-contained in the plan with exact files, code, test commands, and commit messages. The tasks are:

| Task | Finding | Summary |
|------|---------|---------|
| 1.1 | #4 | Add `defer apiSrv.Close()` in runServe |
| 1.2 | #5 | Close `stdlib.OpenDBFromPool` wrappers with defer |
| 1.3 | #12 | Validate `COOKIE_SECURE=true` in production (TDD) |
| 1.4 | #13 | Use `context.WithoutCancel` in worker pool |
| 1.5 | #26 | Delete dead `readTx` method from evaluator |
| 1.6 | #40 | Fix misleading `GetCVEDetail` comment |
| 1.7 | #41 | Add assertion to `TestExecuteDSLQuery_EmptyConditions` |
| 1.8 | #37 | Replace `_` error returns with `require.NoError` in store tests |
| 1.9 | #42 | Fix `DownloadToTemp` test global state mutation |
| 1.10 | #35 | Validate `in_cisa_kev` query parameter |
| 1.11 | #27 | Add sqlc rename directive `Cfe` → `CVE` (large blast radius) |
| 1.12 | #28 | Extract shared `toNullString` to `internal/dbutil` |

**Subagent instructions for each task:**
- Read the full task section from the plan before starting
- Follow TDD where the plan specifies it (Tasks 1.3, 1.7, 1.10)
- One commit per task with the exact commit message from the plan
- Run only the test commands specified — not `go test ./...`
- Match existing code style (tabs, lowercase errors, `//` comments with space)
- Don't "improve" surrounding code — change only what the task specifies
- When the plan says "delete," delete — don't comment out

**⚠️ Task 1.11 warning:** The sqlc `Cfe` → `CVE` rename has a large blast radius. Every file referencing `generated.Cfe` must be updated. The subagent must search exhaustively and verify with `go build ./...` before committing.

**⚠️ Task 1.12 warning:** Creating `internal/dbutil/null.go` is a new file. Only extract the duplicated helpers (`toNullString` value-based and `nullString`/`toNullStringPtr` pointer-based). Do NOT move single-use helpers like `toNullFloat64`.

**Step 3: Review Phase 1 results.** After all 12 subagents complete:
- Run `go build ./...` to verify everything compiles together
- Run `golangci-lint run` to check for lint issues
- Run `go test ./...` to verify no cross-task breakage
- If Task 1.11 (sqlc rename) conflicts with other tasks that touch generated types, resolve by re-running `sqlc generate` and updating references

**Step 4: Execute Phase 2A** (RLS security fix) — can start immediately after Phase 1 review:
- Task 2A.1: Switch app service to `cvert_ops_app` role (security-critical — don't touch migrate service)
- Task 2A.2: Write RLS cross-tenant integration test

**Step 5: Execute Phase 2B** (alert evaluator refactoring) — can run in parallel with 2A:
- Task 2B.1: Extract shared post-filter logic to `dsl.ApplyPostFilters` (TDD)
- Task 2B.2: Merge `queryCandidates` and `queryCandidatesAll` (depends on 2B.1 completing)
- **Phase 8B interaction:** Check if Phase 8B Observe added metric instrumentation near `applyPostFilters` or `queryCandidates`. If so, preserve metrics in the refactored code.

**Step 6: Execute Phase 2C** (wire alert evaluation) — depends on 2B:
- Task 2C.1: Register batch/EPSS/zombie-sweep as scheduled worker jobs
- Task 2C.2: Wire `EvaluateRealtime` as post-merge hook (must fire AFTER merge transaction commits)
- **Critical constraint:** Alert evaluation failures must NOT fail feed ingestion — log and continue

**Step 7: Final verification after Phase 2:**
- `go build ./...`
- `golangci-lint run`
- `go test ./...` (full suite)
- Use `superpowers:verification-before-completion` before claiming done

**Step 8: Stop after Phase 2.** Phases 3-6 need their own detailed plans. Report what was completed, any issues encountered, and whether any Phase 8B metric instrumentation points needed adjustment.

### Key Files Reference

| File | Role |
|------|------|
| `dev/plans/2026-03-10-health-review-remediation.md` | The plan — read each task section before executing |
| `dev/health-reviews/2026-03-10-project-health-review.md` | Original findings with evidence and context |
| `cmd/cvert-ops/main.go` | Tasks 1.1, 1.2, 1.3, 1.4, 2C.1, 2C.2 |
| `internal/alert/evaluator.go` | Tasks 1.5, 2B.1, 2B.2 |
| `internal/store/cve.go` | Task 1.6 |
| `internal/store/dsl_executor.go` | Task 1.7, 2B.1 |
| `internal/store/store_test.go` | Task 1.8 |
| `internal/feed/util.go` + `util_test.go` | Task 1.9 |
| `internal/api/cves.go` | Task 1.10 |
| `sqlc.yaml` | Task 1.11 |
| `internal/merge/pipeline.go` | Task 1.12, 2C.2 |
| `internal/store/ai.go` | Task 1.12 |
| `internal/store/watchlist.go` | Task 1.12 |
| `docker/init.sql` + `docker/compose.yml` | Task 2A.1 |
| `internal/ingest/scheduler.go` | Task 2C.1 |
| `internal/ingest/handler.go` | Task 2C.2 |

### What NOT to Do

- Don't execute Phases 3-6 — they need detailed plans first
- Don't run `go test ./...` during individual subagent tasks — only the specific test commands in each task
- Don't modify files not listed in a task
- Don't add comments explaining that code was "refactored" or "improved"
- Don't skip TDD steps — write the failing test first where specified
- Don't amend commits — one new commit per task
- Don't change the migrate service's DATABASE_URL in Task 2A.1
