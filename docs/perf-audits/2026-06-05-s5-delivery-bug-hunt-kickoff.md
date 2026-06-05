# Bug-hunt kickoff — suspected bugs from the 2026-06-05 S5 delivery audit

Run: `bug-hunt-cycle` with the scope below.

**Scope:** `internal/notify/worker.go` (delivery worker + semaphore eviction + backoff). Surfaced during S5.

**Seed findings (verify, don't trust):**
- **`evictStaleSemaphores` len-check race can transiently double an org's delivery concurrency cap** —
  `internal/notify/worker.go:403-413`. A check-then-act on the per-org semaphore map under concurrent
  delivery can briefly admit 2× the intended concurrency. Verify the locking around eviction vs acquisition.
- **Uncapped exponential retry backoff** — `internal/notify/worker.go:384`. `backoffSeconds` grows without
  a ceiling; a persistently-failing delivery can schedule retries arbitrarily far out. Confirm a max-backoff cap is intended.

Noticed while auditing performance; NOT investigated. Leads, not confirmed bugs.
