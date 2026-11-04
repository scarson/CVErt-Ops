# Phase 6B — Bug Hunting + Phase 6C — Plan Reconciliation

> **Date:** 2026-03-08
> **Commits:** `0926eff`..`020dc66` on `dev`

## What was done

Ran 6 bug hunt passes (3 for Phase 6A security code, 3 for Phase 6B missing-feature code) using exploratory, holistic, and multipass bug hunter skills. Identified 25 bugs across TOCTOU races, anti-enumeration leaks, memory growth, validation gaps, and transaction helper misuse. Consolidated findings into a 13-task bug fix implementation plan.

Separately, reconciled PLAN.md with the implemented API.

## Bug hunting

6 reports in `dev/bug-hunts/`:
- `2026-03-08-phase6a-holistic.md` — lockout case bypass, argon2 semaphore leak, unbounded lockout map growth, password reset TOCTOU
- `2026-03-08-phase6a-security-holistic.md` — anti-enumeration leaks in forgot-password error paths
- `2026-03-08-phase6a-security-multipass.md` — 5-pass deep analysis: contract violations, pattern breaks, state machine gaps, resource lifecycle, config edge cases
- `2026-03-08-phase6b-exploratory.md` — bootstrap registration race, concurrent invitation accept 500s
- `2026-03-08-phase6b-holistic.md` — soft-deleted orgs in `ListAllOrgs`, missing transaction wrappers
- `2026-03-08-phase6b-multipass.md` — PATCH channel empty name validation, invitation duplicate detection, CORS wildcard+credentials

Bug fix plan: `dev/plans/2026-03-08-phase6-bug-fixes.md` — 13 tasks covering all 25 findings

Testing pitfalls: `dev/testing-pitfalls.md` — 8-category checklist distilled from why tests missed these bugs

## PLAN.md reconciliation

- Appendix B rewritten from skeletal skeleton to comprehensive API reference — 60+ endpoints organized by category with role requirements
- Fixed `status` enum: added `withdrawn` (missing from §4.3 but present in implementation)
- Removed corrupt SQL fragment from §18.1
- Updated phase tracker (§18) to reflect Phases 5, Frontend, and 6 as implemented
- Fixed stale cross-references

## Other changes

- `go-chi/cors` promoted from indirect to direct dependency
- Bug hunter skills updated to output to `dev/bug-hunts/` directory
