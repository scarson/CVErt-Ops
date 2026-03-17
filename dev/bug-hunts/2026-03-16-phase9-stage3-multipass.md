# Phase 9 Stage 3 — Multipass Bug Hunt (Frontend Conversion)

**Date:** 2026-03-16
**Scope:** All 33 frontend files (18 Vue consumers, 12 test files, client infrastructure, schema)
**Strategy:** Five focused passes — contract violations, pattern deviations, failure modes, concurrency, error propagation

## Confirmed Bugs

### Bug 1: AdminSystemView doctor 503 responses silently discarded (Medium-High)

**File:** `web/src/views/admin/AdminSystemView.vue`, lines 54 and 76

The `/admin/doctor` endpoint returns 503 with valid JSON body when health checks fail. Both `fetchAll()` and `runDoctor()` only parse the response when `resp.ok` is true (200-299). Since 503 is not in that range, **unhealthy doctor results are silently dropped**.

This means the Health Checks card only shows data when the system is completely healthy — the exact opposite of when users need it most.

**Fix:** Check for parseable body regardless of status code:
```typescript
if (doctorResp.status === 200 || doctorResp.status === 503) {
  doctor.value = (await doctorResp.json()) as DoctorResult
}
```

## Minor Issues

### AdminDeliveriesView `fetchError.status` without optional chaining (Cosmetic)

**File:** `web/src/views/admin/AdminDeliveriesView.vue`, line 105

Uses `fetchError.status === 409` without `?.` optional chaining. Safe at runtime (inside `else` branch where `fetchError` is truthy), but inconsistent with AdminFeedsView and FeedStatusView which use `fetchError?.status`.

## Pre-existing Observations (Not Conversion Bugs)

### InviteMemberDialog vs MembersView role filtering inconsistency

- `MembersView.vue` line 74: admin can assign admin role (`<=`)
- `InviteMemberDialog.vue` line 64: admin cannot invite as admin (`<`)

May be intentional (invite as more privileged operation). Worth verifying.

### AdminDashboardView summary counts are approximations

Fetches with `limit: 1` and shows "1+" when `next_cursor` exists. Very low-fidelity counts by design.

## Pass Results Summary

1. **Contract violations:** Zero. All 18 files use paths matching OpenAPI schema exactly. TypeScript compiler confirms with zero errors.
2. **Pattern deviations:** AdminSystemView intentionally deviates (raw fetch, documented). One cosmetic optional chaining inconsistency.
3. **Failure modes:** Doctor 503 bug is the one failure mode issue. All other files properly guard data/error access.
4. **Concurrency:** No race conditions found. Poll timers properly cleaned up. `coalescedRefresh` handles concurrent 401s correctly.
5. **Error propagation:** Error messages faithfully preserved. `fetchError.detail` usage has proper fallbacks.
