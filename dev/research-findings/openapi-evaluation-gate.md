# OpenAPI Evaluation Gate — Decision Record

**Date:** 2026-03-15
**Context:** Phase 9, Stage 3: API Contract Convergence (mandatory pre-execution gate)
**Proposal:** `dev/plans/2026-03-15-phase9-stage3-api-contract-convergence-proposal.md`

---

## Goal

Determine how (or whether) to achieve OpenAPI spec coverage for Chi-backed routes so the frontend can migrate from `orgFetch` to the typed `openapi-fetch` client.

## Candidates Evaluated

### Candidate 1: Spec-only Huma declarations — PASS

**Approach:** Create a separate `huma.API` instance on a throwaway `chi.Router`, register operation declarations using the same DTO types as the Chi handlers but with no-op handler functions. Merge the generated paths and schemas into the production spec during the `TestOpenAPISpec` / `GENERATE_OPENAPI` flow.

**Proof-of-concept:** `internal/api/openapi_spec_gate_test.go` — demonstrates the approach on the full `groups` route family (create, list, get, update, delete, list members, add member, remove member).

**Results against evaluation criteria:**

| Criterion | Result | Evidence |
|-----------|--------|----------|
| OpenAPI 3.1 compatibility | PASS | Huma generates 3.1 natively; merged spec retains `"openapi": "3.1.0"` |
| Drift resistance | MODERATE | Spec-only wrapper types embed the same Go DTO structs (`createGroupBody`, `groupEntry`, etc.) as the Chi handlers. Field definitions have one source of truth. Path params and Huma struct tags are the drift surface — manageable with CI tests that validate spec against runtime routes |
| Chi handler compatibility | PASS | Separate `chi.Router` — zero interference with production routing or middleware |
| Maintenance cost | LOW | One wrapper struct per operation (8 for the full groups family). Adding a field to the DTO is automatic; adding a new endpoint requires one new wrapper + `huma.Register` call |
| Source-of-truth ownership | PASS | Single spec-generation system (Huma). The spec-only instance feeds into the same OpenAPI document. No second generator |

**Key observations:**
- `ErrorModel` and `ErrorDetail` schemas are shared between production and spec-only instances — deduplication works correctly during merge
- `openapi-typescript` generates correct TypeScript types from the merged spec: `GroupEntry`, `CreateGroupBody`, `GroupMemberEntry`, `UpdateGroupBody`, `AddGroupMemberBody`
- Generated types match Go DTO fields exactly (`id`, `name`, `description`, `created_at`)
- Huma adds a `$schema` field (readonly, optional) — harmless for consumers
- No new dependencies required

**Primary risk:** Drift between spec-only Huma wrapper types and Chi handler DTOs. Mitigated by:
1. Wrapper types embed the actual DTO types (single source for field definitions)
2. CI test validates spec paths exist and schemas are well-formed
3. Future: integration tests that exercise the Chi handlers and validate response shapes against the spec

### Candidate 2: Annotation-based generator (swaggo/swag) — FAIL

**Approach:** Generate OpenAPI from Go doc comments on existing Chi handlers.

**Results:**
- swaggo/swag v2 has `--v3.1` flag for OpenAPI 3.1 support
- **Known panics** on custom string types in 3.1 mode (reported December 2025, unresolved)
- **Segfault** on generic slice types with `-v3.1`
- `examples` keyword (required by OAS 3.1) still a feature request
- Introduces a second, independent spec-generation system alongside Huma — violates source-of-truth ownership criterion
- Adds a supply chain dependency with known stability issues to a security product

**Verdict:** Fails on OpenAPI 3.1 compatibility (stability), drift resistance (separate generator), and source-of-truth ownership.

### Candidate 3: Explicit deferral — NOT SELECTED

Deferral was listed as a formal escape hatch in the proposal, not a real option for Phase 9. Finding 8 (dual frontend API client) is a user-visible contract problem. Since Candidate 1 passes, deferral is unnecessary.

---

## Decision

**Candidate 1 (spec-only Huma declarations) is selected** for the Stage 3 implementation plan.

## Implementation Implications

1. **Spec-only registration functions** should be organized per route family (e.g., `registerGroupsSpec(api)`, `registerWatchlistsSpec(api)`, etc.) in dedicated files or a shared spec registration file.

2. **Spec generation flow:** The existing `TestOpenAPISpec` test (or a companion test) creates the spec-only Huma API, registers all spec-only operations, merges paths and schemas into the production spec, and writes the combined `openapi.json`.

3. **Frontend migration:** Each route family's frontend lockstep update should switch from `orgFetch` to the typed `openapi-fetch` client using the generated types. `orgFetch` can be eliminated when all route families are covered.

4. **CI validation:** The spec generation test should verify that every spec-only path exists and that schemas reference the correct DTO types. A future enhancement could validate response shapes at runtime against the spec.

5. **Component schema merging:** Shared types (`ErrorModel`, `ErrorDetail`) exist in both instances. The merge step skips duplicates. Route-family-specific schemas (e.g., `GroupEntry`) are added from the spec-only instance.

---

## Proof-of-Concept Artifacts

- `internal/api/openapi_spec_gate_test.go` — gate evaluation tests (in `openapi-evaluation-gate` branch)
- Generated merged spec: 20 paths (16 production + 4 groups), 30 schemas
- TypeScript type generation: verified via `openapi-typescript 7.13.0`
