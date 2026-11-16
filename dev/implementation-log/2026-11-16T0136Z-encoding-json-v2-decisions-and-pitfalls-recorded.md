# encoding/json/v2 decisions and pitfalls recorded

## What was built

| Feature | Files | Description |
|---|---|---|
| Pitfall entries | `dev/implementation-pitfalls.md` | FEED-24 (feed adapters stay on v1 `encoding/json`), API-14 (a value validated by the API and used by a worker is decoded by one shared function), API-15 (huma's validator and the v2 request decoder must match member names the same way; security), API-16 (v2 options do not reach `UnmarshalJSON([]byte)`; use `UnmarshalJSONFrom`), API-17 (`omitzero` on a pointer-to-scalar needs `nullable:"false"` in huma; v2 `omitempty` omits a `json.RawMessage` holding `{}`, `null` or `[]`), ARCH-48 (v2 map key order; hash inputs stay on v1 with RFC 8785 canonicalization). Review checklists for §1, §4 and §6, See Also blocks in §3, §4 and §5, the Appendix A.2 changelog row and Appendix B rows updated. Commit `6a3733c`. |
| PLAN.md | `PLAN.md` §10.5, §11.1, §11.3, §16 | §10.5: a "shipped without a bump" bullet for strict decoding of stored conditions. §11.1: config keys per channel type, refusal of other keys, header and recipient rules, one parser at the API and delivery. §11.3: reserved headers refused rather than dropped. §16: strict request decoding (case-sensitive names; duplicates, trailing data and invalid UTF-8 refused), exact huma validation, the SCIM exception, `[]`/`{}` for empty response collections, 400 `invalid cursor`. Commit `6a3733c`. |

## Key decisions

- **Section placement.** API-14 is in §4, not §5: the defect is the API's validation reading the value differently from delivery, and §4 holds the related POST/PATCH parity entry (API-9); §5's See Also points to it. API-15 is in §4 (request validation) with a pointer from §3's See Also. ARCH-48 sits next to ARCH-47, the other hash-input entry.
- **`Deterministic(true)` is not enough for stored hashes.** `go doc encoding/json/v2 Deterministic` (go1.27.4) guarantees equal bytes only across instances of one binary, not across builds or toolchain versions. ARCH-48 states this, which is why `material_hash` keeps RFC 8785 canonicalization.
- **Entry ranges corrected beyond the touched sections.** The Table of Contents and Appendix B listed FEED-20, DB-26, AUTH-25 and ARCH-45 as the last entries; the document holds FEED-23, DB-27, AUTH-26 and ARCH-47. All ranges now match, and the Appendix B total is ~167.
- **"Last validated" line unchanged.** Appendix C does not ask for it to be updated when entries are added.
- **testing-pitfalls.md unchanged.** The tests that guard the new entries (`TestResponseEncoding`, `TestHumaBodyMemberNamesMatchExactly`, the channel config parser tests) are named in the entries themselves.

## Gotchas discovered

- `internal/feed/redhat/adapter.go` has the only remaining `UnmarshalJSON([]byte)` methods (`affectedReleaseList`, `packageStateList`); they are on the v1 feed path, so API-16 does not apply to them.

## Quality checks

- Documentation only; no code changed and no tests run.
- Full suite not run (the coordinator runs it).
