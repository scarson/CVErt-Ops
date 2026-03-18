# Phase 4 DSL FTS Extension — Test Coverage Review

**Date:** 2026-03-03
**Scope:** FTS-related additions only (Phase 4)
**Files reviewed:** 9

---

## File: `internal/alert/dsl/field.go`

### `kindFTS` field registration (line 16, line 38, line 55)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| `kindFTS` constant definition | 16 | Covered (`TestCompile_FTSQuery` compiles with this kind) | — |
| `ftsOps = []string{"matches"}` | 38 | Covered (`TestValidate_FTSQuery_InvalidOp` proves only "matches" is valid) | — |
| `fts_query` field registration in `fields` map | 55 | Covered (`TestCompile_FTSQuery`, `TestValidate_FTSQuery`) | — |

### `ExportFieldDescriptions()` — `kindFTS` case (line 95-96)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| `kindFTS` switch case returns "full-text search" | 95-96 | Covered (`TestExportFieldDescriptions` checks `fts_query` TypeDesc = "full-text search") | — |
| `fts_query` appears in exported descriptions list | 55 | Covered (`TestExportFieldDescriptions` checks expected fields list includes `fts_query`) | — |

---

## File: `internal/alert/dsl/types.go`

### `Joins` field on `CompiledRule` (line 40)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| `Joins []string` populated when FTS conditions exist | 40 | Covered (`TestCompile_FTSQuery` asserts `len(compiled.Joins) == 1`) | — |
| `Joins` empty when no FTS conditions | 40 | Covered (`TestCompile_NoJoinsWithoutFTS` asserts `len(c.Joins) == 0`) | — |

---

## File: `internal/alert/dsl/compiler.go`

### `Compile()` — FTS join generation (lines 92-98)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| FTS condition detected, single join appended | 94-96 | Covered (`TestCompile_FTSQuery` asserts exact join string) | — |
| `break` after first FTS join (dedup for multiple FTS conditions) | 97 | Covered (`TestCompile_FTSJoinDedup` uses 2 FTS conditions, asserts 1 join) | — |
| No FTS conditions: joins remains empty | 92-98 | Covered (`TestCompile_NoJoinsWithoutFTS`) | — |

### `conditionToSQL()` — `kindFTS` case (lines 179-184)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Valid FTS string: generates `websearch_to_tsquery('english', ?)` | 183-184 | Covered (`TestCompile_FTSQuery` asserts `fts_document` in SQL and args contain the search string) | — |
| FTS value unmarshal error (non-string) | 181-182 | GAP | correctness |
| SQL injection via FTS query value (adversarial input to websearch_to_tsquery) | 184 | GAP | security-critical |

---

## File: `internal/alert/dsl/validator.go`

### `validateValue()` — `kindFTS` case (lines 186-194)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Valid string value (happy path) | 187-191 | Covered (`TestValidate_FTSQuery`) | — |
| Non-string value (unmarshal fails) | 188-190 | Covered (`TestValidate_FTSNonStringValue` with value `123`) | — |
| Empty string value | 192-194 | Covered (`TestValidate_FTSQuery_EmptyValue`) | — |
| Invalid operator for fts_query | 60-68 | Covered (`TestValidate_FTSQuery_InvalidOp` with op `"eq"`) | — |
| EPSS flags: fts_query sets `allEPSS = false` | 52-54 | Covered (`TestValidate_FTSQuery` asserts `isEPSSOnly=false`) | — |

### `fts_query` as selective field (line 21)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| `fts_query` + regex passes selective guard | 21, 56-58, 98-105 | GAP — no test combines fts_query + regex to prove fts_query counts as selective | correctness |

---

## File: `internal/alert/evaluator.go`

### `queryCandidates()` — Joins loop (lines 435-437)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Joins loop applies compiled joins to squirrel builder | 435-437 | GAP — no integration test with real FTS join | security-critical |
| FTS join combined with candidate IDs filter | 438-441 | GAP | correctness |
| Build query error with joins | 442-443 | GAP | nice-to-have |

### `queryCandidatesAll()` — Joins loop (lines 484-486)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Joins loop for DryRun all-CVE query | 484-486 | GAP — no integration test with FTS DryRun | correctness |
| FTS join for full-corpus query | 487-490 | GAP | correctness |

---

## File: `internal/store/dsl_executor.go`

### `ExecuteDSLQuery()` — Joins loop (lines 127-129)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Compiled joins applied to query builder | 127-129 | GAP — no test with FTS joins | correctness |

### `ExecuteDSLQuery()` — Limit clamping (line 119-121)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| `limit <= 0` clamped to 25 | 119-121 | GAP | correctness |
| `limit > 100` clamped to 25 | 119-121 | GAP | correctness |
| Normal limit (1-100) passes through | 119-121 | Covered | — |

### `ExecuteDSLQuery()` — compiled.SQL nil check (line 132-134)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| `compiled.SQL != nil` applies WHERE clause | 132-134 | Covered | — |
| `compiled.SQL == nil` skips WHERE clause | 132-134 | GAP | correctness |

### `decodeDSLCursor()` (lines 97-110)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Empty string input → zero cursor | 98-100 | Covered | — |
| Valid base64 JSON → decodes correctly | 101-109 | Covered | — |
| Invalid base64 input | 101-103 | GAP | security-critical |
| Valid base64 but invalid JSON | 106-108 | GAP | security-critical |
| Crafted cursor to bypass keyset pagination | 144-149 | GAP | security-critical |

### `encodeDSLCursor()` (lines 87-93)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Successful encode (happy path) | 87-93 | Covered | — |
| Roundtrip: encode then decode | 87-110 | GAP | correctness |

### `ExecuteDSLQuery()` — Partial cursor

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Partial cursor (SortDate set, CVEID empty) | 144 | GAP | correctness |

### `ExecuteDSLQuery()` — Next page detection (lines 181-191)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| More results than limit: trim and return cursor | 181-190 | Covered | — |
| Exactly limit or fewer: empty cursor | 181 | Covered | — |
| encodeDSLCursor error during next-page | 188-189 | GAP | nice-to-have |

### `ExecuteDSLQuery()` — Status filtering (line 137)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Rejected/withdrawn CVEs excluded | 137 | Covered | — |

### `scanCVERow()` (lines 50-78)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Successful scan of all columns | 52-77 | Covered | — |
| Scan error (column mismatch) | 52-74 | GAP | nice-to-have |

---

## Summary

| Severity | Count |
|----------|-------|
| Security-critical | 4 |
| Correctness | 8 |
| Nice-to-have | 3 |
| **Total** | **15** |
