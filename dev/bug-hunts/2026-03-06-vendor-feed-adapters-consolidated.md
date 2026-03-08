# Bug Hunt Consolidated Report — Vendor Feed Adapters

**Date:** 2026-03-06
**Sources:** exploratory, holistic, multipass
**Status:** ALL FIXED — branch `feature/vendor-feed-adapters`

## Validated Bugs

### 1. Red Hat adapter never advances AfterDate cursor
**Severity:** significant
**Found by:** multipass (Pass 2)
**Corroborated by:** none (unique find)

**Verdict: CONFIRMED BUG.** When the last page has fewer than `listPageSize` entries, `NextCursor` is nil. The caller persists nothing. On the next scheduled sync, `AfterDate` is whatever it was last set to (or empty on first run), causing a full re-sync every time. MSRC and KEV both always return non-nil cursors.

The `IS DISTINCT FROM` guard in the upsert prevents duplicate DB writes, but every sync re-fetches the entire catalog via HTTP (list pages + 100+ detail requests). This is the highest-priority fix.

---

### 2. KEV enrichment fields not null-byte stripped
**Severity:** significant (defense-in-depth)
**Found by:** holistic
**Corroborated by:** none (unique find)

**Verdict: CONFIRMED BUG.** KEV `recordToPatch` (kev/adapter.go:281-288) marshals `RequiredAction`, `DueDate`, `VendorProject`, `Product`, `Notes` directly into the enrichment map without `StripNullBytes`. These are `string` fields decoded from JSON — if the upstream feed contains `\u0000`, the JSONB column rejects the insert and the merge transaction fails.

Compare: MSRC strips every enrichment string (adapter.go:201, 222, 234, 237, 248). Red Hat strips every enrichment string (adapter.go:287-313). KEV only strips `CVEID`, `ShortDescription`, and CWE IDs — not enrichment fields.

Note: the pipeline itself has no sanitization safety net (`pipeline.go:245` passes `patch.VendorEnrichment.Data` straight to the DB). This is fine as long as all adapters sanitize — but KEV doesn't for enrichment.

---

### 3. MSRC silently drops CVSS 0.0 scores
**Severity:** minor
**Found by:** multipass (Pass 1), holistic
**Corroborated by:** two independent finds

**Verdict: CONFIRMED BUG.** `bestV3Score > 0` (msrc/adapter.go:125) treats 0.0 as "no score." A CVSS 0.0 ("NONE" severity) is a valid score that means "informational / no impact." The score and its vector string are both discarded. NVD handles this correctly by checking for metric data presence, not score value.

Practically rare (MSRC rarely assigns CVSS 0.0), but semantically incorrect — a 0.0 score is different from "no score data."

**Fix:** Track a `hasV3` bool alongside `bestV3Score`, or use `>= 0` with a `found` sentinel.

---

### 4. Red Hat detail response body not drained before Close
**Severity:** minor
**Found by:** multipass (Pass 2)
**Corroborated by:** none (unique find)

**Verdict: CONFIRMED BUG.** `parseDetailResponse` uses `json.NewDecoder(r).Decode(&detail)` which reads only enough bytes to decode one JSON value. Remaining response bytes prevent connection reuse. The non-200 error paths (lines 447, 455) correctly drain, but the success path (line 460-461) doesn't.

With 100+ detail fetches per Fetch call, each opens a new TCP+TLS connection instead of reusing one. Noticeable latency impact.

**Fix:** Add `io.Copy(io.Discard, resp.Body)` after `parseDetailResponse` returns, before `resp.Body.Close()`.

---

### 5. MSRC /updates body not drained on non-200
**Severity:** minor
**Found by:** multipass (Pass 2)
**Corroborated by:** none (unique find)

**Verdict: CONFIRMED BUG.** msrc/adapter.go:310-312 returns an error without draining. The deferred `Close()` fires but the connection can't be reused. Compare with the CSAF error path at line 374 which correctly drains.

Error-path only, so low impact. But inconsistent with the adapter's own CSAF handling.

---

### 6. MSRC cursor marshal error swallowed on no-updates path
**Severity:** minor
**Found by:** multipass (Pass 5)
**Corroborated by:** none (unique find)

**Verdict: CONFIRMED BUG.** msrc/adapter.go:341 uses `nextCursorJSON, _ := json.Marshal(nextCursor)` while the normal path at line 400 properly checks the error. If marshal somehow fails, `nextCursorJSON` is nil, which signals "no more pages" — the cursor isn't persisted.

Near-zero probability for a simple `Cursor{LastReleaseDate: string}` struct. But the inconsistency is real and the fix is trivial.

---

### 7. Red Hat error message double-prefixed
**Severity:** minor
**Found by:** multipass (Pass 5)
**Corroborated by:** none (unique find)

**Verdict: CONFIRMED BUG.** `parseDetailResponse` wraps with `"redhat: parse detail: %w"` (line 173), caller wraps with `"redhat: parse detail %s: %w"` (line 463). Result: `"redhat: parse detail CVE-2024-1234: redhat: parse detail: unexpected EOF"`. Cosmetic only.

**Fix:** Remove the prefix from `parseDetailResponse`, or change the caller to just `"redhat: detail %s: %w"`.

---

### 8. Advisory lock ordering comment is misleading
**Severity:** minor
**Found by:** exploratory, holistic (as design concern)
**Corroborated by:** two independent finds

**Verdict: CONFIRMED — comment/code mismatch, with theoretical deadlock.** Comment at pipeline.go:86 says "lower key first" but code always acquires `newKey` first (step 1, line 64) then `oldKey` (line 91). This creates a theoretical deadlock if two concurrent PK migrations cross-reference each other's CVE IDs.

Practical impact is near-zero — requires two concurrent PK migrations where each transaction's target is the other's source. PostgreSQL's deadlock detector handles it. But the comment is actively wrong.

**Fix options:**
- (a) Fix the comment to describe actual behavior
- (b) Restructure to acquire locks in sorted order (more work, prevents the theoretical deadlock)

---

## Rejected / Invalid Findings

### Holistic: "Merge pipeline missing enrichment sanitization"
**Verdict: NOT A BUG.** The holistic report flagged `pipeline.go:245` for not calling `StripNullBytes` on enrichment data. But the architecture deliberately pushes sanitization to the adapter layer (where field-level context exists), not the pipeline. The pipeline correctly trusts adapter output. The *real* bug is that KEV doesn't sanitize enrichment (Bug #2 above), not that the pipeline lacks a safety net.

---

## Design Concerns (non-bugs, for future consideration)

| Concern | Found by | Assessment |
|---------|----------|------------|
| MSRC "Exploitation Detected" not mapped to `ExploitAvailable` | exploratory | **Worth doing.** Creates alert coverage gap for MSRC-detected exploits not yet in KEV. |
| `append(globalVar, ...)` in resolve.go is fragile | exploratory | **FIXED.** Replaced with `slices.Concat` in commit `0eae700`. |
| CSAF parser handles 3 of 8 product status types | exploratory | **Fine for now.** MSRC uses `known_affected` primarily. Revisit if adding ICS-CERT adapter. |
| Neither adapter sets `Severity`/`Status` on CanonicalPatch | multipass | **By design.** Vendor adapters provide severity assessments via enrichment, not lifecycle status. |
| MSRC has no pagination for backfill | multipass | **Acknowledge.** First-time backfill fetches all ~240 CSAF docs in one Fetch call (~1GB). Worth adding a per-call limit eventually. |
| MSRC string-based date comparison | multipass | **Low risk.** ISO 8601 sorts correctly when formatting is consistent. Monitor for format inconsistencies. |
| Single CSAF failure aborts all pending releases | multipass | **Consistent with NVD pattern** but amplified blast radius. Could skip individual docs and continue. |
| MSRC document-level dates applied to all CVEs | holistic | **CSAF format limitation.** No per-vuln dates in CSAF; merge resolution mitigates when NVD/MITRE also have the CVE. Wrong for MSRC-only CVEs. |

---

## Summary

| # | Bug | Severity | Fix effort |
|---|-----|----------|------------|
| 1 | Red Hat cursor never advances | **significant** | Small — return non-nil cursor with updated AfterDate |
| 2 | KEV enrichment not null-byte stripped | **significant** | Small — add StripNullBytes to 5 fields |
| 3 | MSRC drops CVSS 0.0 | minor | Small — use `found` bool instead of `> 0` |
| 4 | Red Hat detail body not drained | minor | Trivial — add `io.Copy(io.Discard, resp.Body)` |
| 5 | MSRC /updates body not drained | minor | Trivial — add drain before error return |
| 6 | MSRC cursor marshal error swallowed | minor | Trivial — handle the error |
| 7 | Red Hat error double-prefix | minor | Trivial — deduplicate prefix |
| 8 | Advisory lock comment wrong | minor | Trivial to fix comment; bigger if restructuring lock order |

**Recommended fix order:** 1 → 2 → 3 → 4 → 5/6/7/8 (batch the trivials)

---

## Resolution

All 8 bugs + 1 design concern (resolve.go fragility) fixed on branch `feature/vendor-feed-adapters`. Commits:

| # | Bug | Commit | Notes |
|---|-----|--------|-------|
| 1 | Red Hat cursor never advances | `bb946ad` | Always return non-nil NextCursor; advance AfterDate to today on last page |
| 2 | KEV enrichment not null-byte stripped | `30efb53`, `00bcaac` | Strip all 6 string fields including `KnownRansomwareCampaignUse` before `== "Known"` comparison |
| 3 | MSRC drops CVSS 0.0 | `0e4d934` | `hasV3`/`hasV4` bools replace `> 0` guards; selection loop also fixed |
| 4 | Red Hat detail body not drained | `a566bce` | `io.Copy(io.Discard, resp.Body)` on success path; also fixed error double-prefix (Bug #7) |
| 5 | MSRC /updates body not drained | `d4e4d0f` | Drain on non-200 path; also fixed cursor marshal error swallowing (Bug #6) |
| 6 | MSRC cursor marshal error swallowed | `d4e4d0f` | Combined with Bug #5 fix |
| 7 | Red Hat error double-prefix | `a566bce` | Combined with Bug #4 fix |
| 8 | Advisory lock comment wrong | `31ba370` | Comment corrected to describe actual new-then-old lock ordering |
| — | resolve.go global slice fragility | `0eae700` | `slices.Concat` replaces `append(globalVar, ...)` at 3 call sites |

Review findings during implementation:
- KEV `KnownRansomwareCampaignUse` also needed stripping before comparison (not in original bug report — null byte in `"Known\x00"` would silently produce `false`)
- All feed tests pass (10 packages). Merge unit tests pass. Lint clean (0 issues).
