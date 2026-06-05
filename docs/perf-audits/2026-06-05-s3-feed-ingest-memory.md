# S3 Feed Ingestion — Memory & Allocation Audit

**Date:** 2026-06-05
**Slice:** S3 "Feed ingestion & adapters" (FULL, HOT)
**Lane:** memory & allocation
**Scope read:** `internal/feed/{interface,client,util}.go`, adapters `nvd`, `ghsa`, `osv`, `mitre`, `epss`, `generic` (deep) + `redhat`, `msrc`, `csaf`, `kev` (divergence spots); `internal/ingest/handler.go`; `internal/store/feed.go`; `internal/merge/pipeline.go` (Ingest signature only).

Confidence is static-only; no runtime profiling was performed.

---

## The structural finding the rest hang off

`feed.Adapter.Fetch` returns `*FetchResult` containing a **fully-materialized `[]CanonicalPatch`** for the entire page. For the bulk-archive adapters (MITRE, OSV) "a page" is the *entire feed*. The merge stage (`ingest/handler.go` loop at L163 → `merge.Ingest`) consumes patches strictly **one at a time** — it marshals each patch independently and never looks at the slice as a whole. The slice therefore provides zero batching benefit downstream; it is pure peak-memory overhead. Every `CanonicalPatch` also carries `RawPayload json.RawMessage` — the unmodified upstream JSON for that record — which is the single largest field and is retained for every record in the slice for the entire run.

This is the dominant memory characteristic of the slice and the source of the two CRITICAL findings below.

---

### [CRITICAL] MITRE/OSV bulk adapters materialize the whole feed (100k+ patches, each retaining full RawPayload) into one slice

**Location:** `internal/feed/mitre/adapter.go:102-121` + `parseEntry` L155-171; `internal/feed/osv/adapter.go:102-119` + `parseEntry` L145-161
**Problem:** Both adapters loop over every ZIP entry, decode each into a `*CanonicalPatch`, and `append` to a single `var patches []feed.CanonicalPatch` that is returned in one `FetchResult`. MITRE's cvelistV5 archive is 100,000+ CVE records on a first run (zero cursor → no `Modified` pre-filter applies, every entry parsed); OSV's `all.zip` is thousands-to-tens-of-thousands. Critically, `parseEntry` does `raw, _ := io.ReadAll(rc)` per entry and assigns `patch.RawPayload = raw` (mitre L169, osv L159), so the full raw JSON of *every* record stays live in the slice. The temp-file ZIP is read lazily (good — only `tmpFile`'s bytes are on disk, not in heap), but the parsed+raw output is fully accumulated. Peak heap ≈ Σ(parsed struct + raw JSON copy) over the entire archive. A typical CVE-5.0 record is several KB of JSON; 100k records → hundreds of MB to low-GB of live heap, all of which the GC must trace, and none of which is needed simultaneously because merge processes one patch then discards it.

The streaming discipline the project mandates (`json.Decoder` Token()/More(), "Decode(&hugeSlice) is forbidden") is correctly applied to the *parse of each entry*, but defeated at the *aggregation* layer: the whole feed lands in memory anyway via the returned slice.

**Impact:** reachability = every MITRE and OSV sync, guaranteed on every backfill and on any incremental run that touches many entries. frequency = scheduled, repeatedly. per-occurrence = O(archive size) peak heap held until the entire merge loop finishes; on a container with `GOMEMLIMIT` set from cgroup (CLAUDE.md confirms `automemlimit` is wired) this is exactly the shape that triggers GC thrash or OOM. Streaming/callback delivery would bound peak to O(1 patch).
**Confidence:** Strong-static
**Effort:** Cross-cutting + low-to-moderate. The fix is an interface change: have `Fetch` deliver patches via a callback / `iter.Seq` / channel rather than returning a slice, OR chunk the bulk adapters into bounded sub-pages. The handler loop (`ingest/handler.go:163`) already consumes per-patch, so the consumer side is a near-trivial adaptation; the cost is touching the `Adapter` interface and all 10 implementations + tests.
**Verification plan:** `go test -bench` a MITRE/OSV `Fetch` over a synthetic N-entry ZIP with `-benchmem`; assert allocated-bytes and peak (`runtime.ReadMemStats` HeapInuse mid-run) scale O(1) with N after the change vs O(N) before. Correctness guard: golden tests for mitre/osv must produce byte-identical patches in identical order; cursor/`LastModified` semantics unchanged; malformed-entry skip behavior preserved.

---

### [CRITICAL] Handler holds the entire returned patch slice live for the whole merge loop while also re-reading it per patch

**Location:** `internal/ingest/handler.go:145-251` (pagination loop), patches consumed at L163-211
**Problem:** `result, _ = adapter.Fetch(...)` returns the full slice; the handler then ranges over `result.Patches` calling `merge.Ingest` per element. Because `result` (and thus the backing array) stays referenced until the loop iteration completes, **none** of the per-patch memory can be GC'd incrementally — the full slice from the bulk adapters (previous finding) lives for the entire duration of the merge of every record, which for MITRE is 100k sequential DB transactions. So the worst-case peak heap (full feed materialized) is held for the *longest* possible window (the entire merge), not just the parse. Additionally, `merge.Ingest` re-marshals each `CanonicalPatch` to JSON (`pipeline.go:45 json.Marshal(patch)`) — meaning each patch's data is allocated a *second* time (the marshaled `normalizedJSON`) on top of the already-retained struct + RawPayload, transiently per patch. The combination (whole feed retained + per-patch re-marshal) is the peak.
**Impact:** reachability = every bulk-feed ingest. frequency = per scheduled sync. per-occurrence = retains O(feed) for O(feed) DB round-trips; this is the single longest-lived large allocation in the slice. For the paginating adapters (NVD 2000/page, GHSA 100/page, generic) the per-page slice is bounded and fine — the problem is specific to the single-`FetchResult`-for-whole-feed adapters, which is why this is coupled to the previous finding.
**Confidence:** Strong-static
**Effort:** Cross-cutting + low. Resolved by the same interface change as the previous finding (stream patches → merge each → drop reference immediately). No separate work if the streaming-delivery fix lands.
**Verification plan:** With streaming delivery, assert via `runtime.ReadMemStats` that HeapInuse during the MITRE merge loop stays flat regardless of archive size. Correctness guard: cursor persistence after each page (handler L218-236) and the three-layer termination (L240-250) must still fire; for a single-`FetchResult` adapter that now streams, ensure `itemsFetched`/`itemsUpserted` counts and fetch-log totals are unchanged.

---

### [MAJOR] NVD re-marshals each vulnerability wrapper to produce RawPayload, doubling per-record allocation on the hot parse path

**Location:** `internal/feed/nvd/adapter.go:398-415`
**Problem:** Inside the streaming `vulnerabilities` loop, each record is `dec.Decode(&wrapper)` into a typed `nvdVulnWrapper`, then **re-serialized** via `json.Marshal(wrapper)` to populate `p.RawPayload`. This is a full second pass over the record (reflection-based encode allocating a fresh `[]byte`) when the original bytes were already in the decoder's buffer. NVD pages are 2000 records and explicitly noted as ">5 MB typical"; on a full backfill there are hundreds of pages. Every record pays decode + re-encode. Worse, the re-marshaled bytes are not even faithful to the wire (field reordering, dropped unknown fields) — so it is both costly *and* lossy as an "audit/debugging" payload. The streaming-friendly idiom is to capture the raw bytes during decode: decode into `json.RawMessage` for the wrapper (or a struct holding `CVE json.RawMessage`) and keep that slice directly, avoiding the re-encode entirely.
**Impact:** reachability = every NVD page parse (the largest-volume API feed, 250k records on backfill). frequency = high. per-occurrence = one extra reflective `json.Marshal` + one `[]byte` allocation per record (~record-size bytes). Aggregate across 250k records on backfill = a second full serialization of the entire NVD corpus.
**Confidence:** Strong-static
**Effort:** Localized. Change `nvdVulnWrapper` decode to capture raw bytes (e.g. decode `json.RawMessage`, then sub-decode the typed struct, or use `dec.Token`-bounded raw capture) and assign that to `RawPayload` instead of `json.Marshal(wrapper)`.
**Verification plan:** `-benchmem` on `parseNVDResponse` over a golden multi-record page; assert allocs/op and bytes/op drop by ~the size of one record per element. Correctness guard: NVD golden test must still pass; note that switching to raw-capture *changes* RawPayload bytes (now faithful to wire) — confirm no downstream consumer depends on the current re-marshaled shape (it is stored for audit only per the field comment).

---

### [MAJOR] GHSA re-marshals each decoded advisory for RawPayload — same double-allocation as NVD

**Location:** `internal/feed/ghsa/adapter.go:211-231` (L226 `json.Marshal(rec)`)
**Problem:** Identical anti-pattern: stream-decode `ghsaAdvisory`, then `json.Marshal(rec)` to fill `patch.RawPayload`. GHSA advisories carry large `Description` (up to 65535 chars) plus vulnerabilities/references arrays; the re-encode allocates a fresh buffer of that size per record. GHSA backfill is thousands of advisories paged 100 at a time. Same fix as NVD: capture raw bytes during the streaming decode rather than re-encoding.
**Impact:** reachability = every GHSA page. frequency = moderate-high (backfill thousands; incremental smaller). per-occurrence = extra full reflective encode + buffer per advisory, dominated by the large description field.
**Confidence:** Strong-static
**Effort:** Localized — decode the array element into `json.RawMessage`, then sub-decode the typed `ghsaAdvisory` from those bytes, keeping the raw for `RawPayload`.
**Verification plan:** `-benchmem` on `fetchPage` parse over a golden page; bytes/op should drop by ~Σ description sizes. Correctness guard: ghsa golden + bugfix tests pass; confirm RawPayload-shape change is acceptable (audit-only).

---

### [MAJOR] Generic CSAF and buffered-JSON paths read whole body into memory then accumulate all patches; MSRC/RedHat re-read every detail doc

**Location:** `internal/feed/generic/adapter.go:142-183` (`fetchJSONBuffered` `io.ReadAll`), `530-570` (`fetchCSAF`), `572-652` (`csafToPatches` L645 `json.Marshal(vuln)`); `internal/feed/msrc/adapter.go:388` (`io.ReadAll` per CSAF doc); `internal/feed/redhat/adapter.go:430-477` (`io.ReadAll` per detail + accumulate)
**Problem:** Three related buffering costs. (1) `fetchJSONBuffered` does `io.ReadAll(LimitReader(…,50MB))` then runs `gjson.GetBytes` over the whole body and `ForEach`-appends every record into `patches` — the body *and* the full patch slice are both live. The streaming path (`fetchJSONStream`) exists and is preferred, but is bypassed whenever the configured root path contains a dot (nested array) — a common config shape — falling back to full buffering. (2) `csafToPatches` re-marshals each vulnerability (`json.Marshal(vuln)`, L645) for RawPayload — the same double-allocation as NVD/GHSA. (3) RedHat's two-phase fetch reads each detail response fully (`io.ReadAll`, L462), assigns `raw` to `RawPayload`, and accumulates all patches across the whole CVE-ID list into one slice; MSRC similarly `io.ReadAll`s each CSAF doc. These are bounded by page/list size (not whole-feed like MITRE/OSV), so lower severity, but they share the "buffer body + retain raw per record + accumulate slice" shape.
**Impact:** reachability = generic feeds with nested roots (buffered path) and all CSAF/MSRC/RedHat syncs. frequency = per scheduled sync. per-occurrence = body buffer (≤50MB) + retained raw per record + full patch slice, held until merge consumes. Bounded per page but multiplied by the re-marshal in the CSAF case.
**Confidence:** Strong-static (Heuristic on the real-world size of nested-root generic feeds, which is config-dependent)
**Effort:** Contained. CSAF re-marshal → capture raw (Localized). Buffered-JSON nested-root → harder (gjson needs the full body for dotted paths); accept the body buffer but at least avoid retaining it once patches are extracted. RedHat/MSRC accumulation → folds into the streaming-delivery interface change.
**Verification plan:** `-benchmem` on `csafToPatches` and `fetchJSONBuffered` over golden inputs; confirm CSAF raw-capture removes one marshal/record. Correctness guard: generic, csaf, msrc, redhat golden/unit tests pass; gjson extraction over buffered body unchanged.

---

### [MINOR] `ResolveCanonicalID` copies + sorts the alias slice on every record even when no CVE alias is possible

**Location:** `internal/feed/util.go:191-203`
**Problem:** Called once per OSV and GHSA record (osv `parseAdvisory` L234, ghsa L343). It unconditionally `make`s a copy of `aliases` and `sort.Strings` it before scanning for a CVE-pattern match. For the overwhelming-common case of 0–2 aliases the sort is trivially cheap, but the `make([]string, len(aliases))` + `copy` allocates a fresh slice **per record** across the entire OSV feed (tens of thousands of records) purely to achieve deterministic ordering. The determinism only matters when ≥2 CVE IDs exist (rare). A single linear scan that tracks the lexicographically-smallest CVE match avoids both the allocation and the sort with identical output.
**Impact:** reachability = every OSV + GHSA record. frequency = per record, whole feed. per-occurrence = one slice allocation (+ sort) per record; small individually, but it is on the hottest per-record path of two bulk feeds. Aggregate = tens of thousands of throwaway slice allocations per OSV sync.
**Confidence:** Strong-static
**Effort:** Localized — replace copy+sort+first-match with a single pass tracking the min CVE-pattern match; return early if `len(aliases) < 2` (no ordering ambiguity).
**Verification plan:** `-benchmem` on `ResolveCanonicalID` with 0/1/2/many aliases; allocs/op → 0 for the common ≤1-CVE case. Correctness guard: `util_test.go` + `util_bugfix_test.go` must pass unchanged — same canonical ID chosen for multi-CVE-alias input.

---

### [MINOR] Pervasive `strings.Clone(StripNullBytes(x))` wrapping forces an allocation even when the input has no null bytes and no aliasing

**Location:** pattern across all adapters, e.g. `nvd/adapter.go:441-505`, `mitre/adapter.go:263-323`, `ghsa/adapter.go:325-462`, `osv/adapter.go:222-309`
**Problem:** Nearly every extracted field is `strings.Clone(feed.StripNullBytes(s))`. `StripNullBytes` is `strings.ReplaceAll(s, "\x00", "")` which **already returns a fresh string** when a null byte is present (and returns the original — sharing the decoder's backing array — when absent). The outer `strings.Clone` is there to break the backing-array aliasing so the (large, soon-discarded) decoded buffer can be GC'd. That goal is legitimate for the streaming `json.Decoder` adapters where small extracted substrings would otherwise pin a multi-MB page buffer. But `strings.Clone` allocates **unconditionally** even when `StripNullBytes` already produced a standalone string — a double allocation for every field containing a null byte (uncommon) and a forced copy for the common no-null case. The per-field cost is tiny, but it is applied to every string field of every record across every feed — the single most-executed allocation in the slice. Whether this is net-positive depends on the alias-pinning tradeoff: for the ZIP adapters (mitre/osv) the per-entry `raw` is already a freshly-read `[]byte` that is *kept* as RawPayload anyway, so cloning substrings out of it does **not** free anything — the clone is pure waste there.
**Impact:** reachability = every string field of every record, all feeds. frequency = highest in the slice. per-occurrence = one string allocation/copy per field; individually negligible, aggregate is the bulk of small-object allocation pressure during ingest (GC-trace cost). Heuristic on net benefit because the clone *does* enable buffer reclamation on the decoder-streaming adapters.
**Confidence:** Heuristic (the optimization is conditional on the alias-pinning analysis per adapter)
**Effort:** Contained + careful. For ZIP adapters (mitre/osv) where `raw` is retained as RawPayload, the inner-buffer-pinning rationale does not apply, so `strings.Clone` can be dropped (rely on `StripNullBytes`). For decoder-streaming adapters (nvd/ghsa/kev), keep clone only where the substring would otherwise pin the page buffer. Do NOT blanket-remove — this needs per-adapter reasoning and is easy to get subtly wrong (re-introduces the page-pinning leak the clones were added to fix).
**Verification plan:** `-benchmem` per adapter parse before/after; expect reduced allocs/op on mitre/osv. Correctness + leak guard: confirm via a retained-reference test that dropping clone on a decoder-streaming adapter does NOT keep the page buffer alive (the original reason for the clones). If uncertain, leave as-is — the safety margin matters more than the micro-allocation here.

---

## Summary of ranking rationale

The two CRITICALs are one architectural problem (whole-feed materialization in `FetchResult.Patches` for MITRE/OSV, held across the entire merge) and dominate peak heap — they are the difference between O(1) and O(feed-size) memory on the largest ingests. The three MAJORs are the redundant re-marshal-for-RawPayload pattern (NVD, GHSA, generic-CSAF) plus the generic/MSRC/RedHat buffering — each a doubled or whole-body allocation on a hot per-record path, bounded per page so below the CRITICALs. The two MINORs (`ResolveCanonicalID` copy+sort, blanket `strings.Clone`) are per-record micro-allocations whose aggregate is real but whose per-occurrence cost and fix-safety put them last.

---

## Suspected Bugs (for follow-up)

- **`internal/feed/osv/adapter.go:139` `isAdvisoryEntry` too permissive** — returns true for *any* `.json` in the zip, including any top-level manifest/index JSON OSV may ship; `parseAdvisory` then skips entries with empty `id` (returns nil,nil) so it is not a correctness failure, but it forces a full `io.ReadAll` + decode of every non-advisory JSON. Memory-adjacent (wasted buffering) more than a bug. Not chased.
- **`internal/feed/nvd/adapter.go:411-413`** — if `json.Marshal(wrapper)` errors, `RawPayload` is silently left nil and the patch is still appended; the error is swallowed (`if … err == nil`). Correctness/observability, not memory. Not chased.
