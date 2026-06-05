# S3 Feed Ingestion — Idiom-Currency Audit

**Date:** 2026-06-05
**Slice:** S3 "Feed ingestion & adapters" (FULL, HOT)
**Lane:** framework-idiom currency (superseded/slow Go idioms vs. Go 1.26-available fast paths)
**Scope read:** `internal/feed/**`, `internal/ingest/**`, `internal/store/feed.go`, plus `internal/merge/pipeline.go` (write-path context)
**Version index:** `version-indexes/go.md` (`covered_through: Go 1.24`). Project runs Go 1.26, which is **newer** than the index — anything past Go 1.24 is Heuristic and not fabricated.

---

## Lane summary

The adapters are, on the whole, written to current streaming idioms: `json.Decoder` `Token()`/`More()` loops on NVD/GHSA/generic, `csv.Reader` with `ReuseRecord` for EPSS, ZIP `FileHeader.Modified` pre-filter, `strings.Clone` discipline against backing-array retention. That is the right baseline and I'm not going to pad the report by re-praising it.

The genuine idiom-currency findings are about (1) **`[]CanonicalPatch` accumulation without preallocation** across the whole-archive adapters, (2) **OSV/MITRE buffering each ZIP entry fully via `io.ReadAll` + `bytes.NewReader`** when the decoder could stream the entry directly, and (3) a per-record **`sort.Strings` allocate-and-sort** in alias resolution on the hottest loop in the corpus. There is one explicitly-NOT-a-finding note on EPSS per-row transactions (architecturally mandated; pgx Batch/CopyFrom does not apply).

---

### [MAJOR] OSV/MITRE buffer every ZIP entry via `io.ReadAll` + `bytes.NewReader` instead of decoding the entry stream directly

**Location:** `internal/feed/osv/adapter.go:145-161` (`parseEntry`); `internal/feed/mitre/adapter.go:155-171` (`parseEntry`)

**Problem:** Both whole-archive adapters do, per entry:
```go
raw, err := io.ReadAll(rc)            // allocate a []byte sized to the full entry
...
patch, err := parseAdvisory(bytes.NewReader(raw))  // wrap in a reader and json.Decode it
```
`json.NewDecoder` accepts any `io.Reader`, so `entry.Open()` (a `zip.fileReader`, an `io.ReadCloser`) can be decoded directly — the intermediate full-size `[]byte` and the `bytes.Reader` wrapper are avoidable. The `io.ReadAll` here exists only because `RawPayload = raw` needs the original bytes; that capture can be done with an `io.TeeReader` into the decoder so the bytes are captured *while* parsing, instead of a separate read-then-parse pass. OSV's `all.zip` is ~100k+ entries per full backfill; MITRE's cvelistV5 is 100k+ entries. Each entry triggers one `io.ReadAll` allocation (sized to the JSON, often multi-KB) that lives until the patch is appended.

The current `io.ReadAll`+`bytes.NewReader` pattern is the pre-streaming idiom; the index's serialization guidance (`encoding/json` `Decoder` for ingest, profile-pack data-access lane) is "prefer `json.NewDecoder(r).Decode` for ingest" specifically to avoid the buffer-then-parse round trip.

**Impact:** Reachability: every full backfill and every incremental run that touches changed entries. Frequency: per-entry across 100k+ entries on a full OSV/MITRE backfill. Per-occurrence cost: one heap allocation sized to the entry JSON + a `bytes.Reader` struct, all surviving to GC after append. Aggregate is hundreds of MB of transient allocation per backfill, driving GC.

**Confidence:** Heuristic — grounded in the index "Stdlib & Generics / `encoding/json` Decoder for ingest" guidance and the profile-pack data-access lane; the `RawPayload` capture constraint means the win is "avoid the second buffering pass," not "zero-copy," so the magnitude is Heuristic not Strong-static.

**Effort:** Contained — `RawPayload` semantics must be preserved. The clean form is an `io.TeeReader(rc, &buf)` feeding the decoder, replacing `io.ReadAll`+`bytes.NewReader`. Touches two adapters identically.

**Verification plan:** Benchmark `parseEntry` on a representative 4 KB and 40 KB advisory with `-benchmem`; compare allocs/op and B/op between `io.ReadAll`+`bytes.NewReader` and a `TeeReader`-into-decoder form. Correctness guard: golden tests for osv/mitre must stay green (they assert `RawPayload` byte-for-byte), and a test asserting `RawPayload` equals the original entry bytes including trailing whitespace.

---

### [MAJOR] Whole-archive adapters accumulate an unbounded `[]CanonicalPatch` with no preallocation

**Location:** `internal/feed/osv/adapter.go:102` + `:118` (`var patches []...; patches = append(...)`); `internal/feed/mitre/adapter.go:102` + `:120`; also `generic` buffered/stream paths `adapter.go:161`, `:207`

**Problem:** `var patches []feed.CanonicalPatch` then `append` inside the per-entry loop. On a full OSV/MITRE backfill this slice grows to 100k–250k elements through repeated geometric doublings, each doubling copying every prior `CanonicalPatch` (a large struct with ~15 pointer/slice fields, so each element copy also re-copies slice headers). The index's profile-pack memory lane flags exactly this: "Slice growth without preallocated capacity ... use `make([]T, 0, n)` when n is known or estimable." Here `n` is highly estimable — `len(zr.File)` is an upper bound for both ZIP adapters, available before the loop at zero cost.

Beyond preallocation, the deeper idiom issue is that the entire result set is **materialized in memory before returning** to the handler, which then iterates and merges one-at-a-time (`handler.go:163`). The handler-merge loop never needs the whole slice at once. A streaming hand-off (channel or iterator `iter.Seq[CanonicalPatch]`, available since Go 1.23 and in the index under "`slices` iterator functions" / range-over-func) would cap resident memory at one patch instead of the full archive. That is the current idiom for this exact pipeline shape on 1.23+.

**Impact:** Reachability: every OSV/MITRE/generic run. Frequency: the doubling copies are O(log n) reallocations but the resident-set spike is the real cost — 250k `CanonicalPatch` values plus their `RawPayload` byte slices held simultaneously. Per-occurrence: peak heap proportional to whole-archive size; on a memory-capped container (GOMEMLIMIT, per CLAUDE.md) this is the most likely OOM/GC-thrash trigger in S3.

**Confidence:** Heuristic for the preallocation half (Strong-static that `make([]T,0,len(zr.File))` is a free win); Heuristic for the iterator-handoff half (range-over-func is past `covered_through` Go 1.24 but shipped in 1.23 and the project is on 1.26 — index "`slices` iterator functions, Go 1.23").

**Effort:** `make([]T, 0, n)` preallocation = Localized (one line per adapter). Iterator/channel hand-off = Cross-cutting (changes the `feed.Adapter` contract or adds a streaming variant; the `FetchResult.Patches []CanonicalPatch` field is the API boundary). Recommend the Localized preallocation now; raise the streaming-handoff as a design decision, not an inline fix.

**Verification plan:** For preallocation: benchmark archive parse with `-benchmem`, confirm allocs/op drops by ~log2(n) reallocation events and B/op for the slice backing array drops to a single allocation. For the handoff: measure peak RSS (or `runtime.ReadMemStats` HeapInuse) across a full OSV backfill before/after. Correctness guard: same patch count and identical patches in order.

---

### [MINOR] `ResolveCanonicalID` allocates a copy and `sort.Strings` on every record

**Location:** `internal/feed/util.go:191-203` (`ResolveCanonicalID`), called per-record from `osv/adapter.go:234` and `ghsa/adapter.go:343`

**Problem:**
```go
sorted := make([]string, len(aliases))
copy(sorted, aliases)
sort.Strings(sorted)
for _, alias := range sorted { if cveIDPattern.MatchString(alias) ... }
```
This is called once per OSV advisory (~250k on full backfill) and once per GHSA advisory. It allocates a fresh slice, copies it, and sorts it — purely to make the "first CVE alias when several exist" deterministic. The vast majority of records have 0–2 aliases, and a CVE-ID match is a simple prefix/regex test. The sort is only meaningful when ≥2 aliases are CVE IDs, which is rare. Two idiom-currency notes: (1) `sort.Strings` is superseded by `slices.Sort` (index "Stdlib & Generics / `slices` package, Go 1.21" — pdqsort-backed, current idiom); (2) more importantly, the allocate+copy+sort can be avoided entirely by scanning for CVE matches first and only sorting/min-selecting the (near-always ≤1) matches.

The per-record regex `MatchString` is correctly compiled once at package scope (`cveIDPattern`, `util.go:67`) — that part is fine and not a finding.

**Impact:** Reachability: every OSV and GHSA record. Frequency: ~250k/backfill for OSV. Per-occurrence: one slice allocation + copy + comparison sort of a tiny slice. Small per call, but on the hottest loop in the corpus it's measurable allocation churn; bounded-small-n on the sort itself (calibration says don't chase the big-O), so this ranks MINOR — the allocation, not the sort cost, is the reason it's here.

**Confidence:** Heuristic — index "`slices` package (Go 1.21)" for the `sort.Strings`→`slices.Sort` currency note; the allocation-avoidance restructure is a memory-lane observation at Heuristic.

**Effort:** Localized — scan aliases for CVE-pattern matches into a small local; sort only if >1 match (or pick min lexicographically in one pass via the `min` builtin, Go 1.21). Single function, well-covered by existing alias-resolution tests.

**Verification plan:** Benchmark `ResolveCanonicalID` with 0, 1, and 3 aliases `-benchmem`; confirm the common 0–1 alias case drops to zero allocations. Correctness guard: existing OSV/GHSA alias-resolution tests must stay green, plus a test with two CVE aliases asserting the lexicographically-first is still chosen (determinism preserved).

---

### [MINOR] GHSA synthesizes per-vulnerability event JSON via `json.Marshal` inside the per-package loop

**Location:** `internal/feed/ghsa/adapter.go:428-437`

**Problem:** For each affected package with a fixed version, the adapter declares a local `event` struct type and calls `json.Marshal([]event{...})` to build a 2-element `[{"introduced":"0"},{"fixed":"X"}]` array. `json.Marshal` spins up reflection-based encoding per call. This is a tiny, fixed-shape payload; the index/profile-pack serialization guidance is to avoid reflective `json.Marshal` on hot paths for fixed shapes — here `fmt.Appendf`/a constant-template `[]byte` with the fixed version interpolated produces identical bytes without reflection. `fmt.Append`/`Appendf` is in the index ("Stdlib & Generics, Go 1.19") for exactly "format directly into `[]byte` without intermediate allocation."

**Impact:** Reachability: every GHSA advisory with affected packages (most reviewed advisories). Frequency: per affected-package-with-fix, several per advisory. Per-occurrence: one reflective marshal of a 2-element slice + the slice/struct allocations. Low individual cost; GHSA volume is far below OSV/MITRE, so MINOR.

**Confidence:** Heuristic — index "`fmt.Append`/`Appendf` (Go 1.19)" and serialization profile-pack.

**Effort:** Localized — replace the marshal with a small `fmt.Appendf(nil, ...)` or template; the output is a fixed-schema 2-element array, trivially asserted byte-equal in a test.

**Verification plan:** Unit test asserting the produced `eventsJSON` is byte-identical for the same `fixed` value before/after. Benchmark with `-benchmem` to confirm allocs/op drop. Correctness guard: golden GHSA test (`internal/feed/ghsa/golden_test.go`) green.

---

### [NOT A FINDING — recorded so a later auditor doesn't re-open it] EPSS per-row `database/sql` transactions are mandated, not a missed pgx Batch/CopyFrom

**Location:** `internal/feed/epss/adapter.go:202-287` (`Apply` loop + `applyRow`)

The index lists pgx `Batch`/`CopyFrom` as the bulk-ingest fast path, and EPSS applies ~250k rows one transaction at a time — superficially the textbook target. **It is not applicable here.** Each row must (a) take `pg_advisory_xact_lock(CVEAdvisoryKey(cveID))` matching the merge pipeline to prevent the TOCTOU race in PLAN.md §5.3, and (b) run the two-statement `IS DISTINCT FROM` / `WHERE NOT EXISTS` pattern whose semantics depend on per-CVE transaction isolation. `CopyFrom` bypasses per-row locking and conflict logic entirely; a `pgx.Batch` would still need one advisory lock + two statements per row and could not be a single round-trip without breaking the lock-per-CVE-transaction invariant. The `database/sql`/stdlib wrapping (`store.go:29` `stdlib.OpenDBFromPool`) is the project-wide sqlc binding, not an EPSS-specific slow choice. Chasing batch here would be a correctness regression. Recorded as deliberately out of scope.

The same reasoning covers `merge.Ingest` (`pipeline.go:52`): one `database/sql` transaction + advisory lock per patch is required by the merge design; pgx Batch/CopyFrom does not apply.

---

## Suspected Bugs (for follow-up)

None. (One adjacent observation, not a bug and not in-lane: `osv/adapter.go:139` `isAdvisoryEntry` only checks `.json` suffix, so a top-level non-advisory JSON in `all.zip` would be fed to `parseAdvisory` and skipped on no-ID — benign, already handled by the `nativeID == ""` guard.)
