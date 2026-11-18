# Version Perf Indexes (shipped, build-once lookup)

**What this is:** curated, committed lookups of *version-specific* performance features/APIs per
ecosystem — "this API/type, as of this version, is the fast path." They are **built once** (mining
rich sources like .NET "What's New" / "Performance Improvements in .NET N" posts) and committed, so a
performance audit **looks them up cheaply at runtime instead of re-researching the whole version
history on every run**.

This is the middle tier of a three-tier knowledge model:

1. **Profile pack** (`../profile-packs/<eco>.md`) — durable, version-independent idioms (the lens).
2. **Version perf index** (this directory) — curated version-specific perf features, build-once.
3. **Live currency brief** (`docs/perf-audits/cache/…`, per `../currency-protocol.md`) — fills only
   the gap *beyond* an index's `covered_through` version, so live web research is the exception.

The `idiom-currency` lane consults the shipped index **first** (no network). Live research runs only
to extend past `covered_through` (or when no index exists for the ecosystem).

## Schema (`index_schema_version: 1`)

One file per ecosystem: `version-indexes/<ecosystem>.md`.

```markdown
---
index_schema_version: 1
ecosystem: <dotnet|javascript-typescript|python|go|rust|jvm>
covered_through: "<newest version this index curates, e.g. .NET 9 / React 19>"
built_on: <YYYY-MM-DD>
sources:
  - <url>            # the pages this index was mined from
---
# <Ecosystem> performance version index
> Build-once lookup. The idiom-currency lane consults this first; live research only extends past
> `covered_through`.

## <Area, e.g. Serialization / Collections / Strings & searching / Async / LINQ / Memory & spans / ORM / Startup & AOT>
- **<API / type / feature>** — landed/major-perf-improved in **<version>** — <durable perf benefit,
  one line> — supersedes <prior approach> — use when <condition>.
```

## Curation rules (avoid overload — same spirit as the packs)
- **Curated, not exhaustive.** Only entries with a *material* perf benefit a code reviewer would act
  on. Skip micro-deltas and internal-only improvements with no API surface.
- **Lookup-shaped.** Each entry is keyed by the API/type/feature so the lane can match code against it
  ("the code parses JSON with reflection-based `JsonSerializer`; the index says source-gen is the fast
  path as of .NET 6+"). One line of guidance per entry.
- **Version is data, not prose.** Put the version in the entry's `version` field/clause, not woven
  into long paragraphs.
- **Group by area** so a lane can scan the relevant section.
- **`covered_through` is the contract** with live research: everything up to it is the index's job;
  everything after is the live brief's job.
- **Note the support cadence (LTS/STS) where the ecosystem has one.** Ecosystems with a long-term-support
  track — **.NET** (even majors = LTS / 3 yr, odd = STS / 18 mo), **Java** (LTS: 8/11/17/21/25, ~2-yr
  cadence), **Node.js** (even majors = LTS) — SHOULD carry a near-top `## Support cadence` section.
  This exists because **"upgrade to the latest major for feature X" is often invalid advice**: a project
  pinned to an LTS line cannot adopt an STS-only feature without leaving support. Upgrade-opportunity
  guidance MUST respect the project's support track — prefer the newest feature available *on its LTS
  line*, or explicitly flag the support-track tradeoff. (The idiom-currency lane enforces this; see
  `lane-prompts.md`.)

## How to add / refresh an index
1. Mine the ecosystem's authoritative version-history perf sources **once** (url-to-markdown for rich
   pages; scan/grep, don't read end-to-end).
2. Distill into curated entries per the schema; set `covered_through`, `built_on`, `sources`.
3. Commit. Refresh when a new major version ships enough perf-relevant surface to matter (bump
   `covered_through` + `built_on`).
