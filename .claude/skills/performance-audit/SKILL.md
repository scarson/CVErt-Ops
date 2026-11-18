---
name: performance-audit
description: Run a critical, multi-dimensional performance review with parallel agents across algorithmic complexity, memory/allocation, data access & I/O, concurrency, framework-idiom currency, payload/startup, and an execution-cost map. Use as a performance snapshot, before scaling or optimization work, or when investigating slowness, latency, throughput, or resource usage.
argument-hint: "[optional: specific area/path to focus on, or 'full']"
---

# Performance Audit

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

## Overview

Running a critical performance review of the project.

Focus: **$ARGUMENTS** (default: full review across all applicable dimensions)

This skill detects the stack and version, builds (or reuses) version-specific performance guidance, dispatches independent performance lanes in parallel, and synthesizes a ranked, calibrated report. It is independently invocable as a **snapshot** (no remediation). For the full audit→verify→decide→remediate loop, use the sibling `performance-audit-cycle`.

Companion references (read as needed, one level deep):
- [`finding-model.md`](finding-model.md) — how findings are scored, calibration, the disposition discipline.
- [`currency-protocol.md`](currency-protocol.md) — version-aware currency-brief research + cache.
- [`lane-prompts.md`](lane-prompts.md) — the verbatim dispatch prompts for every lane.
- [`profile-packs/`](profile-packs/) — per-ecosystem lane lenses (`generic-pack.md` is the always-loaded fallback).
- [`run-schema.md`](run-schema.md) — versioned run metadata + ledger + finding fingerprints for historical/regression analysis.
- [`version-indexes/`](version-indexes/) — shipped, build-once "API/feature → version → perf benefit" lookups; the `idiom-currency` lane consults these before any live research.

---

## Philosophy

This is an adversarial review. Each lane agent's job is to find performance problems in its dimension — not to praise what's working.

**Anti-sycophancy rules for all lanes:**
- Lanes MUST NOT open with "performance is generally fine" or soften findings.
- Lanes MUST NOT give scores or grades — just report problems (with impact).
- Lanes MUST NOT pad with cold-path micro-nits. Calibration (`finding-model.md`) governs what to generate; without it, lanes pad.
- If a lane genuinely finds nothing significant, it MUST say "No significant findings" and explain in one sentence what it examined.

**Exception — the Execution Cost Map (`cost-map`) lane is descriptive, not adversarial.** It produces a map of likely time-concentration, not a problem list, and MUST NOT manufacture problems to fill it.

---

## Phase 0 — Stack & version detection

Detect languages, frameworks, **and exact versions** from manifests:

| Manifest | Ecosystem / signals |
|---|---|
| `package.json` + lockfile | Node/JS/TS; React/Angular/Vue/Next versions |
| `pyproject.toml` / `requirements*.txt` / `poetry.lock` | Python; Django/Flask/FastAPI/SQLAlchemy/pandas |
| `go.mod` | Go + module versions |
| `Cargo.toml` / `Cargo.lock` | Rust + crate versions |
| `*.csproj` / `packages.config` / `Directory.Packages.props` | .NET — **modern** (TFM `net8.0`+, `<PackageReference>`) vs **Framework** (TFM `net4x`, `packages.config`) |
| `pom.xml` / `build.gradle(.kts)` | JVM (Java/Kotlin); Spring/Hibernate |
| `Package.swift` / `*.xcodeproj` / `*.xcworkspace` / `Podfile` | Swift; SwiftUI/UIKit, Core Data/SwiftData, SwiftPM/Vapor |
| `Gemfile.lock` / `composer.lock` | (generic fallback) |
| Hand-written SQL — `*.sql`, migration/stored-proc files, embedded query strings, schema DDL | **SQL companion pack** (loads *alongside* the language pack) + dialect: PostgreSQL vs T-SQL/SQL Server |
| HTML documents — `*.html`/`*.htm`, server templates (`*.erb`/`*.jinja`/`*.twig`/`*.blade.php`/`*.cshtml`/`*.njk`), static-site output, `<!DOCTYPE html>` markup | **HTML companion pack** (loads *alongside* the backend that emits the markup) + modules: images-media, fonts |

**The SQL companion pack** (`sql.md`) is **content-detected, not manifest-detected**: load it in addition to the application's language pack whenever hand-written SQL (not just ORM calls) is *material* to the scope — raw queries, views, stored procedures, functions, triggers, or migrations — and load the matching dialect module (`sql/postgres.md` or `sql/tsql.md`) from the database driver/DSN or dialect syntax. The SQL pack reasons best when the **schema/DDL is in scope** (indexes, types, keys); note reduced confidence when it is not. ORM-generated SQL is covered by the language packs' data modules instead. **Follow routine invocations into their definitions:** an `EXEC`/`CALL`/proc-name reference (or DML on a triggered table) in the application code points at hand-rolled SQL whose body lives in a schema/migration file — pull those routine/trigger definitions into scope and audit their bodies, or the most expensive hand-rolled SQL stays invisible (see `sql.md` "Routines").

**The HTML companion pack** (`html.md`) is likewise **content-detected**: load it *alongside* the backend pack whenever rendered HTML markup (static, server-templated, or a JS framework's HTML output) is material to the scope — it owns the **document/rendering/delivery** layer (critical rendering path, render-blocking resources, DOM size, compression/caching, Core Web Vitals) that exists even with little or no JavaScript. Load `html/images-media.md` when the page carries significant imagery/embeds and `html/fonts.md` when it uses web fonts. The **JS bundle** itself (tree-shaking, code-splitting, transpile target) stays with the JS/TS `bundling-build` module — `html.md` is the markup/delivery layer, not the bundler.

**Detection is scoped to the audit scope, not the whole repo.** In a monorepo the root manifest can misrepresent the area under audit — the runner walks up from the scoped files to the nearest governing manifest(s) and profiles *those*. A `full` audit profiles all of them.

Output a **stack profile** (`{ecosystem, framework, version}` tuples + source layout). It selects which profile pack(s) to load and seeds the currency brief. If detection is ambiguous or polyglot, load every matching pack plus `generic-pack.md` and note reduced specificity for unmatched parts.

**Sub-stack modules:** if a matched pack carries a `## Framework / sub-stack modules (load on detection)` map (`dotnet.md`, `go.md`, `python.md`, `javascript-typescript.md`, and `rust.md` all do), load the **core** pack for the project plus only the `<ecosystem>/<module>.md` files whose detection signals appear in the audit scope (e.g. load `dotnet/sql-server-data.md` only when EF/`SqlClient`/Dapper is present; `go/grpc.md` only when `google.golang.org/grpc`/`.proto` is present; `python/orm-database.md` only when Django ORM/SQLAlchemy/psycopg is present; `javascript-typescript/react.md` only when React/JSX is present; `rust/web.md` only when axum/actix-web/hyper is present, `rust/data-parallelism.md` only when rayon/polars is present). This keeps each run pasting only the relevant tech lenses, not the whole pack. Load a module when its technology is **material to the audit scope**, not on an incidental or transitive import — a lone `import json` / `import asyncio` (Python) or a stray `encoding/json` (Go) that is peripheral to the scoped code does not by itself warrant the serialization or async module; load it when that technology is *central* to the code under audit (the scope is serialization-heavy, or built on asyncio). Detection selects *candidates*; materiality decides the load.

---

## Phase 1 — Currency brief (anti-stale-training)

Follow [`currency-protocol.md`](currency-protocol.md). In brief, per detected framework:

0. **Shipped version index first (no network):** if `version-indexes/<ecosystem>.md` exists, it covers version-specific perf knowledge up to its `covered_through`; the live steps below only extend past that. This keeps version-history mining a build-once cost, not a per-run one.
1. **Cheap, best-effort** registry check (1-day TTL) for the latest published version. Failure fails *soft* — never blocks the audit.
2. **Reuse** the cached brief at `docs/perf-audits/cache/<ecosystem>/<framework>@<major.minor>.md` if the in-use version matches, no newer version has appeared, and the 180-day fallback hasn't elapsed.
3. Otherwise **refresh** via live web research and rewrite the cache (with sources).
4. **Offline** → emit "currency brief unavailable"; `idiom-currency` findings are LOW confidence; never fabricate version-specific claims.

The brief is passed to every lane. The consolidated report MUST record which brief (and its `researched_on` date) it used.

---

## Phase 2 — Parallel lane dispatch

The runner MUST dispatch the lanes as **independent, concurrent agents** (embarrassingly parallel — they share no mutable state; packs and the brief are read-only inputs). Read [`lane-prompts.md`](lane-prompts.md) and, for each lane, paste the shared preamble + that lane's body, filling placeholders with the scope, the matched profile-pack slice for that lane — the lane-keyed section of the core pack, **plus the core pack's cross-cutting Runtime/Variant-notes section** (and any companion pack's equivalent — SQL's *Reading the plan & schema*, HTML's *Rendering path & Core Web Vitals*), which is shared context that applies to every lane, **plus** any loaded sub-stack modules relevant to the lane, per Phase 0 — the currency brief, and the output file path. Each agent MUST write its raw report to `docs/perf-audits/` **immediately** on completion (persist-before-synthesis) and also return findings for consolidation.

**Before dispatch, ensure the artifact paths exist** — create `docs/perf-audits/` (and `docs/perf-audits/cache/`) and an empty `docs/perf-audits/runs.jsonl` if absent. They are referenced by `git add` in Phase 8 and written by the lanes; on a first run they won't pre-exist.

**Two equivalent dispatch modes — paste the slice, or have the lane read its own.** Both must deliver each lane the same lens (its lane-keyed slice **+** the cross-cutting Runtime/Variant-notes section **+** the Phase-0 modules + the brief):
- **Runner pastes the slice** (the description above) — best when the runner already holds the packs in context and the lane count is small.
- **Lane reads its own slice** (first-class — and the **common** case when lanes are dispatched as subagents that do *not* share the runner's skill registry, so they can't invoke this skill by name). The runner instead tells each lane the exact files to read for itself from this skill's install location — `…/performance-audit/profile-packs/<ecosystem>.md` + the relevant `<ecosystem>/<module>.md` + the matching `version-indexes/<ecosystem>.md` — passing only the scope, the brief (or its path), and the output path. This avoids the runner holding and re-pasting every pack across 6–8 lanes (a real context cost at scale). Reading-its-own-slice is **not** licence to walk the whole pack as a checklist — the reference-not-checklist rule in the preamble still governs.

### Lanes

| Lane | id | Run? |
|------|----|------|
| Algorithmic complexity & data structures | `algorithmic` | always |
| Memory & allocation | `memory` | always |
| Data access & I/O | `data-access` | always |
| Concurrency & parallelization | `concurrency` | always |
| Framework-idiom currency | `idiom-currency` | always (uses brief) |
| Execution Cost Map (a map, not findings) | `cost-map` | always |
| Payload / startup / build | `payload-startup` | conditional — only when the stack has such a surface (frontend / serverless / CLI / mobile) |
| Dynamic profiling & benchmarking | `dynamic` | optional — only when the env can build+run AND a real workload exists/can be defensibly built (never invent load) |

The six core lanes (`algorithmic`, `memory`, `data-access`, `concurrency`, `idiom-currency`, `cost-map`) always run **for a standalone, bounded (FULL-depth) audit** — the default. The runner MUST decide `payload-startup` and `dynamic` from the stack profile and environment, and MUST state in the report which lanes ran and why any were skipped. **Refer to lanes by these names, never by bare number** — "Lane 4" is meaningless outside this skill (see Rules).

### Depth tiers (reduced & cold-sweep invocations)

A FULL audit runs the six core lanes. When this skill is invoked as one slice of a tiered whole-repo plan (see the cycle's [`whole-repo-scoping.md`](../performance-audit-cycle/whole-repo-scoping.md)), it MAY run a **reduced lane subset** matched to the slice's tier — coverage without waste on warm/cold code:

| Tier | Lanes to run | When |
|------|--------------|------|
| **FULL** | all six core (+ `payload-startup`/`dynamic` as applicable) | HOT slices; any standalone bounded audit |
| **REDUCED** | `algorithmic`, `memory`, `data-access`, `concurrency` (+ `idiom-currency` only where a framework/library idiom surface exists; `cost-map` optional) | WARM slices — live but bounded/low-frequency work |
| **COLD SWEEP** | one batched run, ~3 lanes: `algorithmic`, `memory`, `data-access` | batched cold glue (CRUD/config/DTO marshalling) — many units in one run |

A reduced or cold-sweep run is a **deliberate, recorded** choice, not silent lane-skipping: the report MUST state the tier and which lanes ran and why. Reduced depth is *not* a licence to under-calibrate — calibration still governs generation, and a warm slice can legitimately come back all-minor (that's the model working, not the depth failing).

### Agent model selection

Each subagent SHOULD be invoked using the **latest available Claude Opus model** or **GPT-5 (or successor) at x-high reasoning effort**, unless the user has explicitly instructed otherwise for this run. Performance analysis benefits asymmetrically from maximum reasoning bandwidth, and saving model cost trades poorly against missed regressions that ship to production. If the framework requires a model parameter on dispatch, set it; if it inherits the parent's model, ensure the parent is on the strongest tier before dispatching.

**Record the request honestly, not a guessed identity.** Some harnesses let you set the subagent *model* but expose **no reasoning-effort knob** (the Claude Code Agent tool, for one). When you can't actually request x-high, record `reasoning_effort: "default (harness exposes no knob)"` in the run metadata rather than claiming x-high — the metadata captures what was *requested*, and an honest "default" is correct where the dial doesn't exist.

The runner MUST wait for all dispatched lanes to complete before Phase 3.

---

## Phase 3 — Synthesis

After all lanes complete, compile one consolidated report:

1. **Deduplicate** across lanes — cross-lane agreement is a **confidence signal, not redundancy**: note which lanes flagged each and **lead the report with the most-agreed findings**. High overlap on a small hot core (the same hot symbol seen through several lane framings — algorithmic "defeats the cache", memory "per-call alloc", idiom-currency "library fast-path") is *expected*, not noise; collapse it to one finding with one fingerprint and record the agreement count.
2. **Rank** by the finding model (`finding-model.md`): Impact × Confidence, Effort sequencing within bands.
3. **Cross-reference the Execution Cost Map** — a finding on a mapped hot region gets its Impact confirmed; one in cold territory is down-weighted (state, per finding, whether it intersects the map).
4. **Group** cross-cutting root causes.
5. **Measurability note** — note whether the identified hot paths can be *observed* in production (metrics/traces present, or would confirming the win require adding instrumentation first?). Flag findings that can't be measured post-fix.
6. **Merge** every lane's "Suspected Bugs" sections into one Suspected Bugs appendix and, if any exist, **auto-write the bug-hunt kickoff prompt** (below).
7. **Capture run metadata** per [`run-schema.md`](run-schema.md): assign a fingerprint to every finding, emit the versioned frontmatter on the report, append one record to `docs/perf-audits/runs.jsonl`, and compute the regression diff against the most recent prior run for the same scope (new / persisting / resolved). Call out **new** and **resolved** findings in the executive summary — that's the regression signal.

**Lanes may correct the scope brief — adopt the code-grounded value.** A lane's reading of the actual code is primary over the scope summary's load/frequency claims (the shared preamble says so). When a lane corrects a load assumption from source (a re-render briefed as ~1 Hz read as 4 Hz; a "DSP real-time" path found to be batch and off the audio callback), the synthesis MUST adopt the corrected value, re-rank accordingly, and **record the correction** in the report (frontmatter or summary). A wrong scope brief must not silently survive into the ranking — this is what makes the audit robust to an imperfect scope summary.

The runner MUST account for every finding from every lane in the consolidated report. The runner MUST NOT drop a surfaced finding as "too minor" — that is the user's call (in the cycle). Calibration governs *generation*, not post-hoc suppression.

**Dispatch lanes blind.** Give the lanes load/scope context only — **not** a list of already-suspected findings. Feeding lanes the answer measures confirmation; withholding it measures *discovery* (in real-world use, blind lanes reproduced a 5-round review's entire hot-path map **and** added findings it missed). The only thing pre-seeded as adjacent context is a *descriptive* frequency/hot-path map when cross-slice calibration needs it (per the cycle's whole-repo method) — never the conclusions.

### Consolidated report format

Save raw per-lane reports immediately (`docs/perf-audits/<date>T<HH-MM>-<slug>-<lane>.md`), then:

```markdown
---
<run-schema.md frontmatter block — run_schema_version, run_id, date, methodology,
 dispatch (model_requested + reasoning_effort), stack, currency_briefs, lanes_run,
 finding_counts, regression>
---
# Performance Audit — <Scope>
**Date:** YYYY-MM-DD HH:MM   **Scope:** <full | area>
**Stack:** <ecosystem/framework@version …>
**Currency brief:** <which brief(s), researched_on dates, or "offline">
**Lanes run:** <list; note any skipped + why>
**Regression vs <prev_run_id|none>:** <N new, N persisting, N resolved> — new/resolved listed below

## Critical Findings
### P1. <title>
**Lanes:** <which flagged it>   **Location:** <file:line or pattern>
**Fingerprint:** `<lane-id>:<file>:<symbol>:<title-slug>` (e.g. `data-access:inventory.py:enrich_line_items:n-plus-1`)   **Status:** <new|persisting|resolved>
**Problem:** …   **Impact:** <reachability × frequency × per-occurrence cost>
**Confidence:** <Measured|Strong-static|Heuristic>   **On cost map:** <yes/no>
**Effort:** <Localized|Contained|Cross-cutting>
**Verification plan:** <benchmark/argument + correctness guard>

## Major Findings
…
## Minor Findings
…
## Cross-Cutting Themes
…
## Measurability
<can these hot paths be observed in prod? what needs instrumentation?>

## Execution Cost Map
> Architectural awareness, NOT an optimization to-do list.
### Likely time-concentration regions
- **<region>** — basis: <structural reasoning> — confidence: <High|Med|Low> — <map-only | also Pn>
### Notes for architecture
- …

## Suspected Bugs (for follow-up — NOT addressed here)
> Correctness bugs noticed during the audit. This audit does not fix or chase them.
> Run bug-hunt-cycle; a ready-to-use kickoff prompt is at
> docs/perf-audits/<date>-<slug>-bug-hunt-kickoff.md.
### SB1. <title>
**Location:** <file:line>   **What looks wrong:** …   **Why suspected:** …
```

Consolidated file: `docs/perf-audits/<date>T<HH-MM>-<slug>-consolidated.md`.

### Bug-hunt kickoff prompt (auto-written when suspected bugs exist)

If the Suspected Bugs appendix is non-empty, the runner MUST write `docs/perf-audits/<date>-<slug>-bug-hunt-kickoff.md` containing a paste-ready prompt, and MUST suggest the user run it — but MUST NOT auto-invoke `bug-hunt-cycle`. Template:

```markdown
# Bug-hunt kickoff — suspected bugs from the <date> performance audit

Run: `bug-hunt-cycle` with the scope below.

**Scope:** <the files containing the suspected bugs + one-paragraph context per area>

**Seed findings (verify, don't trust — surfaced incidentally during a perf audit):**
- <SB1 title> — <file:line> — <what looks wrong, why>
- <SB2 …>

These were noticed while auditing performance and were NOT investigated. Treat them
as leads for the hunters, not confirmed bugs.
```

If there are no suspected bugs, write "None" in the appendix and skip the kickoff file.

---

## Artifacts

- Per-lane raw: `docs/perf-audits/<date>T<HH-MM>-<slug>-<lane>.md`
- Consolidated: `docs/perf-audits/<date>T<HH-MM>-<slug>-consolidated.md` (with versioned frontmatter per `run-schema.md`)
- Run ledger: `docs/perf-audits/runs.jsonl` (one appended record per run — the regression/trend substrate)
- Bug-hunt kickoff (if any): `docs/perf-audits/<date>-<slug>-bug-hunt-kickoff.md`
- Currency cache: `docs/perf-audits/cache/<ecosystem>/<framework>@<major.minor>.md`

The runner MUST save each raw lane report as soon as that lane completes — MUST NOT wait for synthesis — so analysis survives interruption.

---

## Rules

- Lanes MUST read **actual source code**, not just `CLAUDE.md` / `AGENTS.md`.
- Findings MUST be **actionable** and carry the full finding model (Impact/Confidence/Effort/Verification).
- Effort MUST be expressed as work magnitude, never wall-clock (see `finding-model.md`).
- The runner MUST dispatch all applicable lanes; dropping lanes breaks the independence primitive that makes the review work.
- The runner MUST NOT inflate minors to look thorough, nor downgrade criticals to avoid alarm.
- Correctness bugs are recorded and handed off, never chased here.
- **Write for readers without your context.** Lane names and finding IDs (`P1`, fingerprints) are internal scaffolding. In any outward-facing text — commit messages, PR titles/bodies, code comments, remediation-plan task titles, questions to the user — describe the finding in self-contained terms (what / where / why); never use a bare lane name/number or ID as the sole referent ("addresses the `concurrency` lane" / "fixes P3" is meaningless to others). The ID may be appended as a traceability suffix only. See `finding-model.md` "Referring to findings".
