# Whole-Repo / Oversized-Scope Slicing (method)

**Load this when:** the requested audit scope is a whole repository, a top-level
directory/package set, "everything", "all of `<X>`", or any surface materially
larger than one `performance-audit-cycle` run is optimized for. A single cycle's
lanes perform best on a **precise, bounded, perf-relevant** surface (one coherent
subsystem — see [Sizing](#sizing-how-big-is-one-slice)). This method turns "audit the whole thing" into a
**reviewed partition** of bounded slices, each fed to its own cycle run, that
collectively cover all the code — avoiding both naïve failure modes: mega-runs
(lane precision collapses on huge scope) and over-fragmentation (Impact
mis-calibrates when a finding's caller lives in another slice).

> **Provenance / how to read this.** Distilled from a real whole-repo application
> (a ~96k-LOC Rust+TypeScript desktop app) hardened over **five adversarial
> rounds**, then generalized across ecosystems via three further reviews
> (generalizability, robustness, followability). The skeleton — survey → cheap
> hot-path/reachability map → slice into coherent bounded units → cross-slice
> frequency calibration → depth tiers → **review-gate-before-spend** — is the
> durable, ecosystem-agnostic contribution. Numbers and examples are calibrated
> to that case and carry explicit ecosystem-scaling rules; tune them, don't copy
> them blindly. *[case]* marks lessons from the worked example.

---

## TL;DR — minimal ordered checklist

1. **Route by size.** Named bounded scope → run the cycle directly. ≤2 slices / small
   → **lightweight path** (survey + eyeball + run + 3-line ledger, no gate). Else →
   full method.
2. **One program, or many?** Monorepo of deployables → one plan+ledger *per
   deployable*; shared libs audited once.
3. **Survey & measure production LOC.** Production LOC per unit (`tokei` minus the exclude table);
   record raw→prod delta.
4. **Map the hot paths & reachability.** Classify workload (CPU / IO / event-driven); run the HOT/WARM/COLD
   checklist; "no hot path" is valid.
5. **Cut the slices.** Coherent subsystems; the split/keep rule; prefer fewer/larger;
   complete the disjoint-coverage ledger.
6. **Calibrate cross-slice frequency.** Only for a hot symbol whose caller is in another slice —
   ≤1-page frequency map; unknown caller → assume-hot.
7. **Assign depth tiers & verification modes.** HOT→FULL, WARM→REDUCED, COLD→sweep(s), cross-slice→OVERLAY.
8. **Review the partition before executing.** Review depth scales with slice count; skip for 1–2 slices.
9. **Order, persist, execute.** Hottest first; commit per slice; ledger =
   resumable.

---

## Route by size (three-way, don't over-ceremony the small case)

- **Precise bounded scope** (user named a request path / module / package that
  fits one run): skip this method — run the cycle directly.
- **Lightweight path** — PRIMARY gate **≤2 natural slices**; LOC is a secondary,
  language-scaled check (~<8k for verbose ecosystems, ~<4k for dense ones — see
  [Sizing](#sizing-how-big-is-one-slice)) across ≤2 languages: do the survey & measure step, eyeball the 1–2 slices,
  run the cycle on each, a 3-line ledger, **no formal review round** (a 5-minute
  self-check against the heuristics table is enough). Only build a frequency map
  (the cross-slice frequency calibration) if a hot impl's caller sits in the other slice. **Self-check the cross-slice frequency blind
  spot:** confirm no hot symbol's frequency is driven from the other slice; if it
  is, build the ≤1-page frequency map even on the lightweight path.
- **Full method** — a repo / multi-package / >~8k LOC / >2 languages: the full survey-through-execute method + the
  review gate, with review depth scaled by slice count (see the gate).

## One program, or many? (do this before partitioning)
If the repo holds **multiple deployable units** (a Go monorepo of services, a
multi-module Gradle build, a .NET solution of many `.csproj`, an Nx/Turborepo of
apps), the audit unit is the **deployable service/app, not the repo**. Produce a
service inventory and run a **separate slice plan + coverage ledger + run
history per service**. **Shared libraries** consumed by several services are
audited **once** as their own slice and *referenced* by each service's ledger
(marked `shared` — neither re-sliced per consumer nor dropped). Cross-*service*
frequency is set over the network (see the cross-slice frequency calibration). Only after this do you partition
within a single program.

- **.NET caveat:** a `.csproj` is usually a **library, not a deployable** — the
  deployable is the **entry-point project** (Web/Worker/Api); the rest are shared
  libs (audit once, reference). Do not produce one "service" partition per
  `.csproj`.
- **Same axis at two scales:** the one-program-or-many step (the deployable split) and the
  process-boundary split (the one-primary-ecosystem principle) are the **same axis at two scales** — a
  backend+SPA in one repo is a *process boundary* handled by the one-primary-ecosystem principle, **not** a
  per-service split.
- **Data/ML repos (notebooks, pipelines):** the audit unit is the **DAG stage /
  pipeline step**, not a package or notebook; the hot path is a dataframe/Spark op
  or a data-loader; size by **stage + data volume**, not LOC band; partition along
  **DAG-stage seams** (cell/stage execution order replaces the call graph).

---

## Survey & measure production LOC (measure the real surface)

Enumerate before slicing:
- **Build units** (packages/crates/modules/services) from manifests; **languages/
  ecosystems** per area (decides profile packs + lanes).
- **Size on PRODUCTION LOC, not raw LOC** — the #1 trap *[case: a 9.1k-LOC
  "module" was 4.5k production; raw-LOC sizing produced a 2× too-granular
  partition]*. **How to measure concretely:**
  - Baseline with a tool: `tokei --output json` / `scc` per directory.
  - **Exclude** tests, generated, vendored, fixtures, non-code. Tells by ecosystem:

    | Ecosystem | Exclude (tests / generated / vendored) |
    |---|---|
    | Rust | inline `#[cfg(test)]` spans, `tests/`, `benches/`, `target/` |
    | Go | `*_test.go`, `*.pb.go`/`*_gen.go` + `// Code generated` banner, `vendor/` |
    | Python | `tests/`, `test_*.py`/`*_test.py`, `conftest.py`, `__pycache__/`, `migrations/`, `*_pb2.py`, `.venv/` |
    | JS/TS | `*.test.*`/`*.spec.*`, `__tests__`, `*.stories.*`, snapshot dirs, `*.d.ts` gen, `dist/`/`build/`, `node_modules/` |
    | Java/Kotlin | `src/test/`, generated sources dir (incl. generated gRPC/proto stubs), `build/` |
    | C#/.NET | `*.Tests`, `obj/`/`bin/`, `*.Designer.cs`, `*.g.cs`, `*.AssemblyInfo.cs`, EF Core `Migrations/`, generated gRPC/proto stubs |
  - Subtract inline-test line spans (they inflate same-file counts); detect
    generated code by header banner (`@generated`, `Code generated … DO NOT EDIT`).
  - **Record raw→production delta per unit** (the ratio is non-uniform — 0.1×–6.9×
    observed *[case]*; Python/Ruby skew low, Go/Java skew high with test+gen).
- Output a **survey table**: unit → language → production LOC → one-line purpose.

## Map the hot paths & reachability (cheap, structural)

**First classify the workload shape — it changes what "hot" means:**
- **CPU-bound / real-time** (desktop, games, codecs, data kernels, DSP): hot path
  = inner loops, allocation, per-frame/per-message/callback handlers. Grep for the
  loop / hot kernel / real-time callback.
- **IO-bound services** (web, RPC, most microservices): hot path = **DB
  round-trips, N+1 / unbatched queries, cache misses, external-call fan-out,
  serialization** — sized by request/throughput rate, **NOT** inner loops. Grep
  for ORM access in handlers, query-in-loop, `await` fan-out, missing batching.
- **Event-driven / serverless**: entry points live in **config/IaC** (queue/cron/
  HTTP bindings — `serverless.yml`, SAM, function manifests), not the call graph.
  Read the manifest to find entry points + their frequency (queue rate, cron).

Then map where work concentrates **and** classify the calibration hazards:
- **Cold glue** — CRUD, IPC/DTO marshalling, config, string assembly, form
  rendering; **JVM/.NET add** DI wiring, annotation glue, getters/mappers (a LOT
  of it → the COLD SWEEP is *more* valuable there). Batch it.
- **Latent / dead code** — no live callers; findings are *reachability ≈ 0 today*,
  flag "fires once wired in" *[case: a codec crate had zero callers; the live path
  bypassed it]*. **Detection (cheap):** grep call sites + imports + manifest
  wiring. **CONFIRM before flagging dead** — dynamic dispatch, trait objects, FFI,
  plugins, **and especially framework wiring (routers, DI containers,
  `@Scheduled`/`@EventListener`/Celery/Sidekiq task names, signals, webhooks,
  reflection, cloud event bindings (queue/cron/HTTP triggers declared in IaC),
  Python import-time registries (decorators only wire if the module is imported —
  import graph ≠ call graph))** defeat grep. "No in-tree caller" is NOT dead in
  dynamic/DI/serverless code → treat as **LIVE-uncertain** until you've checked the
  framework's wiring.
- **External-process boundaries** — work done in a child process / DB / cache /
  queue / GPU / remote service. The audited code there is **I/O + orchestration**,
  not the compute → reduced tier *[case: a "DSP" module was TCP plumbing to an
  external TNC; the web analogue: an ORM call is orchestration — the query plan
  runs in Postgres, so read the query, not just the Python]*.
- **VERIFY hot-path hypotheses against code; never infer from names** *[case: a
  "waterfall UI" had no canvas/`requestAnimationFrame` — it was ordinary React]*.
- **"No hot path" is a valid outcome.** A uniformly-flat CRUD app legitimately
  partitions into mostly COLD SWEEPS — state that and move on; don't manufacture
  an imaginary hot path.

**Hot / warm / cold checklist (apply per candidate slice):**
A slice is **HOT** if ANY: it sits on the request/render/frame/message path AND
contains a loop/allocation/query that scales with load; it's a real-time/
deadline path; it's IO-bound with N+1/fan-out under load. **WARM** if it's on a
live path but with bounded/low-frequency work, or a secondary/occasional path.
**COLD** if it's setup/config/glue/CRUD with no load-scaling work.
**Tie-breaker:** if you can't find the loop/handler/query that makes it hot, it is
**not** hot → default **WARM** (never silently assume hot or cold).

**Slice-tier vs finding-frequency axes (don't conflate them):** these are different axes — an
unverified-hot **slice** is tiered WARM by the hot/warm/cold tie-breaker; a confirmed-hot
**finding** whose cross-slice **frequency** is unresolved is ranked assume-hot by the
frequency fail-safe. Don't apply the frequency fail-safe's optimistic-Impact rule to a whole slice's tier.

## Cut the slices (principles + crisp rules)

1. **One primary ecosystem per slice — keep embedded languages with their
   driver.** A slice has ONE primary pack (its lanes / idiom index). Embedded
   second languages *driven by* the primary code — SQL in an ORM/query layer, a
   shader, an inline regex/template — stay **in the slice as adjacent context**
   (run the SQL/HTML sub-pack as a sub-lane); do **not** carve them into a separate
   slice that would be split from their caller (that is a cross-slice impl/caller split you
   *induced*). Carve a separate-language slice only at a **real process/deploy
   boundary** (UI↔backend IPC, service↔service, app↔external engine). For a polyglot
   *feature* spanning a process boundary, prefer an **OVERLAY** to recover the
   end-to-end cost rather than pretending per-language slices capture it. *[case:
   Rust↔TS there was a real IPC boundary, so "never mix" happened to coincide with
   a seam; in a Django/Spring service the languages interleave in one call stack —
   splitting SQL from its Python/Java driver would fracture one perf story.]*
2. **Coherent subsystem + shared data flow** per slice (one pipeline stage / one
   feature / one service-triplet), not an arbitrary chunk.
3. **Size to the sweet-spot, by build-unit first, LOC as a sanity check** (see
   [Sizing](#sizing-how-big-is-one-slice)). Split larger along **real module/file seams** (name the files per
   sub-slice). **God-file with no seams:** synthesize seams by symbol cluster /
   call-graph community, run the pieces as an OVERLAY family, and flag the file
   itself as a maintainability finding.
4. **Slice by perf-relevance, not raw size** — carve genuine hot paths out; pull a
   warm exception out of a cold bucket; batch the rest. **Perf-relevance overrides
   LOC for merge/split:** never merge away a hot slice because it's small — an
   IO-orchestration layer is small by LOC but large by Impact.
5. **Complete, disjoint coverage** — every code unit in **exactly one** slice;
   maintain a coverage ledger reconciled against an actual file listing; list
   **out-of-scope** explicitly (tests, `bin/` probes, generated). **OVERLAYs are
   analysis-only passes, NOT coverage units** — they do NOT appear in the
   disjoint-coverage ledger (their member slices already do) and do not emit a
   `runs.jsonl` regression line the same way. **Generated-but-
   hot exception:** if generated code is genuinely on a hot path (a generated
   parser/codec/serializer), audit it FULL, tag `generated-source`, and target the
   **generator/template**, not the emitted file. *[case: a Rust command module was
   orphaned by a name collision with a same-named frontend dir; only the ledger
   caught it.]*

**The split/keep rule** (replaces prose judgment): **SPLIT** a
candidate iff its two halves have *different hot-path character* OR *different
primary ecosystems* OR it exceeds the sized band (see [Sizing](#sizing-how-big-is-one-slice)) with a real seam. **KEEP
together** iff they share a data flow AND a frequency driver AND fit the band.
**Tie-breaker: prefer fewer/larger** — over-fragmentation fails *silently* (cross-slice frequency
mis-rank), oversize fails *loudly* (the run tells you it's too big and you
re-slice once; see *Order, persist, execute*).

## Sizing — how big is one slice?

**The build-unit / coherent-subsystem is the PRIMARY sizer** — one package/crate/
module/service-triplet/pipeline-stage, cut along real seams (per *Cut the slices*). Size by *what is
a coherent perf story*, not by hitting a LOC number.

**Production-LOC band as a sanity check** (per-ecosystem, because verbosity
differs — a number that's "too big" in one ecosystem is mid-band in another):

| Ecosystem | Per-slice production-LOC band (sanity check) |
|---|---|
| Python / Ruby | ~0.5–2k |
| Rust / TS | ~1–4k |
| Go / Java / Kotlin / C# | ~2–6k |
| C / C++ | by **translation unit**, not a flat band |

If a build-unit lands outside its band, that's a prompt to look for a seam (split)
or a sibling to merge — not a hard rule. The band is the *check*; the build-unit
is the *sizer*.

**Note:** "~100k LOC → ~10–20 units" is a **Rust/TS datapoint** *[case]* — count
**features/services, not lines**. Don't port that unit-count to a denser or more
verbose ecosystem without re-deriving it from the band above.

## Calibrate cross-slice frequency (the subtle one; make it fail-safe)

Impact = reachability × **frequency** × per-occurrence cost, and the frequency is
often set by a **caller in a different slice** (or **outside the codebase** — see
below). When impl and hot caller are split, the impl's slice can't see how often
it runs and **under-ranks** it. Make this **demand-driven, bounded, and
fail-safe** — never a global whole-program analysis:
- **Only trigger on a detected impl/caller split** (a slice's hot symbol whose
  callers aren't in-slice). Do not build a global call map.
- **Bound the traversal:** stop at the first of {a nameable frequency *class* —
  per-request / per-frame / per-message / loop-over-N / per-row}, an entry point,
  or 3 caller frames. No infinite "what-calls-the-caller" regress.
- **Mitigate (cheapest first):** (a) a ≤1-page **frequency-map pre-artifact**
  (`impl symbol → caller file:line → multiplier class → N`) handed to the affected
  runs as adjacent context *[case: a compression routine's real driver was an
  Outbox-loop in a cold-swept file; a one-page map fixed calibration without
  re-tiering]*; (b) **order** runs so the frequency-establishing slice precedes the
  impl slice; (c) **merge** the two if small and tightly coupled.
- **Out-of-tree frequency:** for services, frequency is set by request rate / queue
  depth / cron cadence / fan-out / **inter-service network calls** (service A calls
  B's endpoint N×/request — read API contracts/clients/tracing). Capture these in
  the frequency map as first-class inputs (from load context / IaC), not just
  in-tree counts.
- **Shared-substrate fan-in:** a shared lib called in-process by N units is a
  many-to-one **fan-in** — calibrate its frequency by the **hottest caller** (the
  union of caller frequency classes), and tier it by that.
- **Fail-safe:** if the caller is unknown or unaudited, tag the finding
  `frequency-unresolved — assume hot` at **optimistic** Impact; the cycle's
  Phase-3 cross-validation re-ranks it **if it can resolve the caller** — but if
  the caller stays unresolved, **surface the finding in the roll-up for the
  operator to confirm reachability**, rather than letting an unverified assume-hot
  finding ship top-ranked. (Phase 3 re-reads cited code and re-ranks Impact by
  reachability, so it demotes when it CAN reach the caller; the roll-up surface
  covers the case where it can't.) Never silently under-rank a real one.

## Assign depth tiers & verification modes

- **FULL** (all phases, all core lanes) — HOT slices.
- **REDUCED** (algorithmic/memory/data-access/concurrency; skip idiom-currency/
  payload-startup unless flagged) — WARM slices.
- **COLD SWEEP** (one batched run, ~3 lanes: complexity + allocation + data-access)
  over all COLD glue at once — coverage without waste. Batched **up to one run's
  capacity (the [Sizing](#sizing-how-big-is-one-slice) band)** — cold glue exceeding
  that gets **several** cold sweeps partitioned by build-unit/area, not one. The
  economy is *fewer lanes per run*, not *unbounded LOC per run*.
- **OVERLAY** (analysis-only) — a hot pipeline spanning several slices; run after
  its members. Same capacity caveat: an OVERLAY spanning more than one run's
  capacity (the [Sizing](#sizing-how-big-is-one-slice) band) is split into several
  overlay passes, not run as one oversized pass.

**Map the hot/warm/cold checklist result → tier:** HOT→FULL, WARM→REDUCED,
COLD→the sweep, cross-slice-pipeline→OVERLAY.

**Verification mode** per slice: can the environment build+run it (dynamic lane /
`Measured` confidence available), or is it static-only / **deferred**? Deferred
covers physical hardware (a device/rig) **and** "needs a load test / production-
like dataset / a staging service that doesn't exist locally." State it so
fix-plans rely on complexity/allocation arguments, **never fabricated numbers**,
where measurement isn't possible *[case: rig-timing findings were unfalsifiable
without radio hardware].*

## Order, persist, execute (resumable)

- **Execution order**: hottest first; frequency-establishers before their impl
  slices; overlays after members; cold sweep last. Maintain an explicit
  **slice-dependency list** (use the project's dep-graph mechanism — e.g. `bd dep`
  edges — if it has one).
- **Persistent artifacts (mandatory — the job must survive a context reset /
  ephemeral container):**
  - **Slice plan** — the partition (per slice: paths, language, production LOC,
    tier, verification mode, adjacent-context/frequency-map pointers) + coverage
    ledger + out-of-scope list + **the planning commit SHA**.
  - **Progress ledger** — a row per slice: `id | tier | scope paths | state
    (PENDING/IN-PROGRESS/DONE/SKIPPED) | artifact paths`, plus a "how to resume"
    header (read plan + ledger, pick first non-DONE). Commit it; update it per
    slice.
  - **Run ledger** (`runs.jsonl`) — one line per executed run, for regression.
- **Commit per slice** (consolidated report + ledger update). Never batch a repo's
  worth of audit into one commit.
- **Coverage drift:** before each slice, confirm its paths still exist; at the end,
  re-diff the coverage ledger against the **current** tree (vs the planning SHA) —
  renamed/added files must be re-homed, not dropped.
- **Mid-execution mis-scope:** if a slice's own run reveals it's too big/small,
  **re-slice that region at most once**, record it in the ledger, then proceed; if
  still wrong, escalate to the user rather than thrash.
- **Repo-level roll-up:** after the slices, a short cross-slice synthesis (shared
  root causes, repo-wide themes, heat map). **Conditionally REQUIRED** when the
  request was a posture question ("how's the repo's performance?"); optional when
  it was "find and queue fixes". For a **service monorepo** the roll-up is
  **two-level** — a per-service synthesis, then a cross-service meta-roll-up.

---

## Review the partition before executing — adversarially review the partition *before* executing runs

The partition is itself a substantive artifact and a single pass misses
cross-slice defects *[case: four hot-path-hunting rounds converged "clean"; the
fifth, a **partition-design** lens, found a cross-slice calibration defect they
all missed]*. **Scale review depth to slice count — the 5-round case is the
CEILING, not the default:**

| Slices | Review |
|---|---|
| 1–2 (lightweight) | none — 5-min self-check vs the heuristics table |
| 3–5 | 1 general round (fold the partition-design checklist into it) |
| 6–12 | 1 round, **partition-design lens REQUIRED** (its explicit job is cross-slice calibration, not finding-hunting) |
| 13+ / high-stakes | ≥2 rounds, ≥1 dedicated partition-design |

Each reviewer attacks, grounded in actual code: sizing (production vs raw LOC);
hot-path accuracy (verify / refute imaginary / find missed); mis-tiered slices
(cold-as-warm, warm-as-cold, latent not flagged); **cross-slice frequency splits**
(the class a hot-path-only review reliably misses); coverage gaps / double-counts
/ language mis-bucketing; the fewer-larger vs finer-grained tradeoff. Revise
between rounds; finalize when a round finds only nits.

## When in doubt
- **Can't tell if code is hot** (no visible entry point, dynamic dispatch) → WARM +
  `frequency-unresolved`, let the run's cross-validation sort it; don't guess HOT/COLD.
- **Can't find a seam to split an oversize unit** → synthetic-seam OVERLAY family +
  flag the file; don't drop or force one giant run.
- **User disagrees with a slice** → their call on scope; record it and re-slice.
- **Generated/dynamic makes coverage uncertain** → mark `coverage-uncertain` in the
  ledger and surface it, rather than claiming false completeness.

## Heuristics & anti-patterns (quick reference)

| Trap | Rule |
|------|------|
| Size on raw LOC | Measure **production** LOC; non-uniform ratio; build-unit is the primary sizer. |
| One LOC band for all languages | Scale by verbosity; build-unit is the primary sizer (see [Sizing](#sizing-how-big-is-one-slice)). |
| Infer hot paths from names | **Verify against code**; classify workload shape first (CPU vs IO vs event-driven). |
| "Hot path = CPU loop" everywhere | For services it's DB/N+1/fan-out/serialization, sized by request rate. |
| "No in-tree caller = dead" | Not in dynamic/DI/serverless code — check framework wiring; else LIVE-uncertain. |
| "Never mix languages" absolutely | One primary pack; embedded langs stay with their driver; split only at process/deploy boundaries. |
| One mega-run / one-per-file | Coherent bounded subsystems; the split/keep rule with prefer-fewer tie-breaker. |
| Full cycle on cold glue | Batch into one COLD SWEEP. |
| Latent/external code ranked hot | reachability≈0 "fires once wired in" / external-process = orchestration → reduced. |
| Impl + caller in different slices | Demand-driven, bounded, fail-safe cross-slice frequency calibration (assume-hot on unknown). |
| Promise measurements you can't take | Tag verification mode (hardware OR load-test/staging deferred); complexity argument, never fake numbers. |
| Repo = the audit unit always | For service monorepos the unit is the deployable service; shared libs audited once. |
| Trust a single partition pass | Review depth scaled to slice count; ≥1 partition-design lens at 6+ slices. |

## What this method produces (hand-off to the cycle)
A **reviewed slice plan** (ordered slices with {paths, language, production LOC,
tier, verification mode, frequency-map pointers}, coverage ledger, out-of-scope
list, planning SHA) + a progress ledger. Each FULL/REDUCED slice → a normal
`performance-audit-cycle` run; the COLD SWEEP → one trimmed `performance-audit`
run; OVERLAYS → analysis passes. The ledger makes the whole-repo job resumable.
