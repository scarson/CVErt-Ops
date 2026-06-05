# Field feedback — `performance-audit` / `performance-audit-cycle` (whole-repo run on CVErt-Ops)

ABOUTME: Running, tagged feedback on the performance-audit skill family, kept live during a real
ABOUTME: whole-repo audit so the maintainer (Sam) can fold it back into the skill.

> Legend: 👍 worked well · 🟡 friction / ambiguity · 🐞 likely defect · 💡 suggestion.
> Updated after each slice. Newest notes may be appended within a section.

## Context header

```
Repo / project:   CVErt-Ops — multi-tenant CVE vulnerability-intelligence service (Go API + worker + Vue SPA)
Scale:            ~42k Go prod LOC + ~9.2k Vue/TS prod LOC; 2 ecosystems; single Go module + embedded SPA
Stack highlights: Go 1.26, PostgreSQL 15+, pgx/v5 (+database/sql adapter, simple protocol), sqlc + squirrel,
                  huma/v2 + chi, RE2 regexp, JCS hashing, Gemini client; Vue 3 + Vite + Pinia
Skill(s)+version: performance-audit + performance-audit-cycle; superpowers-plus@0.2.0 (vendored into .claude/skills/)
Harness:          Claude Code (web/remote, ephemeral container). Lanes dispatched via the Agent tool as
                  async background general-purpose subagents. Agent tool exposes a MODEL knob (set opus)
                  but NO reasoning-effort knob.
Scope run:        Whole repo via whole-repo-scoping.md → 10-slice reviewed partition + O1 overlay + roll-up
Depth:            FULL (S1–S4 done), REDUCED (S5–S7), COLD SWEEP (S8–S10); 6 / 4 / 3 lanes respectively
Blind run?        Yes — lanes given load/scope context only, never the suspected findings
```

## Methodology asks (the two the template calls out)

- **Blind discovery: YES, and it is the headline result.** Lanes received load/scope context but not the
  answers, and they *discovered* the hot cores independently. The strongest evidence: on S2, **four
  independent lanes (algorithmic, memory, data-access, concurrency) converged on the same two criticals**
  ("realtime re-loads the entire rule set per changed CVE" + "one candidate query per CVE×rule") without
  being told. Cross-lane agreement read cleanly as a confidence signal, exactly as the skill claims. 👍
- **Anti-padding stress: passed, repeatedly and unprompted.** Lanes returned honest non-findings instead of
  nits: S4 lanes *refuted the scope brief's "facet aggregation over corpus" region* (faceting isn't
  implemented) rather than inventing a facet finding; S2's idiom lane opened "No CRITICAL or MAJOR — the
  engine is current-Go"; S2 lanes explicitly dismissed the regex postfilter as "correctly bounded, NOT a
  finding." Lanes also **corrected the scope brief from source** (S1: the feared FTS-GIN write
  amplification is already guarded by `IS DISTINCT FROM`; S4: no COUNT/OFFSET scan exists). 👍 This is the
  calibration discipline working as designed.

## Areas

### 1. Setup, onboarding & dispatch harness
- 👍 **Vendoring + skill discovery clean.** Dropping the skill dirs flat into `.claude/skills/` made
  `performance-audit*` invocable immediately, and the relative sibling refs (`../performance-audit/`,
  `../writing-plans-enhanced/`, `../plan-review-cycle/`) resolved to the project's existing customized
  siblings — exactly the right behavior.
- 👍 **The reasoning-effort honesty rule matched reality precisely.** The Agent tool lets you set the
  subagent *model* (I used `opus`) but exposes **no** effort knob — the skill's instruction to record
  `reasoning_effort: "default (harness exposes no knob)"` is exactly correct for this harness. Nice to hit
  a guidance line that anticipated the environment.
- 🟡 **`plugin_version` provenance.** The skill was vendored flat (no `plugin.json` alongside the skill),
  so I recorded `superpowers-plus@0.2.0 (vendored; version per source repo)` per the run-schema honesty
  note. That note exists and worked, but it required me to go find the version from the source bundle's
  `plugin.json` — a one-line "where to look when vendored" pointer would help.
- 💡 **Bless a shared-preamble-file dispatch mode (workaround I invented — high signal).** `lane-prompts.md`
  assumes the runner pastes the shared preamble + lane body inline per lane. At **6 lanes × 10 slices ≈ 50
  dispatches**, re-pasting the preamble is a large *runner* output-token cost. I factored the shared
  preamble into `docs/perf-audits/lane-preamble.md` and each lane prompt opens with "read this file, then
  here's your slice + lane." This is the natural extension of the existing "lane reads its own pack slice"
  mode to the *preamble itself*, and it cut per-dispatch prompt size by ~70%. Worth documenting as a
  first-class option in `SKILL.md` Phase 2.

### 2. Scope handling (whole-repo-scoping.md)
- 👍 **The size router → full method routed cleanly** and the partition survived a 3-round adversarial
  review (sizing / hot-path / partition-design lenses). The "one deployable → backend↔SPA is a process
  boundary, not a service-monorepo split" rule resolved the Go+Vue layout unambiguously.
- 👍 **LOC bands were right for Go** (2–6k/slice). The one band tension — S3 feed+ingest landed ~6.3k —
  was resolved by the method's own "homogeneous pattern family → audit representatives" guidance, and the
  lanes did exactly that (deep on nvd/ghsa/osv + shared base, cited others on divergence).
- 🟡 **`tokei`/`scc` assumed, absent in container.** "Survey & measure production LOC" leans on
  `tokei --output json`. The container had neither (nor `cloc`). Workaround: `wc -l` with a
  generated-banner + `_test.go` + `web` test-glob exclusion. A documented `wc`/`find` fallback (and the
  "subtract inline `#[cfg(test)]`/banner-detected generated" tells, which I applied manually) would make
  the survey step portable to bare containers.
- 💡🟡 **No described "whole-repo + autonomous (no user available)" mode — the single biggest process gap.**
  The cycle's Phase 5 is "present to user" and Phase 6 writes a fix plan, then Phase 7 plan-reviews — *per
  cycle run*. For a 10-slice whole-repo run with the user offline (this run), that implies 10 present-to-
  user pauses + 10 fix-plans + 10 plan-reviews, which is neither possible (no user) nor sensible. Workaround
  I adopted: treat per-slice Phase 5 as "record dispositions in the validated report" (default-FIX
  discipline preserved), and **defer fix-plan + plan-review to ONE consolidated remediation plan after the
  roll-up**. `whole-repo-scoping.md` should describe this explicitly: per-slice = audit+validate+commit;
  fix-planning happens once, post-roll-up, over the deduped finding set.

### 3. Detection & pack loading (Phase 0)
- 👍 **Materiality kept junk out.** Go core + `database-sql` + `serialization` + `net-http-servers` loaded;
  `grpc`/`messaging` correctly *not* loaded (not used). SQL companion pack loaded only for data-access
  lanes touching `store`/queries/DDL. The materiality-over-detection rule did real work.
- 🟡 **Third-party libs have no version index.** `version-indexes/go.md` (covered_through 1.24) grounded
  stdlib idioms well, but huma/v2, pgx/v5, squirrel are outside it — the idiom-currency lanes flagged those
  as Heuristic/manual-check and (correctly) did not fabricate. A pgx/huma index entry (e.g. pgx
  `CollectRows`/`Batch`/`CopyFrom`, huma streaming) would have upgraded several Strong-static-gap findings
  from Heuristic-magnitude.
- 👍 **Go 1.26 > index's 1.24 covered_through handled exactly as documented** — idiom findings downgraded
  to Heuristic with an explicit "project is newer than the index" note in every idiom lane.

### 4. Lane dispatch (Phase 2)
- 👍 **Lane-reads-own-slice was the right mode** at 6 lanes — the runner never had to hold every pack in
  context. Each lane read its pack lane-slice + the relevant module(s) + (idiom) the version index.
- 🐞🟡 **Sibling-file "prior run" confusion.** Multiple lane subagents reported the deterministic output
  file "already contains a complete report from a prior run of this exact lane" and declined to overwrite —
  when there was **no** prior run (first run). One cost-map lane noted it *overwrote* an existing cost-map
  file. Likely cause: concurrent siblings writing to predictable adjacent paths in the same dir, which a
  lane reads and mistakes for a prior artifact. It did **not** corrupt output (findings were still returned
  inline and I cross-validated them), but it's a real dispatch-hygiene defect. Fixes worth considering:
  give each lane a uniquely-stamped output path it *owns*, and/or add a preamble line "you may see sibling
  lanes' files in this dir; ignore them, they are not prior runs."

### 5. Lanes & profile packs (the heart)
- 👍 **Reference-not-checklist held — lanes out-reasoned the pack repeatedly.** Real findings the pack
  doesn't enumerate: S3's `FetchResult.Patches []CanonicalPatch` contract re-introducing whole-feed
  materialization *after* correct per-entry streaming; S1's redundant JCS re-serialization of an
  already-sorted struct; S4's missing **composite** keyset index behind a correctly-written row-value
  cursor. None are pack bullets; all are real.
- 👍 **cost-map earned its keep.** It was the cleanest single source of the "where does time go" framing per
  slice (e.g. S3: "the merge, not the adapters, is where S3 spends time") and repeatedly caught the framing
  that the adversarial lanes then quantified.
- 🟡 **False-positive rate was low but non-zero, and cross-validation caught it** — see area 6. The packs
  did not *cause* the FPs; lanes generated them from plausible-but-unverified structure.

### 6. Synthesis & finding model (Phase 3)
- 👍 **Dedup + cross-lane agreement as confidence worked**, and the fingerprints made it mechanical.
- 👍 **Cross-validation caught errors in BOTH directions, which is the whole point:** it **confirmed** a
  likely *missed-alerts* correctness bug in S2 (sweep advances the cursor past the 5,000-candidate cap) and
  **refuted** a different S2 finding as a false positive (a lane called a `date>$1 AND cve_id>$2` keyset
  "skips same-date rows," but the query orders by `cve_id` alone under a fixed date floor, so it's
  complete). Both went into the report honestly (confirmed vs "likely FP — verify").
- 🟡 **Cross-slice finding homing needs a sentence in the SKILL.** Because ingest (S3) *drives* merge (S1),
  S3's lanes surfaced merge-internal findings (child-row-by-row writes, EPSS staging drain, the double
  hash-read) as "adjacent context." Correct behavior, but it produced **shared fingerprints across slices**
  that I had to attribute by ownership and mark for roll-up dedupe by hand. The method anticipates this
  (frequency calibration, roll-up dedupe) but `SKILL.md`/`whole-repo-scoping.md` should state plainly: *a
  slice's lanes will surface adjacent-slice findings; attribute each to its owning slice and dedupe by
  fingerprint in the roll-up.*
- 👍 **bug-no-chase boundary held perfectly.** Every lane recorded suspected bugs (incl. co-located ones
  like the EPSS partial-run-as-complete sitting in the same function as the EPSS perf finding) and none
  chased them. The co-located-bug guidance matched real cases.

### 8. Artifacts & ergonomics
- 👍 **Resumable by construction.** `docs/perf-audits/` + `runs.jsonl` + the `SLICE-PLAN.md` progress
  ledger + per-slice commits mean a container restart loses nothing — exactly the property this environment
  needs. First-run path creation (the empty `runs.jsonl`, `cache/`) worked.
- 👍 **run-schema frontmatter + fingerprints**: sane, greppable, and the regression machinery degrades
  correctly on a first run (`prev_run_id: null`, all `new`).
- 🟡 Minor: per-slice I merged the "consolidated" (snapshot Phase 3) and "validated" (cycle Phase 3) reports
  into one `*-consolidated.md` with validation dispositions inline, rather than two files. For a 10-slice
  run, two files/slice is noise; the merge kept it readable. Worth blessing as the cycle's default.

## Top changes so far (ranked; will finalize at the end)
1. **Document a whole-repo + autonomous mode in `whole-repo-scoping.md`**: per-slice = audit→validate→
   commit (no per-slice present-to-user / fix-plan); fix-planning + plan-review happen **once** post-roll-up
   over the deduped finding set. (Biggest real gap this run hit.)
2. **Fix the sibling-file "prior run" confusion** (area 4 🐞): unique per-lane output paths and/or a
   preamble line telling lanes to ignore sibling files.
3. **Bless the shared-preamble-file dispatch option** and add a `tokei`-absent `wc`/`find` survey fallback;
   add a pgx/huma entry to the Go version index.

## Verdict so far (4 of 10 slices)
**Yes — it is finding real, well-calibrated, actionable performance work, and the calibration/anti-padding
discipline is genuinely holding.** The four FULL slices produced a coherent hot-core story (per-source-write
merge recompute + round-trip amplification; O(CVEs×rules) realtime alerting; per-row EPSS transactions;
whole-feed materialization; a one-line missing-index quick win) with honest non-findings and two
cross-validated correctness bugs handed off — not a single padded nit survived validation.
