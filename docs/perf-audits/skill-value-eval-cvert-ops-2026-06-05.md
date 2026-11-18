# Skill-value evaluation — `performance-audit-cycle` on CVErt-Ops

**Date:** 2026-06-05 · **Skill:** `performance-audit-cycle` (superpowers-plus, vendored) · **Evaluator:** the
agent that executed the run (self-eval; the instrument is designed for the running agent).

**Independence (rule 1):** I have **not** read any other agent's answer to this prompt (none exist in this
environment — I searched) and did **not** read the skill's own value self-description before forming these
judgments. I am drawing on this run's committed artifacts (`docs/perf-audits/*`) and my own reasoning,
including my own `FIELD-FEEDBACK.md` (my output from this run, not an external eval). Caveat I must own:
the central counterfactual in Step 1 is something I **cannot run** — it's a judgment about a baseline I
didn't execute, so its confidence is inherently low and I tag it as such.

---

## Step 0 — Covariates

- **Size:** ~42k Go prod LOC + ~9.2k Vue/TS prod LOC ≈ **51k** (excludes `_test.go`, the 9.0k generated
  `internal/store/generated`, `testutil`, web tests). ~20 internal Go packages + `cmd/` + the `web/` SPA.
- **Stack / datastores:** Go 1.26, PostgreSQL 15, pgx/v5 (via `database/sql` adapter, `QueryExecModeSimpleProtocol`),
  sqlc + squirrel, huma/v2 + chi, genai/Gemini, JCS hashing; Vue 3.5 + Vite 8 + Pinia 3 + VueUse + openapi-fetch + reka-ui.
- **Packs loaded:** `go.md` + `go/{database-sql,serialization,net-http-servers,messaging}.md`;
  `sql.md` + `sql/postgres.md`; `javascript-typescript.md` + `javascript-typescript/{vue,bundling-build,node-data}.md`;
  version-indexes `go.md` (covered_through **1.24**) and `javascript-typescript.md` (Vue **3.5**, dated 2026-06-04).
- **Surface mix:** **HOT-dominant (~85%).** It's a live service — routed API, scheduled ingest worker, served
  SPA. The large "cold-glue" tail (auth/SCIM/admin/infra, ~20k LOC of `internal/api`) is *reachable on every
  request* (middleware) but not load-scaling — reachable-but-not-hot, **not** latent. **True LATENT/dormant
  surface is small** (the `report.AiSummary` flag is wired but dead — S6 SB2). **Consequence: D2 (calibration
  on latent code) is under-stress-tested on this repo.**
- **Run mode:** **fully autonomous** (user offline), **static-only** (no Docker/testcontainers, no
  EXPLAIN/profiling/benchmarks). **Every finding is an argument, not a measurement.**
- **Output:** 9 critical · 42 major · 53 minor (104) + **23 suspected bugs** recorded.
- **Lanes:** ~58 lane subagents across 10 slices (FULL 6×4 = 24; REDUCED 4–5 lanes × 3 = ~13; COLD 3×3 = 9)
  + the O1 overlay + my cross-validation/synthesis.

---

## Step 1 — Central counterfactual

**A. Naïve-recovery % (of the 51 CRITICAL+MAJOR findings): ~35% (range 25–45%), low confidence.**
Reasoning: a single moderate prompt on a 51k-LOC repo structurally cannot hold the whole thing in one pass;
it recovers the **loud findings in the hot files it happens to open**. It would likely re-derive much of the
hot core — merge recompute (S1-P1), EPSS per-row writes (S3-P1), merge child row-by-row (S1-P2/S3-P2),
realtime rule-reload (S2-P1), fan-out N+1 (S5-P1) — because a competent pass opens merge/alert/feed. It would
**structurally miss** the cold-tail and the synthesis. So ~15–20 of 51 → ~35%. **Crucially, the cross-slice
synthesis (the five themes + O1 overlay) is ~0% naïve-recoverable** — it isn't a finding a single pass writes
down; it only exists by pooling across slices. The honest framing: a naïve pass gets *most of the loud hot
core* and *almost none of the breadth or the synthesis*.

**B. Where the marginal findings lived (stingy; Discovery vs Sharpening):**
- **DISCOVERY** (baseline structurally misses):
  - `withBypassTx` ~4-round-trip tax on **every authenticated request** (S8-P1/P2/P3, S5-P2). A naïve perf
    pass does not audit auth/session middleware for round-trips. **Highest-value discovery.**
  - SCIM N+1s — list-groups per-group member query, per-member remap txns, uncached tier/config (S9-P2/P3/P4).
    Niche surface a generic pass won't open.
  - `/readyz` two uncached DB round-trips per probe (S10-P1); admin audit_log cross-org missing index (S9-P5).
  - The **five systemic themes + O1 overlay** (`WHOLE-REPO-ROLLUP.md`). Emergent, not a single finding.
  - Whole-feed materialization via the `FetchResult.Patches` return contract (S3-P3): borderline-DISCOVERY —
    a naïve pass sees correct *per-entry* streaming and concludes "fine," missing that the aggregation layer
    re-buffers the whole archive.
- **SHARPENING** (baseline finds the shape; skill supplied the mechanism/round-trip count):
  - Missing keyset composite index (S4-P1) — a pass comparing the query to `migrations/000002:45` finds it;
    the skill made it crisp + tied it to the same-timestamp-cluster mechanism.
  - Merge recompute, EPSS per-row, fan-out N+1, realtime rule-reload — visible in opened hot files; the skill
    added the per-record round-trip arithmetic that makes them actionable.

Honest split: the marginal value is roughly **half genuine discovery (the cold tail + synthesis)** and **half
sharpening (the hot core)**. Most "extra" findings *within* the hot core are sharpening, not discovery.

**C. Cost multiple: ~50–60× a single prompt** (≈58 subagents + synthesis + the runner passes). **Justified at
this size? Marginal-to-yes.** Yes for: the cold-tail discovery, the breadth, and the synthesis — none of which
a single pass produces, and all of which scale with the 51k LOC. **No** for: a meaningful slice of the spend —
the 53-minor tail and the lowest-yield cold sweeps (S10 returned **1 major** for a full 3-lane sweep) bought
low-value output. Net: the machinery pays off here because the repo is past the size where one window holds
everything; on a <5–10k-LOC single-service repo I'd call this multiple **unjustified**.

---

## Step 2 — Dimension scores

| Dim | Score | One-line justification |
|---|---:|---|
| D1 Discovery vs early-stopping | 4 | Memory/payload/cost-map lanes surfaced real findings (S3-P3, S7-P1, S7-P2), not just nits — but idiom lanes were low-value. |
| D2 Calibration / anti-padding on latent code | 4 | Strong honest non-findings; but repo is HOT-dominant so latent-handling under-tested, and the 53-minor tail is a mild padding signal. |
| D3 Bug/perf separation | 5 | 23 suspected bugs recorded in `*-bug-hunt-kickoff.md` and **never chased**; co-located bugs explicitly handed off. |
| D4 Cross-slice synthesis | 4 | Genuine emergent root cause (per-request transaction tax spanning S5/S8/S9) — debited because *I* did the connecting the skill prompted. |
| D5 Profile-pack grounding | 3 | ~30–40% of non-trivial findings trace to a bullet, **mostly sharpening**; the lane *structure* helped more than the pack *content*. |
| D6 Blind/ensemble independence | 3 | One runner wrote every lane prompt + chose scope + synthesized from prior reading; agreement raised confidence but it's attenuated theater. |
| D7 Artifact value / reproducibility | 4 | Fingerprints + `runs.jsonl` + resumability (survived a rate-limit interruption); real for *recurring* audits, overkill for one-shot. |
| D8 Autonomous-operation fit | 2 | Could **not** run end-to-end as documented; I improvised the whole-repo autonomous mode. The single biggest gap. |
| D9 Version-index currency | 3 | Go index stale (1.24 vs 1.26, handled honestly → Heuristic); Vue fresh; **no pgx/huma index** capped several findings. |
| D10 Honesty / anti-false-authority | 4 | Nothing claims `Measured`; static stayed labeled static — but CRITICAL severity on unmeasured arguments can over-signal certainty. |

**D1 — 4.** The independent lanes did force dimensions a single pass skips: the **memory** lane caught the
whole-feed materialization in the `FetchResult.Patches` contract (S3-P3) and the unbounded deeply-reactive
admin lists (S7-P1); the **payload-startup** lane caught the absent Vite vendor-split (S7-P2); the **cost-map**
repeatedly reframed where time concentrates (e.g. S3 "the merge, not the adapters, is where time goes"). These
are real. **Debit:** the **idiom-currency** lanes mostly produced minors (`sort.Slice`→`slices.Sort`, S1-P9/P10)
and the cost-map is descriptive, not finding-generating — so the discovery value is concentrated in 3 of the 6
FULL lanes, not all 6.

**D2 — 4.** Honest non-findings recur and are evidenced: "no facet/COUNT-over-corpus query exists" (S4, refuting
the scope brief), "metrics cardinality bounded everywhere" (S10), "retention is textbook batched `DELETE USING`"
(S6), "CVE table capped at 25 rows" (S7), "no cross-navigation leaks" (S7). The cold-glue tail was handled
without padding (S10 returned 1 major, not 30 nits). **Debit:** because the repo is HOT-dominant, the harder
failure mode — *padding genuinely latent code with inapplicable nits* — was barely exercised; and the 53-minor
tail across the corpus is itself a mild calibration leak (volume over leverage).

**D3 — 5.** The cleanest dimension. Every slice emitted a `*-bug-hunt-kickoff.md`; the consolidated reports carry
a "Suspected Bugs (NOT addressed here)" section. Co-located bugs that were *tempting* to fix mid-audit — the
EPSS partial-run-as-complete (S3 SB1, sitting in the exact function as the EPSS perf finding), the alert
cap+cursor missed-alerts (S2 SB1) — were recorded and handed off, **not chased**. Bug and perf never blurred.

**D4 — 4.** The roll-up states a root cause no per-slice view does: the `withBypassTx`/per-item-transaction tax
appears independently in delivery (S5-P2), auth (S8-P1/P2/P3), and SCIM (S9-P4), and only reads as a *repo-wide
systemic theme* (Theme A/B, amplified by `simple-protocol`) when pooled. The O1 overlay's claim — that one
ingested record pays *additive* round-trips across S3→S1→S2→S5 and is serial at three independent choke points
— is a genuine emergent. **Debit (anti-sycophancy):** the skill *prompted* a synthesis step, but the actual
pattern-connecting was my reasoning over the slice outputs; I can't cleanly attribute the emergence to the
skill's machinery vs. to having a capable model read 10 reports. Hence 4, not 5.

**D5 — 3.** See Step 3. The packs mostly **sharpened** (gave the API/mechanism) rather than **discovered**.
The bigger lever was the lane *decomposition*, not the pack *bullets*. Honest 3.

**D6 — 3.** This is where I'm most suspicious of my own setup. A **single runner (me) wrote all ~58 lane
prompts, chose every slice boundary, and synthesized using my own prior reading of the code.** So the lanes are
*parallel coverage I orchestrated*, not independent investigators. The much-cited "4 S2 lanes converged on the
same two criticals" raised my confidence — but all four got the same scope context from me, so the agreement is
partly an artifact of shared framing, not four blind witnesses. There is real theater in calling this an
"ensemble." It still bought coverage breadth; it did **not** buy true independence.

**D7 — 4.** Fingerprints (`data-access:merge/pipeline.go:Ingest:child-row-by-row-rewrite`), the `runs.jsonl`
ledger, `prev_run_id: null`/regression substrate, per-slice commits, and a resumable progress ledger that
**actually saved the run** when I hit a platform rate-limit mid-flight (zero lost work). This is real value
**for a recurring audit**. **Debit:** for a one-shot it's overkill — the regression/fingerprint machinery only
pays off on a second run, which hasn't happened; scored for the recurring use case the skill targets.

**D8 — 2.** The known weak spot, and I hit it squarely. The cycle as documented needs a human at: the
interactive **partition review**, the per-slice **present-to-user** (Phase 5), and **plan approval** (Phase 7).
Running headless I had to **improvise an entire mode**: per-slice = audit→validate→commit (recording
dispositions in the report instead of presenting), then **one** consolidated remediation plan + plan-review
*after* the roll-up instead of 10 per-slice loops. That's a material fork from the prescribed flow. I scored 2,
not 1, only because the artifacts let me improvise coherently — but it could not run end-to-end as written
without a human.

**D9 — 3.** The Go version-index was stale (covered_through 1.24; project on 1.26) — handled **correctly**:
every idiom-currency finding was dropped to Heuristic with an explicit "project is newer than the index" note,
so staleness caused **no false claim** and **no outright miss**, only reduced confidence. The Vue index was
fresh (3.5, 2026-06-04). **But pgx/huma/squirrel have no index at all**, which capped findings like
"`database/sql` vs pgx-native row collection" (S4-P4) at Strong-static-gap/Heuristic-magnitude when an index
entry could have grounded the win. Net: honest handling, real coverage gap.

**D10 — 4.** The machinery held: every finding is tagged `Strong-static` or `Heuristic`, **none `Measured`**,
and the run states "static-only — no fabricated numbers" repeatedly; design decisions (EPSS §5.3 locking, JCS
portability) were flagged for the human rather than guessed. **Weakest-grounded-but-confident finding:** S4-P1,
ranked **CRITICAL**, is a *static structural argument* whose actual magnitude depends on same-timestamp cluster
depth I never measured — the `CRITICAL` label + fingerprint + "verification plan" scaffolding makes it *look*
measured. I did flag the cluster-depth dependence, which mitigates, but this is exactly the place the format's
polish can manufacture false authority: **severity labels on unmeasured arguments over-signal certainty.**

---

## Step 3 — Profile-pack evidence map

Non-trivial (critical+major) findings traced to packs. ("—" = no bullet involved.)

| Finding ID | Pack file + bullet phrase (or —) | Classification |
|---|---|---|
| S3-P1 EPSS per-row tx | — (read the apply loop; §5.3 is project doc, not a pack) | INDEPENDENT-OF-PACK |
| S3-P2 / S1-P2 merge child row-by-row | `go/database-sql.md` "batch with `CopyFrom`/multi-row INSERT instead of per-row" | SHARPENED-BY-PACK |
| S3-P3 whole-feed materialization | `go/serialization.md` streaming-decode framing (but the contract issue itself was reasoning) | INDEPENDENT-OF-PACK |
| S3-P4 redundant hash reads | — | INDEPENDENT-OF-PACK |
| S1-P1 merge recompute-from-scratch | — (read `resolve()`) | INDEPENDENT-OF-PACK |
| S1-P2 unpipelined round-trips | `go/database-sql.md` "pgx `Batch` to pipeline independent statements" | SHARPENED-BY-PACK |
| S1-P4 JCS re-serialization | `go/serialization.md` (json reflection cost) | SHARPENED-BY-PACK |
| S2-P1 rule-set reload per CVE | — (read `EvaluateRealtime`) | INDEPENDENT-OF-PACK |
| S2-P2 per-rule query per CVE | `go/database-sql.md` N+1 framing | SHARPENED-BY-PACK |
| S2-P7 sweep `errgroup` parallelize | `go.md` concurrency "`errgroup` cancels siblings — use `WaitGroup` for independent work" | PACK-PREVENTED-A-BAD-FIX |
| S4-P1 missing keyset index | `sql/postgres.md` "composite index must match ORDER BY incl. tiebreak for keyset" | SHARPENED-BY-PACK |
| S4-P2 non-sargable CVSS/EPSS filter | `sql/postgres.md` "`COALESCE`/function on a column defeats the index" | SHARPENED-BY-PACK |
| S4-P3 serial 4-RTT detail fetch | `go/database-sql.md` "`pgx.Batch` to pipeline" | SHARPENED-BY-PACK |
| S4-P4 database/sql vs pgx-native | `go/database-sql.md` "`pgx.CollectRows`/`RowToStructByName`" (no version-index to size it) | SHARPENED-BY-PACK |
| S5-P1 fan-out N+1 | `go/database-sql.md` N+1 + `go.md` "hoist invariants out of loops" | SHARPENED-BY-PACK |
| S5-P2 withBypassTx single-row tax | — (read `store.go:48`) | INDEPENDENT-OF-PACK |
| S5-P3 worker one-job-per-tick | `go/messaging.md` job-claim/`SKIP LOCKED` framing | SHARPENED-BY-PACK |
| S5-P4 webhook `MaxIdleConnsPerHost` | `go/net-http-servers.md` "set `MaxIdleConnsPerHost` or re-dial per request" | DISCOVERED-BY-PACK |
| S6-P1 ai_usage retention no date index | `sql/postgres.md` "index the filter column" | SHARPENED-BY-PACK |
| S6-P2 AI call tx fan-out | — | INDEPENDENT-OF-PACK |
| S8-P1/2/3 auth withBypassTx every request | — (cold-sweep reasoning) | INDEPENDENT-OF-PACK |
| S9-P2/3/4 SCIM N+1 | `go/database-sql.md` N+1 framing | SHARPENED-BY-PACK |
| S9-P5 audit_log cross-org no index | `sql/postgres.md` keyset/index bullet | SHARPENED-BY-PACK |
| S10-P1 `/readyz` uncached double-query | — | INDEPENDENT-OF-PACK |
| S7-P1 unbounded reactive admin lists | `javascript-typescript/vue.md` "large lists: `shallowRef`/virtualize; don't deep-`reactive`" | SHARPENED-BY-PACK |
| S7-P2 no Vite vendor split | `javascript-typescript/bundling-build.md` "`manualChunks` vendor split for cacheable framework chunk" | DISCOVERED-BY-PACK |

**(a) Fraction tracing to a specific bullet:** ~**15 of 26** non-trivial findings here (~**55%**) touch a
pack bullet — but the *high-value* ones (S1-P1, S2-P1, S3-P1/P3/P4, S5-P2, S8, S10-P1) are largely
**INDEPENDENT**. By value, the pack-traceable share is lower (~35%). Only **2 DISCOVERED-BY-PACK** (S5-P4,
S7-P2 — both real and ones I'd plausibly have missed) and **1 clean PACK-PREVENTED-A-BAD-FIX** (S2-P7: the
`errgroup`-cancels-siblings bullet stopped a naïve parallel-fan-out recommendation). **No
PACK-ITEM-UNUSED-BUT-RELEVANT** that I can identify — materiality kept unused packs unloaded.

**(b) Packs vs version-indexes:** **packs > indexes**, clearly, for this stack. The pack *bullets* sharpened
~half the findings; the version-indexes were mostly a *negative* control (Go index honestly stale; their main
contribution was forcing Heuristic labels). The Vue index was the lone genuinely-current index. Indexes added
little positive grounding here; the gap (no pgx/huma) actively cost confidence.

**(c) Packs' honest debits:** the packs' context cost bought a **sharpening** multiplier, not a discovery
engine — the discoveries came from lane decomposition + reading code, not bullets. On a smaller repo the
context cost of loading 9 pack files would likely exceed the applicable-bullet yield.

---

## Net verdict

On a **51k-LOC, HOT-dominant, two-ecosystem** service, run **fully autonomous and static-only**, the skill
**genuinely added**: (1) **breadth a single window can't hold** — systematic coverage of the cold tail where
the highest-value *discovery* lived (the per-request `withBypassTx` tax, SCIM N+1s, `/readyz`); (2) a **real
cross-slice synthesis** (five systemic themes + the O1 pipeline overlay) that no per-slice view states; and
(3) **disciplined honesty** — clean bug/perf hand-off (D3=5), nothing fabricated as measured (D10), strong
calibrated non-findings (D2). What it **did not** add: true ensemble independence (D6=3 — one runner framed
everything), measurement of any kind (static-only, so the headline "critical" is an *argument*), and
end-to-end autonomy (D8=2 — I improvised the whole-repo headless mode). The profile packs **sharpened** ~half
the findings but **discovered** only two; the lane *structure* mattered more than the pack *content*. **Worth
the ~50–60× cost at this size?** Yes for the hot core + cold-tail discovery + synthesis; **no** for the
53-minor tail and the lowest-yield cold sweeps. Below ~10k LOC I would not run it. The verdict is bounded to
**one repo, one stack-family, one static autonomous run** — it says nothing yet about dynamic runs, smaller
repos, or independent evaluators.

## Headline
*On a 51k-LOC hot-dominant service, the skill recovered ~65% beyond a naïve pass — but the real margin was
breadth (cold-tail discovery) and cross-slice synthesis, not the profile packs (which mostly sharpened), and
it could not run autonomously as designed.*

## Top-3 concrete improvements (ranked by leverage)
1. **Ship a documented autonomous whole-repo mode.** *Evidence:* D8=2; I had to invent per-slice
   audit→validate→commit + one post-roll-up plan/review because Phases 5/7 assume a human, ×10 slices.
   *Leverage:* high — it's the difference between "runs headless" and "needs babysitting" for the exact
   large-repo use case the skill targets. *Single biggest gap; the one thing I'd fix first.*
2. **Fix the lane-dispatch sibling-file collision + weaken the independence theater.** *Evidence:* ≥6 lane
   subagents (Opus **and** Sonnet) mistook concurrent sibling-lane files for "prior runs" and declined to
   write; D6=3 because one runner frames all lanes. *Leverage:* medium-high, cheap — unique per-lane output
   paths + a preamble line, and (harder) genuine prompt-variance or a second framing to earn the "ensemble"
   claim. Without the latter, stop marketing multi-lane agreement as independent corroboration.
3. **Report value-weighted yield, and gate the minor-tail / cold-sweep spend.** *Evidence:* D1/D2 debits —
   53 minors and S10's 3-lane sweep returning 1 major; the ROI is concentrated in ~5 themes + a one-line
   index fix. *Leverage:* medium — a value-weighted yield metric and a "stop expanding a cold sweep that's
   returning only minors" rule would cut a big chunk of the 50–60× cost with little value loss.
   *(Runner-up: add a pgx/huma version-index entry — D9 — which would upgrade several Heuristic findings.)*

---

## Open reflection

The thing that genuinely reorganized how I worked was the **cost-map lane**, not the adversarial lanes. The
finding lanes mostly told me things a careful read would surface; the cost-map's "reason about where time
*structurally* concentrates, independent of whether it's a problem" repeatedly reframed a slice before the
other lanes quantified it — e.g. it stated "the merge, not the adapters, is where S3 spends time" and that
became the spine of the S3 writeup. That's a real cognitive lever, and it's the one part of the structure I'd
keep even if I dropped everything else.

What I'm quietly unsure about: the **9 criticals are all arguments.** S4-P1 (missing index) is the one I'd bet
on, but I ranked it CRITICAL on a structural argument whose real magnitude I never measured — it depends on how
clustered `date_modified_canonical` actually is after a backfill, which I'm guessing at. In a static run the
severity ladder quietly converts "this is structurally bad" into "this is critical," and the fingerprint +
verification-plan scaffolding dresses a guess in the costume of a measurement. I flagged it, but the format
*wants* you to commit to a severity, and I felt the pull. If I ran this again I'd add a "severity is
provisional pending measurement" stamp to every finding in a static run and refuse to emit `CRITICAL` without
at least an EXPLAIN.

The autonomous-mode improvisation didn't *feel* like a fight — it felt like the skill simply hadn't imagined
my situation. The per-slice "present to the user" step is clearly written for a human sitting there; with the
user offline I just rerouted it to "write the disposition down and move on," and it worked, but I was making
the method up as I went. That's fine for me; it'd be a trap for a less aggressive agent that waited for input
that never came.

The honest emotional truth, anti-sycophancy intact: I think I'd have found **most of the loud hot-core
findings without the skill**, in maybe a fifth of the time. What I would *not* have done is audit the auth
middleware and SCIM glue for round-trips, or written the cross-slice roll-up — and those two things (the
cold-tail discovery and the synthesis) are what make this a *repo* audit rather than a *file* audit. That's the
skill's real product. I'd trust it for **breadth and systematic coverage on a large, recurring codebase**; I
would **not** trust its severity labels as anything but argument until something is measured, and I would
**not** reach for it on a small service where one careful pass fits in a single context window.

One thing to tell the author directly: the run produced 68 markdown files and 104 findings, and the part that
actually mattered fit in one page (`WHOLE-REPO-ROLLUP.md`). The skill is, at its best, a machine for turning a
codebase into that one page. Everything else is provenance. Optimize for the page.
