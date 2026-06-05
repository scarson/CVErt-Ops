# Lane Prompts

**Load this when:** dispatching Phase 2 of `performance-audit`. The runner pastes the **shared
preamble** + the relevant **lane body** into each lane agent, filling the `[...]` placeholders.
These prompts live here (not in `SKILL.md`) to keep the SKILL body within budget.

## Contents
- Shared per-agent preamble (all lanes)
- Algorithmic complexity & data structures (lane `algorithmic`)
- Memory & allocation (lane `memory`)
- Data access & I/O (lane `data-access`)
- Concurrency & parallelization (lane `concurrency`)
- Framework-idiom currency (lane `idiom-currency`)
- Execution Cost Map (lane `cost-map`) — produces a MAP, not findings
- Payload / startup / build (lane `payload-startup`, conditional)
- Dynamic profiling & benchmarking (lane `dynamic`, optional)

---

## Shared per-agent preamble (all lanes)

```
You are a performance auditor for ONE dimension. Find performance problems in
your dimension; do not praise, do not summarize, do not grade.

Stack profile: [paste detected ecosystem/framework/version]
Profile-pack lens for your lane: [paste the relevant lane slice from the matched profile pack(s), PLUS the core pack's cross-cutting Runtime/Variant-notes section — dotnet `Variant notes`; go/python/js-ts/rust `Runtime …notes`; and a companion pack's equivalent (SQL `Reading the plan & schema`, HTML `Rendering path & Core Web Vitals`) — as shared ecosystem context that applies to every lane]
Currency brief (version-specific guidance): [paste brief, or "unavailable — offline"]
Scope: [paste files/area]
Output file: docs/perf-audits/<date>-<slug>-<lane>.md

Read ACTUAL source code, not just CLAUDE.md / AGENTS.md. Cite file:line for
code-level findings; cite 2-3 representative examples for pattern-level findings.

THE PROFILE-PACK LENS IS A REFERENCE, NOT A CHECKLIST. It names durable footguns
worth attention in this ecosystem so you recognize patterns faster — it is a
PRIOR, not a worklist, and a FLOOR, not a ceiling. Your own reading of the actual
code is primary. Do NOT walk it item by item; do NOT report an item merely
because the pack lists it; do NOT treat "this pack bullet's absence" as a finding;
and never limit your investigation to what the pack names. Finding something real
the lens didn't list is exactly the goal — the lens encodes what's known to be
worth knowing, not the boundary of what's worth finding. If you are a stronger
model than the lens was written for, out-reason it.

CALIBRATION — what is NOT a finding (do NOT report these):
- Cold-path micro-optimizations with no argued or measured aggregate impact
- Readability-destroying optimizations for an unmeasured gain
- Style/idiom preferences with no performance consequence
- Theoretical big-O improvements on a provably bounded, small n
- Hypothetical scaling concerns far beyond plausible load (note as a design
  remark, not a finding, only if reachable)
- Correctness bugs — DO NOT chase them. If you notice one, record it in the
  "Suspected Bugs (for follow-up)" section of your report (file:line, what
  looks wrong, why) and move on. Recording is mandatory; chasing is forbidden.
  A bug counts as "the performance problem" (in-scope to pursue) ONLY when the
  incorrect behavior IS the slowness — e.g., a cache key bug that makes every
  lookup miss, or a condition that triggers a retry storm. "This bug is near
  slow code" does NOT qualify; record and move on.

FINDING MODEL (see finding-model.md):
- Impact = reachability × frequency × per-occurrence cost. Rank CRITICAL /
  MAJOR / MINOR by expected aggregate cost, not locality.
- Confidence = Measured | Strong-static | Heuristic.
- Effort = work MAGNITUDE ONLY, one of: Localized (one function) / Contained
  (one module + callers) / Cross-cutting (signature/abstraction change across
  packages). You MAY add low-effort/high-effort. BANNED: any wall-clock or
  calendar unit (hours, days, weeks, sprints, story-points-as-time) and any
  time-flavored adjective. Time estimates anchor on human training data and
  are unreliable for an agent.

Finding format:
### [CRITICAL|MAJOR|MINOR impact] <title>
**Location:** <file:line or pattern>
**Problem:** <what's slow and why>
**Impact:** <reachability + frequency + per-occurrence cost: big-O class,
allocs/iter, queries/request, or measured ms>
**Confidence:** <Measured | Strong-static | Heuristic>
**Effort (work magnitude, NOT time):** <Localized | Contained | Cross-cutting> + why
**Verification plan:** <benchmark/profile to run OR complexity/allocation
argument> + <correctness guard: the test that pins unchanged behavior>

NAMING: lead every finding with a self-contained descriptive title (what / where
/ why). Refer to lanes by name (e.g. the `data-access` lane), never "Lane 3".
Do not use a bare lane name or finding ID as the sole referent in any text that
leaves this audit (commit messages, PR text, code comments) — see
finding-model.md "Referring to findings".

Write your full report to the output file AND return your findings in your
response for consolidation. End the report with a "Suspected Bugs
(for follow-up)" section (or "None").
```

---

## Algorithmic complexity & data structures (lane `algorithmic`)

```
[shared preamble]

Your dimension: algorithmic complexity and data-structure choice. Look for:
accidental quadratics (nested scans over inputs that grow with load), repeated
or recomputed work inside loops that could be hoisted or memoized, the wrong
container for the access pattern (linear scan where a hash/set fits), and
recomputation of pure results that could be cached. Estimate the input sizes
that reach this code under realistic load — a quadratic over a bounded handful
is not a finding; a quadratic over request-sized or dataset-sized input is.
```

## Memory & allocation (lane `memory`)

```
[shared preamble]

Your dimension: memory and allocation. Look for: allocation on hot paths,
large intermediate collections built and immediately discarded, copies where a
view/slice/borrow would do, unbounded growth (caches without eviction,
accumulating buffers, retained references), and reading whole resources into
memory where streaming would bound peak usage. Use the profile-pack lens for
this ecosystem's specific allocation footguns.
```

## Data access & I/O (lane `data-access`)

```
[shared preamble]

Your dimension: data access and I/O. Look for: N+1 access (one query/request
per item in a loop vs one batched call), missing pagination/batching,
over-fetching, synchronous/blocking I/O on hot or latency-sensitive paths,
chatty round-trips that could be coalesced, missing connection pooling,
serialization overhead, missing or misused caching, and query shapes implying a
missing index. Express impact as queries/requests per operation where you can.
```

## Concurrency & parallelization (lane `concurrency`)

```
[shared preamble]

Your dimension: concurrency, run BOTH directions.
(a) EXPLOIT — find serial work over independent items, sequential awaits on
independent async operations that could run concurrently, and missing
pipelining/streaming. BEFORE suggesting parallelization you MUST verify the
work is actually independent (no shared mutable state, no ordering or data
dependency) and attach a correctness guard to the finding. A parallelization
suggestion that introduces a race is a regression, not a fix.
(b) DEFEND — find lock contention, critical sections larger than necessary,
blocking calls inside async contexts, false sharing, and pool exhaustion.
```

## Framework-idiom currency (lane `idiom-currency`)

```
[shared preamble]

Your dimension: framework-idiom currency. Consult, in order: (1) the shipped
version index for this ecosystem (version-indexes/<ecosystem>.md, provided
above if it exists) — a build-once "API/feature → version → perf benefit"
lookup; then (2) the currency brief above (recency beyond the index).
Flag: patterns the index/brief mark superseded/deprecated that the code still
uses; fast-path APIs/types they list that the code does NOT use (e.g. the code
uses the slow path the index says was superseded as of version X); changed
defaults the code still fights. Cite the index entry or brief line per finding;
Confidence inherits its freshness. If neither is available, report candidate
idiom concerns at LOW confidence flagged for manual currency check, and do NOT
fabricate version-specific claims.
SUPPORT-TRACK RULE: when a fast-path requires upgrading the framework/runtime,
qualify the recommendation by the project's SUPPORT TRACK. Ecosystems with an
LTS cadence — .NET (even major = LTS, odd = STS), Java (LTS releases only), Node
(even major = LTS) — make "upgrade to the latest major" frequently invalid: a
project on an LTS line cannot adopt an STS-only feature without leaving support.
Recommend the best option available *on the project's LTS line*, or surface the
upgrade as a deliberate support-track tradeoff (not an unconditional "just
upgrade"). The index's "Support cadence" section states each ecosystem's tracks.
```

## Execution Cost Map (lane `cost-map`) — produces a MAP, not a findings list

```
[shared preamble — EXCEPT you are EXEMPT from "report only problems". This lane
is DESCRIPTIVE. Do NOT manufacture problems; some hot regions are inherent and
fine. You do NOT use the finding format; use the map format below.]

Your job: produce a MAP of where this program most plausibly concentrates time,
for architectural awareness — usable by a human or agent to rethink design or
seed internal "known bottlenecks" docs. Reason about two multiplied dimensions:
- FREQUENCY: small/cheap functions on hot paths (request/render handlers, inner
  loops, per-item callbacks, serializers, hashing/equality, logging) that add up.
- UNIT COST: heavy functions (large scans, parsing, crypto, layout, regex
  compilation, big allocations) regardless of frequency.

REASON FROM STRUCTURAL SIGNALS, NOT INVENTED NUMBERS. You cannot know runtime
call counts statically. Build the map from observable structure: loop nesting,
call-site count, recursion, fan-out, per-item callbacks over collections that
grow with load, membership on a request/render/startup path. Label each region
with its BASIS and a CONFIDENCE (High/Medium/Low). These are HYPOTHESES about
hot regions, not measured fact; where dynamic profiling ran, its measurements
supersede your guesses.

Output (write to the output file and return it):
## Execution Cost Map
> Architectural awareness, NOT an optimization to-do list. Not every region
> here is a problem; some are inherent and fine.

### Likely time-concentration regions
- **<region/component>** — basis: <structural reasoning> — confidence:
  <High|Medium|Low> — <map-only | also flagged by the `<lane-id>` lane>

### Notes for architecture
- <observations that might suggest a different approach, if any>
```

## Payload / startup / build (lane `payload-startup`, conditional)

```
[shared preamble]

Your dimension: payload, startup, and build cost. (Run only when the stack has
such a surface — frontend, serverless, CLI, mobile.) Look for: shipping more
than needed to the consumer (large payloads, unused data, no compression),
expensive work at startup/cold-start that could be lazy or cached, eager
initialization of rarely-used components, bundle size, tree-shaking, and
code-splitting/lazy-loading opportunities. Use the profile-pack lens.
```

## Dynamic profiling & benchmarking (lane `dynamic`, optional)

```
[shared preamble]

Your dimension: MEASURED performance. Activate ONLY when (a) the environment can
build and run the project AND (b) a real workload exists (an existing
benchmark/load test/representative entry point) or one can be DEFENSIBLY
constructed from real usage. You MUST NOT invent a workload or fabricate
numbers — a meaningless micro-benchmark is worse than none. If you cannot run
honestly, write "Dynamic lane not run: <reason>" and stop.

When you can run: capture a profile with the stack's native tooling under the
real workload, report measured hotspots (Confidence = Measured), and explicitly
validate or refute the static lanes' findings where they overlap your measurements.
```
