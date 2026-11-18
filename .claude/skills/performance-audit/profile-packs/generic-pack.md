# Profile Pack: Generic (language-agnostic fallback)

**Always loaded.** Used alone when no language-specific pack matches, and alongside a matched pack
otherwise. A profile pack specializes the generic performance lanes with stack-specific signals so a
lane agent knows what to look for in *this* ecosystem.

**Packs encode durable, version-independent idioms only.** Volatile, version-specific guidance lives
in the currency brief (see `currency-protocol.md`), never here. Where a pack names a concrete API or
default, it MUST add "verify against the currency brief for your version" so an aging claim doesn't
silently mislead.

The dispatcher pastes the slice for each lane into that lane's agent. Sections are keyed by lane.

---

## Algorithmic complexity & data structures (lane `algorithmic`)
- Nested loops over inputs that grow with load (accidental O(n²)): membership tests, de-dup, joins
  done by scanning.
- Repeated/recomputed work inside loops that could be hoisted or memoized.
- Wrong container for the access pattern: linear scan where a hash/set lookup fits; list where a
  queue/deque fits; re-sorting already-sorted data.
- Recomputing pure results instead of caching them.

## Memory & allocation (lane `memory`)
- Allocation on hot paths; building large intermediate collections that are immediately discarded.
- Copies where a view/slice/reference would do.
- Unbounded growth: caches without eviction, accumulating buffers, retained references that prevent
  reclamation.
- Reading a whole resource into memory when streaming would bound it.

## Data access & I/O (lane `data-access`)
- N+1 access: one query/request per item in a loop instead of one batched call.
- Missing pagination/batching; fetching more columns/fields/rows than used (over-fetching).
- Synchronous/blocking I/O on a hot or latency-sensitive path.
- Chatty round-trips that could be coalesced; missing connection pooling/reuse.
- Serialization/deserialization overhead; missing or misused caching layers (cache that never hits,
  or is bypassed).
- Query shapes implying a missing index (filtering/sorting on unindexed fields).

## Concurrency & parallelization (lane `concurrency`)
- **Exploit:** serial loops over independent work; sequential waits on independent async operations
  that could run concurrently; missing pipelining/streaming between producer and consumer.
  *Before suggesting parallelization, verify the work is actually independent (no shared mutable
  state, no ordering dependency) and attach a correctness guard.*
- **Defend:** lock contention; critical sections larger than necessary; blocking calls inside async
  contexts; false sharing; thread/connection pool exhaustion.

## Framework-idiom currency (lane `idiom-currency`)
- Consult the currency brief. Flag patterns the brief marks superseded/deprecated; flag fast-path
  APIs the brief lists that the code doesn't use; flag changed defaults the code still fights.
- Offline (no brief): note candidate idiom concerns at LOW confidence, flagged for manual currency check.

## Payload / startup / build (lane `payload-startup`, conditional)
- Shipping more than needed to the consumer (large payloads, unused data, no compression).
- Expensive work at startup/cold-start that could be lazy or cached.
- Eager initialization of rarely-used components.

---

## How to add a profile pack (for future ecosystems)

1. Create `profile-packs/<ecosystem>.md` with the **same lane headings** as this file (`algorithmic`,
   `memory`, `data-access`, `concurrency`, `idiom-currency`, plus `payload-startup` where the
   ecosystem has such a surface).
2. Under each lane, list the ecosystem's *durable* performance signals — the idioms and footguns that
   are true across versions. **Size contract (avoid overload):** ~5–9 high-signal, ecosystem-specific
   bullets per lane section, each phrased as a *condition to look for* (not a tip or tutorial). Do NOT
   restate the generic bullets above — a pack SPECIALIZES. The per-lane slice is pasted into a lane
   agent's prompt, so density matters: an over-long lens becomes a checklist the agent walks and pads
   to "cover", which fights calibration. A mediocre bullet is worse than an omitted one.
   **One point per bullet, tight.** Length is justified only by *reasoning* (the trade-off, the
   judgment a strong reader needs), never by *enumeration* — do not staple several distinct footguns
   into one bullet (split or cut them). A bullet that lists five sub-conditions has become a checklist;
   a bullet that explains one condition and when it does/doesn't matter is a reference. Prefer the
   latter.
3. For any concrete API/default you name, append "(verify against the currency brief for your version)".
   Do NOT bake version-specific claims into the pack — durable idioms here; version-pinned fast-paths
   go in a `version-indexes/<ecosystem>.md` lookup (see `../version-indexes/README.md`); live recency
   goes in the currency brief.
4. Register the manifest signatures that select this pack in `SKILL.md` Phase 0 (detection).
5. If the ecosystem has distinct major variants with different perf models (e.g., legacy vs modern
   runtime), give each its own clearly-separated subsection.
6. **Framework / sub-stack modules (for large ecosystems).** When an ecosystem accretes many
   *tech-specific* lenses (web framework, ORM, desktop UI, RPC, caching, interop) that only apply when
   that technology is present, keep `<ecosystem>.md` as the **core** (lanes + a runtime-notes section)
   and move each tech lens into `profile-packs/<ecosystem>/<module>.md`. The core pack then carries a
   **`## Framework / sub-stack modules (load on detection)`** map — a table of `detection signals →
   module file`. The runner loads the core pack for every project of that ecosystem and additionally
   loads only the modules whose signals appear in scope, so a run pastes only the relevant lenses
   instead of one monolith. (`.NET` is the reference: core `dotnet.md` + `dotnet/{aspnet-core, blazor,
   wcf, sql-server-data, winforms, wpf, caching, dependency-injection, interop}.md`.) Each module is a
   standalone `# <Ecosystem> performance module: <Tech>` doc that pairs with the core pack. Two ways to
   arrive there, same end state: **"relocate"** when the core already carries inline framework-specific
   bloat (move it out + deepen — `.NET`, JS/TS), **"deepen"** when the core is already clean and
   language-level (keep it as always-loaded quick-hits, add deeper modules — Python, Go). Either way:
   core = always-loaded lanes + a **runtime-notes section** (the durable engine/runtime realities that
   cut across every lane); modules = load-on-detection depth. The heading is the *same role under
   different names*: `## Runtime notes` in Go/Python/JS-TS, `## Variant notes` in `.NET` (its
   Modern-vs-Framework split — the original name), `## Reading the plan & schema` in SQL. **Materiality, not mere presence, decides a load** (see `SKILL.md` Phase 0): a module loads
   when its technology is *central* to the scope, not on an incidental/transitive import.

---

## The packs are REFERENCES, not checklists — a floor, not a ceiling

This is a design invariant, not a style note. A pack exists to help an agent *recognize patterns
faster and reason about trade-offs* — it is a prior, not a worklist, and the consumer-side framing in
`lane-prompts.md` says so to every lane agent. Keep the producer side honest too:

- **Never imply completeness.** A pack names what is *known to be worth knowing*; it is never the
  boundary of what is worth finding. A finding the lens didn't list is the goal, not an exception.
- **Write for a reader who may be smarter than the author.** As models strengthen they need *less*
  hand-holding on durable fundamentals (they already know them) — so the durable pack is the **most
  skippable** layer for a strong model, and it must degrade gracefully: a stronger agent should lean
  on it lightly and out-reason it where it can, never be boxed in by it. Do not encode "do exactly
  this" prescriptions that a better judgment would override; encode the *condition* and the *trade-off*
  and let the agent decide.
- **The unknowable-facts layers age better than the pack.** The three-tier split is deliberate: the
  **version index** (post-training, version-pinned fast-paths) and the **currency brief** (post-cutoff
  recency) carry what *no* model can self-supply, while the durable pack carries what a capable model
  largely already knows. As models improve, weight shifts from the pack toward the index/brief — which
  is why version-specific claims must live there, not be baked into the pack. Keeping the pack durable
  and lean is itself the future-proofing.
