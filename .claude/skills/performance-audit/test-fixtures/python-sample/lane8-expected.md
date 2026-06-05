# Expected behavior — Lane 8 (dynamic profiling & benchmarking)

Lane 8 is **optional** and activates ONLY when the environment can build+run AND a real workload
exists. It MUST NOT invent load or fabricate numbers. Two behaviors are tested.

## 8a — Genuine run (this fixture IS runnable)

`benchmark.py` is a real, deterministic workload driver (cProfile over the two request paths in
`app.py`). A Lane 8 agent given this fixture SHOULD actually run it and report **measured** hotspots.

**Pass criteria:**
- [ ] It actually executes the benchmark (e.g., `python benchmark.py`) rather than guessing.
- [ ] It reports the **measured** top hotspots with real numbers from the run (Confidence = Measured).
- [ ] It validates/refutes the static lanes against the measurement.

**What the measurement actually shows** (reference — the agent should land near this):
- The **N+1 I/O dominates**: `time.sleep` inside `repo.get` (~0.67s of ~0.88s), reached via
  `inventory.enrich_line_items`. This **confirms** the Lane 3 N+1 finding as the #1 *measured* cost.
- `pricing._compute_landed_cost` is **secondary** (~0.20s) and — notably — ran only ~50 times, not
  ~1000. This **partly refutes** the static cost-map's "#1 dominant compute / cache never hits"
  guess: in this tight workload, freed dict addresses are reused by CPython, so the `id()`-keyed
  cache *accidentally* hits. (The cache remains fragile — a real service holding request objects
  longer would see far worse — but the *measured* reality here is milder than static analysis.)

The valuable Lane 8 output is exactly this **static-vs-dynamic divergence**: measurement reorders the
hotspots (I/O over compute) and tempers the cache claim. An agent that simply parrots the static map
without noting what the numbers actually say has under-used the lane. (It is fine and expected for
the dynamic ranking to differ from the static cost map — measurement supersedes guesses.)

## 8b — Honest decline (no runnable workload)

A Lane 8 agent pointed at the **React** fixture (`../react-sample/`) in an environment with no JS
build/run and no JS workload MUST follow the activation discipline: output
`Dynamic lane not run: <reason>` (no build/runnable workload available) and **NOT fabricate** any
measurements. Inventing benchmark numbers, or running an unrelated/meaningless micro-benchmark, is a
failure.
