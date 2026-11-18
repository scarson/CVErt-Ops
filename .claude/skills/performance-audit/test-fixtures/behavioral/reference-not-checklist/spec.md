# Behavioural eval: "a reference, not a checklist — a floor, not a ceiling"

**Property under test:** the consumer-side framing in `lane-prompts.md` (shared preamble: *"THE
PROFILE-PACK LENS IS A REFERENCE, NOT A CHECKLIST … a PRIOR not a worklist, a FLOOR not a ceiling …
do NOT report an item merely because the pack lists it … never limit your investigation to what the
pack names … out-reason it"*). This is the highest-value behavioural guarantee in the skill; this test
checks both halves: **(a)** don't fabricate findings for pack idioms that don't apply, and **(b)** find
a real issue the pack didn't name.

**Scope:** `orders.py`. **Lane:** `algorithmic` (the `memory` lane works too).

## How to run

- **GREEN run (primary):** dispatch an `algorithmic` lane subagent with the shared preamble (which
  contains the reference-not-checklist framing) + the `algorithmic` lane body + the **Python pack**
  `algorithmic` slice + the path to `orders.py`. Do not let it read this spec.
- **RED run (control, optional):** same, but **strip the reference-not-checklist paragraph** from the
  preamble. Expect more fabricated "consider using a set / a generator / `__slots__`" findings on the
  decoys, and/or no engagement with `process_in_arrival_order`.

## Scoring

| Function | Category | GREEN expectation |
|---|---|---|
| `dedupe_order_ids` | **Recall** (genuine O(n²)) | **Found** — flagged as accidental quadratic; `set` fix. Missing it = recall failure. |
| `is_valid_status` | **Decoy** (constant n=4, not looped) | **Not flagged** (or explicitly considered + rejected on bounded-n grounds). Flagging "use a set" = precision/checklist failure. |
| `status_breakdown` | **Decoy** (bounded one-pass list) | **Not flagged.** "Use a generator" here is a checklist-walk; the intermediate is small and consumed once. |
| `Money` / `__slots__` | **Decoy** (few instances) | **Not flagged.** "Add `__slots__`" with a handful of instances is a checklist-walk with no aggregate impact. |
| `process_in_arrival_order` | **Beyond-the-pack** (`list.pop(0)` → `deque`) | **Bonus if found** (reasoned that `pop(0)` is O(n); `collections.deque`). NOT a recall miss if absent — but consistent misses across runs ⇒ checklist-walking signal. |

**Pass = GREEN run flags `dedupe_order_ids`, fabricates ZERO decoy findings (ideally states it
considered and rejected them), and ideally surfaces `process_in_arrival_order` by reasoning.**
The discriminating signal vs. a checklist-walker is the *decoys staying silent* and the
*beyond-the-pack issue being engaged*.

## Result log

| Date | Model | Recall (dedupe) | Decoys fabricated | Beyond-the-pack found | Verdict |
|---|---|---|---|---|---|
| 2026-06-04 | Sonnet | ✅ | 0 (explicitly considered + rejected all 3, naming "checklist-walking") | ✅ (`pop(0)`→`deque`, reasoned from CPython list internals) | **GREEN** |
