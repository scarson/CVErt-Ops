# Expected Findings — Rust fixture (core + web + async-tokio + database)

**Purpose:** exercise the Rust core lanes + the `web`, `async-tokio`, and `database` modules + the
Runtime & build notes. Illustrative (not built).

**Pack slice to provide:** `rust.md` lane slices + the **Runtime & build notes** section + (material)
`rust/web.md`, `rust/async-tokio.md`, `rust/database.md`. Do NOT let the agent read this rubric.

## Planted issues (should be found)

| # | Location | Lane / module | Issue |
|---|----------|---------------|-------|
| 1 | `handlers.rs` `AppState` (`#[derive(Clone)]`) | `web` | big owned state (`Vec<Product>` catalog) deep-cloned per request; hold heavy fields behind `Arc` (or `Arc<AppState>`). `PgPool` clone is fine — don't flag that part |
| 2 | `handlers.rs` `order_handler` loop | `database` | **N+1**: one `fetch_one` per id; batch with `WHERE id = ANY($1)` |
| 3 | `handlers.rs` `record_metric` | `async-tokio` | `std::sync::Mutex` guard **held across `.await`** — stalls the executor thread; drop the guard before awaiting |
| 4 | `handlers.rs` `dashboard` | concurrency | two **independent** awaits run sequentially; `tokio::join!`. Must state the independence guard |
| 5 | `inventory.rs` `label_for` | memory | `name.clone()` where `tag_of` could take `&str` — needless allocation |

## Beyond-the-pack (floor-not-ceiling — bonus, not required)

| Location | Issue | Why beyond the pack |
|----------|-------|---------------------|
| `inventory.rs` `count_skus` | `contains_key` then `insert` (+ a later `get_mut`) hashes the key 2–3× per item | The **Entry API** (`*counts.entry(sku).or_insert(0) += 1`) hashes once. No Rust-pack bullet names the double-hash; requires knowing the Entry API. Found ⇒ out-reasoned the lens. |

## Decoy (should NOT be flagged)

| Location | Why ignored |
|----------|-------------|
| `inventory.rs` `boot_defaults` | a `.clone()` of small fixed `Settings`, run once at startup. Mirrors #5's clone pattern but is cold/bounded → not a finding. Flagging it is a precision/checklist failure. |

## Scoring

- **Recall** = (# of {1..5} found) / 5. #1 should target the heavy fields (not the `PgPool`); #4 must
  include the independence guard.
- **Precision** = `boot_defaults` decoy not flagged; no fabricated findings.
- **Beyond-the-pack** = `count_skus` Entry-API double-hash flagged → out-reasons-the-lens bonus.

## How to run

Dispatch lane subagents (memory, data-access, concurrency) with the shared preamble + lane body from
`../../lane-prompts.md`, the `rust.md` lane slice + Runtime & build notes + the three modules, and this
directory as scope. Score against the tables above.

## Last run

**2026-06-04, Sonnet — GREEN.** Recall 5/5 (#1 correctly targeted the heavy fields and excluded
`PgPool`; #4 stated the independence guard); beyond-the-pack (`count_skus` Entry-API multi-hash) found
and flagged as not-in-the-pack; `boot_defaults` decoy rejected as the cold-path clone; the `Vec::with_capacity`
and hasher micro-opts correctly subordinated/rejected; zero fabrications.
