# Behavioural eval: "materiality decides the load, not mere presence"

**Property under test:** the Phase-0 rule in `SKILL.md` — *"Detection selects candidates; materiality
decides the load … a lone `import json` / `import asyncio` that is peripheral to the scoped code does
not by itself warrant the serialization or async module."* This guards against over-loading a lane
agent's prompt with modules irrelevant to the actual scope.

**No code fixture needed — it's a Phase-0 detection scenario.** (Optionally point it at a real repo.)

## How to run

Dispatch a subagent with **only** the `SKILL.md` **Phase 0** section (the detection table + the
sub-stack-modules rule + the materiality sentence) and this scenario, and ask: *"Which profile pack(s)
and sub-stack module(s) do you load, and why?"* Do not show it the expected loadout below.

### Scenario

> **Audit scope:** `pricing/calc.py` — a CPU-bound pricing-calculation module (nested rate tables,
> tier math). Profile/optimize this file.
>
> **Repo facts:** `requirements.txt` lists `fastapi`, `sqlalchemy`, `pydantic`, `orjson`. `calc.py`
> itself imports only `math` and `json` (the latter used **once at import time** to load a static
> rate-table config file). The web handlers and DB models live in *other* packages not in this scope.

## Expected loadout (GREEN)

| Pack / module | Load? | Why |
|---|---|---|
| `python.md` core + Runtime & interpreter notes | **Yes** | the scoped code is Python |
| `python/serialization.md` | **No** | the only `json` use is a one-time startup config read — *incidental*, not the hot path under audit; `orjson` in `requirements.txt` is used elsewhere, not in scope |
| `python/web-frameworks.md` | **No** | `fastapi` is a repo dep but the scoped file has no web surface; web is not material to `calc.py` |
| `python/orm-database.md` | **No** | `sqlalchemy` is a repo dep but the scoped file does no DB access |
| `python/async-asyncio.md` | **No** | no async in scope |

**Pass = loads the Python core (+ Runtime notes) and NONE of the four modules**, with the reasoning
that materiality (not the presence of a dep in `requirements.txt` or an incidental `import json`)
decides the load. **Fail (RED, without the materiality rule)** = loads `serialization` on the `json`
import and/or `web-frameworks`/`orm-database` because the deps are in the manifest.

> Variant: change the scope to "audit the FastAPI request handlers in `api/routes.py` that serialize
> large responses" — now `web-frameworks` and `serialization` **are** material and SHOULD load. The
> rule is scope-relative, not a fixed per-repo answer.

## Result log

| Date | Model | Loaded core only? | Spuriously loaded a module? | Verdict |
|---|---|---|---|---|
| 2026-06-04 | Sonnet | ✅ (python core only) | No — skipped all 6 with correct materiality reasoning (`json` flagged as the closest call, correctly rejected as a one-time import-time config read) | **GREEN** |
