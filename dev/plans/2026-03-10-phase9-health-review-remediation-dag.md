# Phase 9 Health Review Remediation — Task DAG

Dependency graph for `dev/plans/2026-03-10-phase9-health-review-remediation-plan.md`.

Sources of edges:
- Stage Overview "Dependency graph" block in the plan (lines 43–51)
- Stage 1 prologue: "Task 1.11 must execute AFTER all other Stage 1 tasks have been committed" (line 83)
- Stage 2B prologue: "These tasks clean up the evaluator internals BEFORE wiring it into the runtime (Stage 2C)" (line 961)
- Task 2B.1 body: post-filter target type is `generated.CVE`, "type was renamed from `Cfe` to `CVE` by Task 1.11" (line 980) → 2B.1 ⟵ 1.11
- Task 2A.2 body: query asserts via `tdb.AppStore` (the `NOBYPASSRLS` role) → 2A.2 ⟵ 2A.1
- Task 2C.2 body: realtime hook fires after merge once batch/EPSS jobs are registered → 2C.2 ⟵ 2C.1
- Task 6C body: "DEFERRED — depends on Stage 3 completing" (line 2761)
- Stage 3 body: "implementation plan for the revised Stage 3 will be written after the OpenAPI evaluation gate completes" (line 1282)

## Mermaid graph

```mermaid
graph TD
  P8["Phase 8 merges<br/>(8B Observe, 8C Operate, 8D, 8E)"]:::prereq

  %% ── Stage 1 ──────────────────────────────────────────
  subgraph S1["Stage 1: Quick Wins"]
    T1_1["1.1 Close api.Server"]
    T1_2["1.2 Close stdlib DB wrappers"]
    T1_3["1.3 Validate COOKIE_SECURE"]
    T1_4["1.4 Worker pool ctx cancel"]
    T1_5["1.5 Remove dead readTx"]
    T1_6["1.6 Fix GetCVEDetail comment"]
    T1_7["1.7 Add missing assertion"]
    T1_8["1.8 Stop discarding setup errors"]
    T1_9["1.9 DownloadToTemp pkg state"]
    T1_10["1.10 Validate InCISAKEV bool"]
    T1_12["1.12 Dedup toNullString"]
    T1_11["1.11 sqlc rename Cfe → CVE<br/>(after all other Stage 1)"]:::ordering
  end

  %% ── Stage 2A ─────────────────────────────────────────
  subgraph S2A["Stage 2A: RLS Security"]
    T2A_1["2A.1 Restricted app DB role"]
    T2A_2["2A.2 RLS cross-tenant test"]
  end

  %% ── Stage 2B ─────────────────────────────────────────
  subgraph S2B["Stage 2B: Evaluator Refactor"]
    T2B_1["2B.1 Extract post-filter"]
    T2B_2["2B.2 Merge queryCandidates"]
  end

  %% ── Stage 2C ─────────────────────────────────────────
  subgraph S2C["Stage 2C: Alert Wiring"]
    T2C_1["2C.1 Schedule batch + EPSS jobs"]
    T2C_2["2C.2 Realtime post-merge hook"]
  end

  %% ── Stage 3 ──────────────────────────────────────────
  GATE["OpenAPI evaluation gate<br/>(see proposal doc)"]:::gate
  subgraph S3["Stage 3: API Contract Convergence"]
    T3_0["3.0 Reference: Groups"]
    T3_1["3.1 Saved Searches"]
    T3_2["3.2 API Keys"]
    T3_3["3.3 Channels"]
    T3_4["3.4 Watchlists"]
    T3_5["3.5 Alert Rules"]
    T3_6["3.6 Deliveries (#43)"]
    T3_7["3.7 Reports"]
    T3_8["3.8 Orgs (#34)"]
    T3_9["3.9 Members + Invitations"]
    T3_10["3.10 Audit Log"]
    T3_11["3.11 Admin Endpoints"]
    T3_12["3.12 Feeds Admin"]
    T3_CLEAN["Post-migration cleanup<br/>(delete orgFetch + writeJSON)"]
  end

  %% ── Stage 4 ──────────────────────────────────────────
  subgraph S4["Stage 4: Ops Hardening"]
    T4D["4D Notification semaphore eviction"]
    T4E["4E Configurable statement timeout"]
  end

  %% ── Stage 5 ──────────────────────────────────────────
  subgraph S5["Stage 5: Test Quality"]
    T5A["5A Feed adapter golden tests"]
    T5B["5B Ingest handler integration test"]
    T5C["5C Email testcontainer"]
    T5D["5D Advisory lock concurrency test"]
  end

  %% ── Stage 6 ──────────────────────────────────────────
  subgraph S6["Stage 6: Architecture"]
    T6A["6A ServerDeps options struct"]
    T6B["6B Notification worker health"]
    T6E["6E merge.Store interface"]
    T6F["6F BootstrapFirstUserOrg refactor"]
    T6C["6C Extract buildApp()<br/>(deferred)"]:::deferred
    T6D["6D ~~import-bulk for NVD~~<br/>INVALIDATED"]:::invalidated
  end

  %% ── Edges ────────────────────────────────────────────
  P8 --> S1
  P8 --> S2A
  P8 --> S2B
  P8 --> S2C
  P8 --> GATE
  P8 --> S4
  P8 --> S5
  P8 --> S6

  T1_1 --> T1_11
  T1_2 --> T1_11
  T1_3 --> T1_11
  T1_4 --> T1_11
  T1_5 --> T1_11
  T1_6 --> T1_11
  T1_7 --> T1_11
  T1_8 --> T1_11
  T1_9 --> T1_11
  T1_10 --> T1_11
  T1_12 --> T1_11

  T2A_1 --> T2A_2

  T1_11 --> T2B_1

  T2B_1 --> T2C_1
  T2B_2 --> T2C_1
  T2C_1 --> T2C_2

  GATE --> T3_0
  T3_0 --> T3_1 --> T3_2 --> T3_3 --> T3_4 --> T3_5 --> T3_6 --> T3_7 --> T3_8 --> T3_9 --> T3_10 --> T3_11 --> T3_12 --> T3_CLEAN

  T3_CLEAN --> T6C

  classDef prereq    fill:#fce4a6,stroke:#a06b00,color:#3a2a00
  classDef ordering  fill:#e8d5ff,stroke:#5b27a8,color:#22094a
  classDef gate      fill:#d4edff,stroke:#1f6feb,color:#0a2540
  classDef deferred  fill:#f0f0f0,stroke:#999,color:#444
  classDef invalidated fill:#f7f7f7,stroke:#bbb,color:#888,stroke-dasharray: 4 3
```

## Topological layers (parallel-execution view)

A subagent coordinator can fan out each layer in parallel; later layers wait for the prior layer's edges.

| Layer | Tasks | Notes |
|-------|-------|-------|
| L0 | Phase 8 merges | Prerequisite — out of scope for this plan |
| L1 | 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.10, 1.12 · 2A.1 · 2B.2 · 4D · 4E · 5A · 5B · 5C · 5D · 6A · 6B · 6E · 6F · OpenAPI gate | All independent. Stage 1 (excl. 1.11) is the prime parallel batch. |
| L2 | 1.11 · 2A.2 · 3.0 | 1.11 waits on all other Stage 1; 2A.2 waits on 2A.1; 3.0 waits on the OpenAPI gate. |
| L3 | 2B.1 | Needs the `generated.CVE` rename from 1.11. |
| L4 | 2C.1 | Needs both 2B.1 and 2B.2 complete. |
| L5 | 2C.2 | Sequential after 2C.1. |
| L6 | 3.1 → 3.2 → 3.3 → 3.4 → 3.5 → 3.6 → 3.7 → 3.8 → 3.9 → 3.10 → 3.11 → 3.12 | Sequential migrations following the 3.0 reference; each is one commit per the plan. |
| L7 | Stage 3 post-migration cleanup | After 3.12. |
| L8 | 6C (extract `buildApp()`) | Deferred until Stage 3 is complete and stable. |

Tasks not on the critical path: 4D, 4E, 5A–5D, 6A, 6B, 6E, 6F can finish at any point after L1.

## Critical path

`Phase 8 → {1.1–1.10, 1.12} → 1.11 → 2B.1 → 2C.1 → 2C.2`

Stage 3 has its own parallel critical path gated by the OpenAPI evaluation:

`Phase 8 → OpenAPI gate → 3.0 → 3.1 → … → 3.12 → cleanup → 6C`

The two paths don't intersect, so they can progress concurrently once Phase 8 lands.

## Resolved / invalidated (no DAG nodes)

- **Findings 3, 10, 11, 38** — resolved by Phase 8 or already correct; no task.
- **Task 6D (Finding 19)** — invalidated; NVD has no bulk download archives.
- **Task 4A, 4B, 4C** — 4A/4B subsumed by Phase 8; 4C moved into Stage 6 as 6C.
