# Operational Maturity — Overview & Coordination

**Date:** 2026-03-10
**Status:** Design approved
**Scope:** Four pillars taking CVErt Ops from "working application" to "production-ready service"

## Context

CVErt Ops has a solid functional core (~95% of PLAN.md implemented). This design addresses the operational gaps that differentiate "building an app" from "running a service": observability, operations, security hardening, and extensibility.

**Target deployment:** Self-hosted open-source, with architecture decisions that anticipate open-core/SaaS later.

**Audience:** Enterprise IT teams evaluating self-hosted deployment. The engineering should be enterprise-grade; the process overhead should not be.

## Four Pillars

| Pillar | Design doc | Summary |
|--------|-----------|---------|
| **Observe/Instrument** | `2026-03-10-ops-observe-design.md` | Prometheus metrics enrichment, structured log correlation, Grafana dashboards, alerting rules, SLOs |
| **Operate** | `2026-03-10-ops-operate-design.md` | Health endpoints, auto-migrate, doctor CLI, site admin API+UI, Docker prod profile, deployment guide |
| **Secure** | `2026-03-10-ops-secure-design.md` | Dual-key rotation (JWT + encryption), SIGHUP config reload, security event pipeline, runtime self-checks |
| **Extend** | `2026-03-10-ops-extend-design.md` | Config-driven generic feed adapter, inbound webhook for custom feed ingestion, validate-feeds CLI |

## Phasing

```
Phase 8A ─ Shared Foundation (sequential, ~1 session)
  │  system_settings migration
  │  admin middleware verification
  │  security event type constants
  │  custom source precedence tier in merge pipeline
  │
Phase 8B-8D ─ Parallel Pillars (3 worktree agents)
  │
  ├── 8B Observe    ── metrics, logs, dashboards, alerts
  ├── 8C Operate    ── health, admin, doctor, deploy
  └── 8D Extend     ── generic feeds, inbound webhook, validate CLI
  │
Phase 8E ─ Secure (sequential, builds on Phase 8B-8D)
  │  dual-key rotation (JWT + encryption)
  │  SIGHUP config reload (+ feeds.d rescan from Extend)
  │  security events table + pipeline
  │  runtime security self-checks (wired into doctor from Operate)
  │  secret rotation runbook
  │
Phase 8F ─ Integration & Polish (sequential)
     deployment guide finalization
     runbook cross-references
     SLO documentation
     end-to-end smoke test across all pillars
```

## Phase 8A — Shared Foundation

Small, targeted changes that multiple pillars depend on. Done in a single session before spawning agents.

| Item | Why | Consumed by |
|------|-----|-------------|
| `system_settings` migration (`key TEXT PK, value BYTEA, created_at, updated_at`) | Doctor encryption sentinel, potential future system metadata | Operate, Secure |
| Verify `RequireSiteAdmin()` middleware exists and works | All admin endpoints | Operate, Secure |
| Security event type constants (`internal/secure/events.go`) | Event pipeline, Prometheus metric labels | Secure, Observe |
| Custom source precedence tier in `merge/pipeline.go` | Generic adapter, inbound webhook | Extend |

## Cross-Pillar Interface Contracts

Points where one pillar produces something another pillar consumes. Each contract must be stable before the consuming pillar starts.

| Producer | Consumer | Interface |
|----------|----------|-----------|
| **Observe (8B)** metrics package | **Secure (8E)** security event counter | `cvertops_security_events_total{event_type, severity}` counter. Secure imports and increments. If Observe hasn't landed yet, Secure registers the metric itself (same name, same labels). |
| **Operate (8C)** doctor framework | **Secure (8E)** security self-checks | Doctor exposes a `Check` interface: `Run(ctx) → (status, message, error)`. Secure implements checks, Operate wires them in. If Operate hasn't landed, Secure's checks are standalone functions. |
| **Operate (8C)** admin API routes | **Secure (8E)** security events API | Secure adds `GET /api/v1/admin/security-events` to the admin route group using the same `RequireSiteAdmin()` and `withBypassTx` patterns. |
| **Extend (8D)** `Rescan()` method | **Secure (8E)** SIGHUP handler | SIGHUP handler calls `Rescan()` on the generic feed loader. If Extend hasn't landed, SIGHUP only reloads secrets. |
| **Observe (8B)** metrics port config | **Operate (8C)** Docker Compose prod profile | Prod profile maps `METRICS_PORT`. Observe defines the env var; Operate's compose file references it. |

**Key principle:** Each pillar is independently testable and mergeable. Cross-pillar integrations are additive — a pillar works without its consumers.

## File Ownership (Conflict Prevention)

| File | Observe | Operate | Extend | Secure |
|------|---------|---------|--------|--------|
| `internal/api/server.go` | Metrics port listener | Admin routes, health endpoints | One ingest route | Reload-config endpoint |
| `internal/metrics/*.go` | Creates all files | — | — | May register security counter |
| `internal/api/admin_*.go` | — | Creates all files | — | Adds security-events handler |
| `internal/feed/generic/*` | — | — | Creates all files | — |
| `internal/secure/*` | — | — | — | Creates all files |
| `internal/log/*` | Creates (context logger) | — | — | — |
| `internal/ingest/feeds.go` | — | — | Modifies (generic detection) | — |
| `internal/merge/pipeline.go` | — | — | — (Phase 8A only) | — |
| `cmd/cvert-ops/main.go` | — | Auto-migrate logic | — | SIGHUP handler |
| `cmd/cvert-ops/validate.go` | — | — | Creates | — |
| `cmd/cvert-ops/rotate.go` | — | — | — | Creates |
| `cmd/cvert-ops/doctor.go` | — | Creates | — | — |
| `deploy/grafana/*` | Creates all files | — | — | Adds security alert rules |
| `docker/compose.prod.yml` | — | Creates | — | — |
| `docs/deployment/*` | — | Creates most | — | Secret rotation runbook |
| `web/src/views/admin/*` | — | Creates all files | — | — |

**`server.go` is the only shared file.** Each pillar touches a different section:
- Observe: new listener for metrics port (separate from main router)
- Operate: admin route group + health endpoints (infrastructure routes)
- Extend: one route in org-scoped group
- Secure: one route in admin group

## Merge Order

1. **Phase 8A** → merge to `dev`
2. **Observe (8B)** → merge to `dev` (no dependencies)
3. **Operate (8C)** → merge to `dev` (no dependencies on Observe)
4. **Extend (8D)** → merge to `dev` (depends on Phase 8A precedence tier only)
5. **Secure (8E)** → merge to `dev` (consumes Operate doctor, Observe metrics, Extend rescan)
6. **Phase 8F** → integration PR

Observe, Operate, and Extend can merge in any order. The listed order is preference, not requirement.

## Agent Context Requirements

Each pillar agent MUST be given:
1. This overview document (cross-pillar contracts, file ownership)
2. Its pillar-specific design document
3. `dev/testing-pitfalls.md`
4. `dev/implementation-pitfalls.md`
5. `CLAUDE.md`

Each pillar agent MUST NOT:
- Modify files owned by another pillar (see ownership table)
- Create cross-pillar dependencies not listed in the contracts table
- Assume another pillar's work has landed (design for independence)
