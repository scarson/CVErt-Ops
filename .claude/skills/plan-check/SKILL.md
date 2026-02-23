---
name: plan-check
description: Verify a CVErt Ops implementation against PLAN.md requirements. Finds all "Required", "MUST", and "(required)" markers in the relevant section and checks whether the code satisfies them. Use before merging a feature.
argument-hint: "<area or file to check (e.g., 'notification delivery', 'nvd adapter', 'internal/merge')>"
allowed-tools: Read, Glob, Grep
---

# Plan Compliance Check

Verifying CVErt Ops code against PLAN.md.

Target: **$ARGUMENTS**

## Step 1: Identify relevant PLAN.md sections

Search `PLAN.md` for the target area. Section quick reference:

| Area | Section |
|------|---------|
| Feed adapters, data ingestion, FeedAdapter interface | §3 (esp. §3.2, §3.3) |
| CVE data model, schema, timestamps | §4 + Appendix A |
| Merge pipeline, source precedence, material_hash | §5 |
| Multi-tenancy, RLS, org isolation | §6 |
| Auth, JWT, OAuth, API keys, sessions | §7 |
| Search, FTS, facets, CWE | §8 |
| Watchlists | §9 |
| Alert DSL, compiler, evaluation, dedup | §10 |
| Notifications, webhooks, delivery, fan-out | §11 |
| Scheduled reports, digests | §12 |
| AI gateway, LLM client | §13 |
| Rate limiting | §16.1 |
| Worker, job queue, graceful shutdown | §18.1 |
| HTTP framework, huma patterns | §18.2 |
| Binary, container, startup, timeouts | §18.3 |
| Data retention, cleanup batching | §21 |
| Schema conventions, index rules, migrations | Appendix A |
| API endpoint patterns, PATCH structs, pagination | §16 |

## Step 2: Read the relevant sections

Use Grep to find `(required)`, `MUST`, `Required pattern`, `(required design decision)`, `Required:` in the relevant PLAN.md sections. These are non-negotiable requirements.

Also read the code to check (glob the target package or read the specified file).

## Step 3: Check each requirement

For every requirement found:

**Format:**
```
§X.Y — <Section title>

✅ <Requirement summary>: satisfied at path/file.go:line
   Evidence: <brief quote or description of where it's implemented>

❌ <Requirement summary>: NOT satisfied
   Required: <what PLAN.md says>
   Found: <what the code actually does, or "not found">
   Fix: <how to correct it>

⚠️  <Requirement summary>: partially satisfied
   Missing: <what's incomplete>
```

## Step 4: Common requirement categories to check

These appear frequently across sections — always check them for any org-scoped code:

**Tenant isolation:**
- Every org-scoped repository method accepts `orgID uuid.UUID` as a parameter
- No query returns cross-org data
- `SET LOCAL app.org_id = $1` called at transaction start

**Security:**
- Outbound HTTP uses `doyensec/safeurl`
- No open DB transaction during outbound HTTP call
- `crypto/subtle.ConstantTimeCompare` for any hash/secret comparison

**Worker concurrency:**
- Background goroutines from HTTP handlers use `context.WithoutCancel(r.Context())`
- Long-running goroutine loops use `time.NewTicker` not `time.After`
- Notification fan-out uses `sync.WaitGroup`, not `errgroup`

**PATCH endpoints:**
- All optional fields in PATCH request structs use pointer types (`*bool`, `*string`, not value types)

**Pagination:**
- All keyset pagination queries include composite `(sort_col, cve_id)` cursor with tiebreaker
- Nullable sort columns use `COALESCE` in cursor comparison

## Step 5: Score

End with:

```
Plan compliance: X/Y required items satisfied.
Critical failures (❌): N
Warnings (⚠️): M
```

List all ❌ failures sorted by risk impact.
