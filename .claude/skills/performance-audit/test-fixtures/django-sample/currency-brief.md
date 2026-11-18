---
schema_version: 1
framework: django
ecosystem: pypi
researched_against_version: 5.0.x
latest_known_at_research: 5.0.x
researched_on: 2026-06-03
fallback_ttl_days: 180
sources:
  - https://docs.djangoproject.com/en/5.0/ref/models/querysets/
  - https://docs.djangoproject.com/en/5.0/releases/
---

> HAND-AUTHORED for the Lane 5 fixture test. In real use this file is produced by the
> currency-protocol research step; here it is the brief the workhorse would pass to Lane 5.

## Superseded patterns (old → new)
- `len(queryset)` / `bool(queryset)` / `if queryset:` to test existence → `queryset.exists()`.
  `len()` executes the query and instantiates every row; `.exists()` issues a cheap `SELECT 1 ... LIMIT 1`.
- `QuerySet.extra(select=..., where=...)` raw SQL fragments → `annotate()` with ORM expressions
  (`F`, `Value`, `ExpressionWrapper`, database functions). `.extra()` is long-deprecated, a
  SQL-injection/maintenance hazard, and excluded from query-planner optimizations.
- Per-object `.save()` in a loop over the same field set → `QuerySet.bulk_update(objs, ["field"])`
  (one statement instead of N).

## New fast-path APIs (and the version that introduced them)
- `QuerySet.bulk_create(..., update_conflicts=True, unique_fields=..., update_fields=...)` — native upsert.
- Async ORM: `aget()`, `acount()`, `async for` over querysets for async views.

## Changed defaults
- (none relevant to this fixture)

## Known perf regressions / fixes by version
- (none relevant to this fixture)
