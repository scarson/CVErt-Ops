# Remove `fire_on_non_material_changes` from alert rules

**Status:** decided by Sam, 2026-11-14. Implemented on branch `claude/remove-fire-on-non-material`.
**Changes:** PLAN.md §10.4 (dedup model); the `alert_rules` table (migration 000064); the alert-rule API and its OpenAPI schema.

## The short version

Alert rules carried a flag, `fire_on_non_material_changes`, that the API accepted, stored and returned, but that nothing ever read: setting it changed nothing. Building it as PLAN.md §10.4 described would mostly produce noise, so the flag is removed: from the API, from the `alert_rules` table, and from PLAN.md. The useful versions of the idea are specific triggers, designed separately if they are wanted (see "If something like it is wanted later").

## How alerting avoids repeats

Every CVE carries a fingerprint, `material_hash`: a hash of the fields that change what the CVE means. Those are the status, severity, CVSS scores and vectors, CWEs, the exploit-available and KEV flags, and the affected packages and products (PLAN.md §5.3; `merge.MaterialFields`). A rule alerts on a CVE once per fingerprint (PLAN.md §10.4; `alert_events` is unique on `(org_id, rule_id, cve_id, material_hash)`).

- If NVD re-publishes a record with only a new "last modified" date, one more reference link or reworded description text, the fingerprint does not change, and nobody is notified again.
- If the CVSS score goes from 5.0 to 9.8, the fingerprint changes, and the rule alerts again.

The EPSS score (FIRST's daily estimate of how likely a CVE is to be exploited) is left out of the fingerprint on purpose. FIRST publishes a new score for nearly every CVE every day, and most changes are tiny (0.0412 to 0.0415). With EPSS in the fingerprint, every rule would re-alert on most of its CVEs every day.

## What the flag would have done

The flag meant "also alert me when something outside the fingerprint changes". What that produces depends on the rule:

- **A rule with an EPSS condition**, for example "severity critical and `epss_score` at least 0.1". The EPSS evaluator re-checks such rules every day (PLAN.md §10.3), and almost every matching CVE's score has moved a little. With the flag on, each of those moves counts as a change, so the rule would notify about once a day for every CVE it matches. A rule that matches 200 CVEs would send about 200 messages a day, each saying in effect "the score moved slightly".
- **A rule without an EPSS condition.** EPSS changes never trigger it. Repeats would come from feeds re-publishing records with nothing meaningful changed: NVD updating its date, adding a reference link or rewording the description. That happens irregularly and in bursts. Old CVEs are quiet, a new CVE can be re-published several times in its first weeks, and NVD sometimes reprocesses tens of thousands of records in one day.

Either way, "alert on any non-material change" mostly delivers noise, and the changes a user would care about get lost in it.

Building it would also have cost a migration and a change to how repeats are suppressed. `alert_events` allows one event per rule, CVE and fingerprint, so firing again at the same fingerprint needs another record of which change the rule last fired on.

## Why removing it is safe

- Nothing reads the flag (`internal/alert` never refers to it), so removing it changes no alert.
- The project has no users yet (CLAUDE.md, "Development status"), so dropping an API field and a column breaks no one. A client that still sends the field in a create or update request is not refused: the alert-rule handlers ignore JSON fields they do not know. The field no longer appears in responses or in the OpenAPI schema.
- PLAN.md §10.4 keeps the other two re-fire rules: a rule fires again when `material_hash` changes, and a resolved event reopens when its CVE matches again at a fingerprint the rule already fired on.

## If something like it is wanted later

The useful versions are specific triggers, each its own small feature:

- "Tell me when EPSS rises above 0.5." Part of this exists already: a rule with `epss_score gte 0.5` alerts when a CVE's score crosses into that range, not on every small move. It does not alert again on a further rise inside the range.
- "Tell me when an exploit reference or a KEV listing is added." KEV status is already in the fingerprint. A new exploit reference is not.

Each would say exactly which change fires the rule, so it stays quiet otherwise.
