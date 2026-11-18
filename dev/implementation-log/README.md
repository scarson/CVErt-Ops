# CVErt Ops — Implementation Log

> **Purpose:** Record of what was built in each phase or feature block, implementation decisions
> that are *not* already in PLAN.md, gotchas discovered, and quality check results.
>
> **Not a substitute for:** commit messages (what changed), PLAN.md (the PRD/spec),
> research.md (architectural rationale), implementation-pitfalls.md (anti-patterns to avoid).

## One file per entry

Each entry is its own file in this directory, named:

```
YYYY-MM-DDTHHMMZ-<slug>.md
```

- **Timestamp** — UTC time the work landed: an ISO 8601 date, then the time without colons, which
  Windows does not allow in filenames. Get it with `date -u +%Y-%m-%dT%H%MZ` (bash) or
  `(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHHmm'Z'")` (PowerShell).
- **Slug** — the entry title in lowercase ASCII, words joined by `-`, at most about 70 characters.
- The file starts with `# <Entry title>`; its sections are `##` headings. The
  `.claude/skills/implementation-log/SKILL.md` skill holds the section template.

Sorting the filenames gives the entries in chronological order, so this directory has no index.
Do not add one: a file that every branch appends a line to causes the merge conflicts that a
single shared log file caused. For the same reason, an entry never edits another entry to add
to it. Correcting a mistake in an existing entry is fine.
