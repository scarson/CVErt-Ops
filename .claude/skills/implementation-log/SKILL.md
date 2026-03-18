---
name: implementation-log
description: Append a phase completion entry to dev/implementation-log.md. Use when finishing a phase or significant feature block — not after every commit.
argument-hint: "<phase name, e.g. 'Phase 8E — Ops & Secure' or 'Phase 11 — MFA Handlers'>"
---

# Implementation Log Entry

Appending a phase completion entry for: **$ARGUMENTS**

## Step 1: Gather context

Collect the raw material for the entry. Run these in parallel:

1. **Read the tail of `dev/implementation-log.md`** (last 80 lines) to see the most recent entry's format and the `---` separator you'll append after
2. **Identify the commit range**: `git log --oneline dev` — find the first and last commits belonging to this phase (use branch name, PR title, or commit message prefixes to identify them)
3. **Find the plan file** (if one exists): `ls dev/plans/` — look for a plan matching the phase name
4. **Identify files changed**: `git diff --stat <first-commit>^..<last-commit>` to see the scope of changes

## Step 2: Draft the entry

Follow the exact structure used by existing entries. The format varies slightly by phase complexity, but always includes:

```markdown
---

## <Phase name>

> **Date:** <YYYY-MM-DD>
> **Commits:** `<first>`..`<last>` on `<branch>`
> **Plan:** `dev/plans/<plan-file>` (if applicable)

### What was built

| Feature | Files | Description |
|---|---|---|

### Key implementation decisions

- **<Decision>** — <rationale>

### Gotchas discovered

- **<Gotcha>** — <what happened and how it was resolved>

### Quality checks

- **go build ./...:** <result>
- **golangci-lint:** <result>
- **Tests:** <summary of test results>
```

**Important guidelines:**
- Only include sections that have content — skip "Gotchas" if there were none
- "What was built" should be a table of features, not a file-by-file listing
- "Key implementation decisions" captures decisions NOT already in PLAN.md — things discovered during implementation
- "Gotchas discovered" captures surprises, pitfalls, debugging insights — things future sessions should know
- Keep entries concise — this is a reference log, not a narrative
- Use commit messages, PR descriptions, and the plan file as source material — don't fabricate details

## Step 3: Run quality checks

Before writing the entry, run the actual quality checks so you can report real results:

```bash
go build ./...
golangci-lint run
go test ./...
```

Report the real output, not assumptions.

## Step 4: Append the entry

Append the entry to the end of `dev/implementation-log.md`. The file should end with a `---` separator after the new entry.

## Step 5: Commit

Stage and commit just the implementation log:

```bash
git add dev/implementation-log.md
git commit -m "docs(log): add <phase name> implementation log entry"
```
