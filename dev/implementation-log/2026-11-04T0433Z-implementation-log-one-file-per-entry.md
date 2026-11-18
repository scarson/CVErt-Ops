# Implementation Log — One File per Entry

> **Date:** 2026-11-03

## What was built

| Feature | Files | Description |
|---|---|---|
| Entry directory | `dev/implementation-log/` | Replaces `dev/implementation-log.md`. Each entry is a file named `YYYY-MM-DDTHHMMZ-<slug>.md`; the README holds the naming rules |
| Split of the existing log | 65 entry files | Each `##` section of the old file became one file with its headings raised one level; no other text changed |
| Updated instructions | `CLAUDE.md`, `AGENTS.md`, `.claude/skills/implementation-log/SKILL.md`, four `dev/plans/` files | Point at the directory and say to write a new file instead of appending |

## Key implementation decisions

- **Separate files instead of appending to one file** — parallel branches all appended to the end of `dev/implementation-log.md`, so nearly every merge to `dev` conflicted in that file. Separate files with distinct names do not conflict.
- **No index file** — the sorted filenames already give chronological order, and an index that every branch adds a line to would conflict in the same way.
- **Timestamp of a migrated entry is when its work landed** — for entries that name a commit range, the author time of the last commit; for 8A, 8B, 8D, 8E and 11 (PR only), the PR's merge commit on `dev`; otherwise the time the section was first committed to the log. The earlier of the work time and the logging time was used, so backfilled entries sort with their work, not with the backfill commit.
- **Colon-free time in the filename** — Windows does not allow `:` in filenames, so the time is written `HHMM` after an ISO 8601 date.

## Gotchas discovered

- **`**Commits:**` lines that name a branch base** — three entries end with "branched from dev at `2dcffc8`" or use a `<first>..HEAD` range. Taking the last hash on the line dated them by the branch base (2026-10-27). The split ignores text after "branched" and does not use `..HEAD` ranges.
- **GNU `sed -i` from Git Bash wrote LF** into CRLF working-tree files. The index content was unaffected; the files were deleted and checked out again from the index to restore CRLF.

## Quality checks

- **Content preserved:** a script compared every non-blank, non-separator line of the old file with the 65 entry files (headings lowered back one level). Result: 0 missing lines, 0 extra lines.
- **Stale references:** `git grep 'implementation-log\.md'` finds none.
- **Go build, lint, tests:** not run; the change contains no code.
