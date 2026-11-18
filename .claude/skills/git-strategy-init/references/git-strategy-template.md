# Git Strategy

Policy for keeping a repository out of the branch-proliferation + checkout-roulette failure mode that eats coordination time. The failure is acute when multiple concurrent agents share one working tree, but the rules apply to any workflow where more than one unit of work is ever in flight (including solo developers juggling branches).

## Branching model

This strategy assumes **one long-lived integration branch** where work converges. All other work happens in isolated worktrees — each with its own ephemeral branch that exists only to carry commits to a PR. Branches are merge vehicles, not workspaces; the root checkout stays on the integration branch and never switches off it. This maps directly to:

- **GitHub flow** — integration branch is `main`. (This doc's default.)
- **Trunk-based development** — integration branch is `main`; worktrees live hours rather than days; feature flags cover incomplete work.
- **Two-branch / simplified gitflow** — integration branch is `dev`; `main` is release-only, updated via periodic release PRs from `dev`.

Out of scope: the release-cut mechanism itself (e.g. `release/*` branches, hotfix branches cut from `main`, environment branches like `staging` and `production`, and the PR-from-`dev`-to-`main` flow in two-branch gitflow). The invariants below still apply to all feature work converging on the integration branch — you'll need separate policy for whatever ships *off* that branch.

## Adapting this doc to your project

This doc assumes your integration branch is `main`. If it's something else (e.g. `dev`, `develop`, `trunk`):

1. Identify your pattern in the **Branching model** section above. Once you've identified it, you can delete that section — it's descriptive, not operational, and it uses both `main` and `dev` as concrete branch names inside the patterns, which makes step 2 unsafe to apply to it.
2. Find-replace `main` → your branch name throughout **the rest of the doc** (everything below this section). The word `main` below this section *only* refers to the branch — the root working tree is called the "root checkout" to avoid collision.
3. Review the command blocks after replacement to confirm they still make sense.

### Other baked-in assumptions

- **GitHub + `gh` CLI.** Commands like `gh pr create` and `gh pr merge` assume GitHub. For GitLab, Bitbucket, or other forges, substitute the equivalent CLI (`glab`, `bb`, etc.) or web-UI step.
- **Bash-like shell.** `$(date +%Y%m%d)` and similar constructs assume bash/zsh (or Git Bash on Windows). PowerShell / cmd users will need to adapt.
- **Worktree path is gitignored.** This doc uses `.claude/worktrees/<name>` by convention (originating from Claude Code usage); any gitignored path inside the repo works. If you pick a different path, substitute it throughout. Whatever path you choose, add it to `.gitignore` before creating any worktrees — otherwise worktree files show up in `git status` and risk being committed.
- **Optional project-tracking doc.** One bullet in §Mechanics for auto-merge mentions updating a `program-status` doc. If your project has no such doc, ignore that bullet.


---

## Why this exists

Typical failure pattern: multiple concurrent agents share the root checkout, create and check out feature branches inside it, commit to local `main`, and produce a three-way divergence that requires manual reconciliation. Branches accumulate — dozens of local branches, many live worktrees — and every fresh agent spends turns orienting to the git state rather than doing the work.

The framing: when every agent working right now is getting confused, the strategy is not working. Time and tokens get spent unfucking git instead of shipping. The goal is to keep the repo in a state where a new agent can orient in seconds.

This doc captures the policy so the failure doesn't recur.

## Contents

- [Invariants](#invariants)
- [Day-one workflow for any new work](#day-one-workflow-for-any-new-work)
- [What NOT to do](#what-not-to-do)
- [Recovery from a messy state](#recovery-from-a-messy-state)
- [Multi-agent coordination rules](#multi-agent-coordination-rules) — git isolation + output persistence
- [Campaign branches](#campaign-branches) — long-cycle work (audits, multi-phase refactors)
- [Living documents on campaign branches](#living-documents-on-campaign-branches)
- [Merge authority](#merge-authority) — review triggers, auto-merge, classification, CI failures, merge conflicts
- [Abandoning a branch](#abandoning-a-branch) — PR closed without merging
- [Red flags (stop and diagnose)](#red-flags-stop-and-diagnose)
- [Rationale (failure-mode table)](#rationale-failure-mode-table)
- [Exceptions](#exceptions)

## Invariants

1. **The root checkout is always on `main`.** `git branch --show-current` in the root checkout always prints `main`. No `git checkout <branch>` in the root checkout, ever.
2. **Local `main` mirrors `origin/main`.** Any divergence is transient — at most one operation away from being pushed or reset.
3. **Work happens in dedicated worktrees.** `git worktree add .claude/worktrees/<name> -b <branch>` creates both the worktree and the branch atomically. The worktree is the workspace (for whoever — agent or human — is doing the work); the branch is the merge vehicle.
4. **Branches are ephemeral.** Branch → work → PR → merge → delete branch + worktree **in the same session that performed the merge, before starting the next task**. That's the concrete bar — not "promptly" in the hand-wavy sense, but *this session, now, before I move on*. For day-sized work the branch's whole lifecycle fits in one session. For long campaigns (audits, multi-phase refactors, research with a Living Document), the branch lives for the duration of the campaign and is deleted in the session that merges its final PR. See §Campaign branches for the long-cycle pattern. No branch — regardless of prefix (`feat/*`, `fix/*`, `chore/*`, `audit/*`, etc.) — persists past its PR merge.
5. **Push after every merge.** Local `main` never sits ahead of `origin/main` for more than the single operation between merge and push.
6. **Only one session writes to local `main` at a time.** Concurrent merges by different sessions into local `main` cause the three-way divergence described in §Why this exists.

   **Concrete test:** if you are running any of `gh pr merge`, `git push origin main`, or `git reset --hard origin/main` against local `main` *right now*, you are the writer for that operation. No other session may run any of those at the same time — full stop, no exceptions, no "probably fine if it's fast." If you don't know whether another session is about to write, wait and ask.

   The practical consequence: worker sessions that push their branch and open a PR don't merge; the session that does the merge is the writer for that turn. Call that session the "orchestrator" if you like — the role name is shorthand, the mutual-exclusion test above is the load-bearing rule. In a single-session setup where one session authors + dispatches analysis subagents + merges, that session is the only writer by construction and there's no race to manage.

## Day-one workflow for any new work

**Worktree naming convention (this project).** Branch names can use `/` for grouping (`feat/foo`, `fix/bar`, `audit/security-review-2026-04-22`). Worktree paths replace `/` with `-` and live directly under `.claude/worktrees/` — a flat directory tree, not nested. Example:
- branch: `audit/security-review-2026-04-22`
- worktree: `.claude/worktrees/audit-security-review-2026-04-22`

This is a project convention, not a universal rule. The alternative (nested dirs mirroring branch prefixes) works too — the cost is the flattening loses round-trip identification (you can't recover the exact branch name from the worktree path). We accept that because branch names in practice are unique enough and cleanup is simpler. Pick one and stay consistent.

**For worktree creation mechanics** (directory priority, gitignore verification, project setup, baseline tests), see the `superpowers:using-git-worktrees` skill. This doc covers the lifecycle of a worktree; that skill covers its creation.

```bash
# 1. Ensure the root checkout is on main and fresh
cd <repo-root>
git branch --show-current                 # must print 'main'
git fetch origin main
git log --oneline origin/main..main       # should be empty
# If non-empty and you want to keep those commits: push first.
# If non-empty and you don't: this is destructive realignment — see
#   §What NOT to do. Surface the commits to the user and get explicit
#   approval before running: git reset --hard origin/main
git log --oneline main..origin/main       # should be empty; if not, fetch+reset

# 2. Create isolated worktree + branch (ONE command creates both).
#    See the naming-convention paragraph and worktree-creation skill
#    reference directly above this bash block.
git worktree add .claude/worktrees/<name> -b <branch-name>

# 3. Do all work inside the worktree
cd .claude/worktrees/<name>
# ... edit, test, commit with EXPLICIT paths (no 'git add -A', 'git add .', 'git commit -a') ...

# 4. Push the branch and open a PR
git push -u origin <branch-name>
gh pr create --fill   # or full body per project conventions

# 4a. If the PR develops conflicts with main:
#       cd .claude/worktrees/<name>
#       git fetch origin main
#       git rebase origin/main
#       # ... resolve conflicts, git add <paths>, git rebase --continue ...
#       git push --force-with-lease       # NEVER plain --force
#     See §Handling merge conflicts for substantive conflicts, recovery, escalation.
#
# 4b. If CI fails: investigate and fix. Lint / build / test errors are the
#     agent's responsibility, not a classification escalation. Up to 3 attempts
#     on the same failure before escalating. See §Handling CI failures.

# 5. When the PR merges, reclaim everything
cd <repo-root>
git fetch origin main
# This reset is always safe-sync mode: local main never gained commits
# (invariant 2), so we're only advancing the ref to include the merge commit.
git reset --hard origin/main              # bring local main to the post-merge tip
git worktree remove .claude/worktrees/<name>
git branch -D <branch-name>
```

If the PR is closed WITHOUT merging (scope rejected, approach abandoned, duplicate), see §Abandoning a branch for cleanup.

## What NOT to do

- **No `git checkout <branch>` in the root checkout.** Every time this happens, a concurrent agent in the same checkout gets the wrong branch state. Use a worktree.
- **No commits directly to local `main`.** Even for docs. Create a worktree + branch + PR. The single exception is an emergency `git reset --hard origin/main` realignment, which has two modes:
  - **Safe sync** — local `main` has no divergent commits, so the reset just advances the ref to match `origin/main` with nothing to lose. No approval needed.
  - **Destructive realignment** — local `main` has divergent commits that you've decided are not worth keeping. The reset drops them permanently. In this mode you MUST stop, surface the divergent commits to the user (`git log --oneline origin/main..main`), and receive explicit user approval before running the reset.
- **No `git pull` on `main`** — via terminal or VS Code Sync. A diverged local main + remote main produces a merge-of-main-into-main commit. Use `git fetch origin main && git reset --hard origin/main` to realign.
- **No branches living past their PR merge.** Merged-branch-still-exists is where the zoo starts. Delete on merge.
- **No `git add -A`, `git add .`, or `git commit -a`.** All three stage more than you mean to. Explicit paths only. Keeps stale test fixtures, secrets, and cross-agent residue out of commits.
- **No skipping hooks** (`--no-verify`, `--no-gpg-sign`) unless the user has explicitly authorized skipping for this specific operation. If a hook fails, fix the underlying issue — don't bypass it because "the user seemed okay with it last time."

## Recovery from a messy state

When the repo already has a zoo of branches — or when you inherit it:

### Step 1 — Quiesce in-flight work

Don't start cleanup while agents are mid-merge or mid-commit. Wait for them to finish, then audit. Destructive cleanup during in-flight work destroys work.

### Step 2 — Push anything local-only that should survive

```bash
git fetch origin main

# Any commits on local main not on origin/main?
git log --oneline origin/main..main

# If yes and wanted: push them
git push origin main

# If yes and NOT wanted: this is destructive realignment (see §What NOT to do).
# Surface the commits to the user and get explicit approval before:
git reset --hard origin/main
```

### Step 3 — Identify reclaimable branches

```bash
git branch --merged main
```

Every branch listed (except `main` itself) is already fully absorbed into `main`. Safe to delete.

```bash
# Delete each reclaimable branch. -d refuses if not merged (safety).
git branch -d <branch-name>
```

### Step 4 — Triage the remainder

```bash
git branch --no-merged main
```

For each: decide keep (active work, genuine experiment worth preserving) or delete. Stale WIP branches almost always get deleted. Experiments with published results usually can be deleted too — the results are already committed on `main`.

Before deleting an unmerged branch, save a reflog pointer if there's any chance you want the work back:

```bash
# Save a pointer first (optional but cheap insurance)
git branch rescue/<name>-$(date +%Y%m%d) <branch-name>

# Capital -D force-deletes even unmerged branches. This is destructive —
# lowercase -d would refuse. Only use -D after the rescue pointer above
# or after confirming the branch is truly disposable.
git branch -D <branch-name>
```

### Step 5 — Prune worktrees

```bash
git worktree list
git worktree prune                        # removes worktree records for deleted dirs
git worktree remove <path>                # removes a live worktree's files cleanly
```

### Step 6 — Verify clean state

```bash
git branch                                # short list, mostly just main
git worktree list                         # only live worktrees
git log --oneline origin/main..main       # empty
git log --oneline main..origin/main       # empty
git status --short                        # empty, or only files you can explicitly account for (e.g. local scratch dirs you know are yours)
git branch --show-current                 # 'main'
```

## Multi-agent coordination rules

Multi-agent safety has two orthogonal dimensions — **git isolation** (preventing commit interleaving) and **output persistence** (preventing findings from being lost when orchestrator context compacts). Rules for each:

### Git isolation — writes only

- **Every session that WRITES to the tree (commits, pushes) needs its own worktree.** Reads are different — see below. Two concurrent writers in the same worktree produce interleaved edits that cost hours to reconcile.
- **Dispatched writer sessions MUST create a worktree, not reuse the parent checkout.** If your agent framework has an isolation setting (e.g. Claude Code's Agent tool takes `isolation: "worktree"`), enable it. If the framework has no such setting, the dispatch prompt itself must instruct the agent to `git worktree add .claude/worktrees/<name> -b <branch-name>` before doing any work. Without this, the dispatched writer will check out a branch in whatever checkout it was launched from — often the root checkout.
- **Analysis dispatches (read-only, return findings, no commits) do NOT need their own worktree.** They can read from any checkout safely because reads don't conflict. One caveat: an analysis dispatch sees the state of whatever ref it was launched against. To audit an in-flight branch's state, launch the dispatch from that branch's worktree. To audit `origin/main`, launch from the root checkout. Being clear about which ref you're auditing prevents the "I audited the wrong thing" failure mode.
- **Fetch before comparing.** When scripts or agents compare against `main`, always use `origin/main` after `git fetch origin main`. Never the local `main` ref — it can be stale by minutes when another agent just merged.

### Output persistence — analysis dispatches MUST write findings before returning

**The rule:** every dispatched analysis subagent that produces non-trivial output (reports, findings, audits, deep-analysis summaries) MUST write its complete output to a persistent file in the repo BEFORE returning to the orchestrator. The response message exists for consolidation and can be summarized; the file is the canonical record.

**Copy-pasteable dispatch prompt block** (prepend to every dispatch that this rule applies to, substituting `<PERSISTENCE_PATH>` with the specific file path for that subagent):

```
MANDATORY PERSISTENCE. Before returning findings in your response, you MUST
write your complete report to <PERSISTENCE_PATH>. <PERSISTENCE_PATH> is an
ABSOLUTE path — do not interpret it as relative, do not strip any prefix,
do not re-anchor it to your current working directory. Your CWD may not
match the orchestrator's (common case: orchestrator dispatched from a
worktree, you inherited the root checkout's CWD), so only the absolute
path reliably lands the artifact where the orchestrator expects it. The
file is the persistent record; the response message exists for orchestrator
consolidation but must not be the sole record. If you cannot write the
file (tool failure, disk error), STOP and report the failure — do not
proceed with a response-only report. This rule exists because orchestrator
context compacts during long consolidations and lossily reconstructs
in-memory reports — findings get silently dropped when they live only in
response messages.
```

**Substitute `<PERSISTENCE_PATH>` with:** an ABSOLUTE path (not repo-relative). Derive it in the orchestrator's context before crafting the dispatch prompt — the orchestrator knows its worktree root, the subagent may not. Typical derivation:

```bash
# Orchestrator computes absolute path before dispatch:
WORKTREE_ROOT=$(git rev-parse --show-toplevel)
PERSISTENCE_PATH="${WORKTREE_ROOT}/dev/bug-hunts/YYYY-MM-DD-<topic>-<variant>.md"
# Then substitute this absolute value into the dispatch prompt.
```

Shapes to use: `<worktree-root>/dev/bug-hunts/YYYY-MM-DD-<topic>-<variant>.md`, `<worktree-root>/docs/audits/<topic>/<subagent-name>.md`, or similar. The relative forms (`dev/bug-hunts/...`) are what the PATH-under-worktree looks like — but pass the absolute form to the subagent. Known failure mode: a hunter received the relative form, wrote to the root checkout's `dev/bug-hunts/` instead of the worktree's, orchestrator had to recover. `/tmp` is NOT durable across sessions — never use it.

**Why this rule:** the failure mode it prevents is that an orchestrator dispatches several parallel analysis subagents, each returns a large report in its response message, the orchestrator tries to consolidate them while its context approaches compaction, compaction lossily summarizes the reports, and findings silently disappear. The fix is to make the reports durable before the orchestrator has to hold them in memory.

**Orchestrator commits the artifacts wave-by-wave.** Immediately after a parallel dispatch wave returns, commit the persistent files to the campaign branch (see §Campaign branches for why intermediate commits are expected). One commit per wave, e.g. `docs(audit): capture Phase 2 CLI bug-hunt artifacts (3 hunters)`. A mid-consolidation interruption can resume from committed artifacts without reconstructing from orchestrator memory. A resuming session reads its state from: (a) the latest phase-boundary commits on the campaign branch, and (b) the Living Document's current state on the branch (see §Living documents on campaign branches).

**When the rule doesn't apply:** trivial dispatches where the response itself is the entire output (one-line questions, yes/no checks, single-value lookups). If the response could fit in a tweet and losing it wouldn't be expensive to regenerate, no persistent file is needed.

**Cross-cutting discovery hook:** `docs/pitfalls/implementation-pitfalls.md` §Orchestration carries a trigger-and-pointer back to this section for plan authors. Pitfalls is mandated reading during plan-writing (via `writing-plans-enhanced`), so plan authors hit the trigger via their normal workflow and land here for the full rule.

## Campaign branches

**When the pattern applies:** work that spans multiple sessions over days or weeks — audits, multi-phase refactors, security reviews with a Living Document plan, research deliverables with staged phases. Campaigns don't fit the day-sized assumption of Invariant 4's "promptly after merge" rule.

**What's different from short-cycle work:**

- **Branch lifetime is the campaign's lifetime.** The branch exists until the final PR merges. That may be days or weeks. The invariant — *no branches past PR merge* — still holds; the PR just takes longer to be ready.
- **Intermediate commits on the campaign branch are expected, not an anti-pattern.** A campaign accumulates load-bearing artifacts at phase boundaries (e.g. the bug-hunt findings committed in §Output persistence above). Commit each phase's deliverables as they land — a session crashing in phase 5 resumes from the phase-4-committed state, not from orchestrator memory. Intermediate-state commits are cheap; reconstructing from memory is expensive.
- **Rebase onto `origin/main` at phase boundaries, not ad hoc.** During a 2-week campaign, `origin/main` will gain many merges from other work. Rebase the campaign branch onto `origin/main` at each natural phase boundary to keep the campaign's conflict surface small at final-merge time and surface any incompatibility early while campaign context is still fresh. Mechanics: see §Handling merge conflicts.

    **Concrete triggers for a rebase** (any one is enough; whichever fires first):
    1. A numbered phase just completed and its artifacts are committed on the branch.
    2. `git log --oneline origin/main..main` on local `main` is empty and `git log --oneline <campaign-branch>..origin/main` shows 10+ commits of drift — `main` has moved far enough that waiting will hurt more than rebasing now.
    3. You're about to start a new plan section that touches files likely-modified by other in-flight work.
    4. A week has passed since the last rebase of this campaign branch.

    Don't rebase on *every* `origin/main` advance — that's the churn we're avoiding. Don't wait until final merge to discover conflicts either — that's what we're protecting against.
- **If main keeps advancing faster than the campaign progresses** such that you're rebasing every session, the PR's scope is likely too broad — surface to the user to decide whether to split the campaign into two narrower branches.

**Single-writer assumption.** This policy assumes **one session at a time writes to the campaign branch**. Multiple sessions can dispatch analysis subagents against the campaign branch in parallel (see §Multi-agent coordination → Git isolation for the reads-vs-writes split), but only one session commits at a time. Git's default behavior enforces this — `git worktree add <path> <existing-branch>` fails with `fatal: '<branch>' is already checked out` when another worktree has it. (Technically `--force` overrides that check, which is why it's the default-behavior safety net, not an ironclad guarantee.) So the failure mode in practice isn't concurrent-writes-on-one-branch — git's default behavior blocks that — it's someone hitting the `already checked out` error, giving up, and committing to `main` or creating a parallel branch off `main`. If you hit that error, STOP and surface to the user; don't improvise around it with `--force` or a parallel branch.

**Stacked PRs are the escape hatch and are out of scope for this version.** If a campaign genuinely requires parallel writers, the pattern is: each writer has a sub-branch off the campaign branch, sub-branches merge into the campaign branch via PR, campaign branch merges into main via final PR. This works, but the mechanics (rebase ordering, in-flight sub-branches, final-merge bookkeeping) aren't documented here. If you hit this, surface to the user — don't retrofit stacked-PRs without a documented pattern.

**Session-to-session hand-off:** when a campaign spans sessions, the outgoing session commits any in-progress work (even WIP commits, as long as CI would still be green or the commit is marked `wip:` and not the merge head) and updates any Living Document to reflect current state (see §Living documents on campaign branches). The incoming session reads the branch's latest state from committed artifacts — not from the outgoing session's chat history, which it doesn't have.

## Living documents on campaign branches

**What's a Living Document:** a plan file (or equivalent) that the executing session updates as work progresses — marking phases complete, recording discoveries, appending Deviations from the original plan, etc. Authoritative in-flight state lives in this file.

**The producer side — where the authoritative state lives:** during a campaign, the authoritative version of the plan file is the one on the campaign branch. The campaign session reads from it and writes to it every session. Updates committed to the branch are the permanent record.

**The consumer side — where downstream readers should look:** readers of `main` (other agents, other sessions, humans consulting the project's docs directory) see the version of the plan file as of the last merge, which may be days or weeks behind the branch's current state. This is a feature, not a bug — `main` represents merged, reviewed state; in-flight campaigns are explicitly not merged yet.

If a downstream reader needs the current state of a plan file that's under active campaign execution, they have three paths:

```bash
# Option 1: check out the campaign branch in a short-lived read-only worktree
git worktree add -f .claude/worktrees/read-audit audit/security-review-2026-04-22
cd .claude/worktrees/read-audit
cat docs/plans/audit-plan.md
# ...read, then clean up:
cd <repo-root>
git worktree remove .claude/worktrees/read-audit

# Option 2: read the file directly from the branch without a worktree
git show audit/security-review-2026-04-22:docs/plans/audit-plan.md

# Option 3: if there's an open PR, read the PR's version via gh. Two paths:
#   a) The diff of the file as the PR changes it (good for seeing what's changed):
gh pr diff <pr-number> -- docs/plans/audit-plan.md
#   b) The full file content at the PR's head ref (good for reading the whole thing):
gh api "repos/{owner}/{repo}/contents/docs/plans/audit-plan.md?ref=<pr-head-branch>" \
    --jq '.content' | base64 -d
# Note: `gh pr view --json files` returns metadata (paths + diff stats), NOT file
# content — don't use it for reading. Option (a) or (b) is what you want.
```

**Check for in-flight campaigns before relying on main's copy:** `gh pr list --state open --search 'plan <name>'` or similar. If an open PR touches the plan file, consult the branch version; if not, main's copy is the authoritative state.

## Merge authority

Default mode is **auto-merge by the agent**. The user ordered the work, the agent executed it, CI validated it — if none of the Review triggers below apply, the agent merges on green CI. The core goal of this doc is velocity: stop agents from tripping over each other in git, and have them automatically handle anything that doesn't genuinely require the user's judgment. Click-to-approve with no actual review is theatrical trust, not real trust; this policy aims for genuine trust.

### Review triggers — user merges

A PR is `Review` if ANY of these apply:

**Domain triggers** (the code itself is in a sensitive area):

- Authentication / authorization, secrets handling, session management, cryptography, SSRF / injection guards, or other security-sensitive code.
- Data-integrity paths — anything that could corrupt persisted state if wrong.
- Architecture changes — project structure, public interfaces, serialization / wire contracts, database schema, external API contracts that callers depend on.

**Discovery triggers** (the agent's work surfaced something needing judgment):

- `Escalate` classification — the agent hit something requiring the user's judgment. Concrete cases:
    - CI investigation revealed a bigger design issue (see §Handling CI failures).
    - A merge conflict is substantive — not mechanical — and requires deciding which behavior is correct (see §Handling merge conflicts).
    - Scope drift — what was built deviates materially from what was ordered.
    - Any other surprise, ambiguity, or design-level concern encountered during implementation.

If none of the above apply → `Routine`, auto-merge on green CI. When genuinely unsure whether a trigger applies, classify up. But don't reflexively choose Review as hedging — the policy assumes routine merges are routine.

### Auto-merge (the default)

Requirements for a Routine PR to auto-merge:

- Green CI. Skipped checks must be verifiably not-applicable to the changed files (e.g. a frontend check skipped because only backend files changed). Unexplained skips count as failures — investigate per §Handling CI failures; don't classify up as an escape hatch.
- PR title + body accurately describe what was done; scope matches the original ask.
- No dependency on a still-open `Review`-class PR. "Dependency" means: the PR imports, calls, or otherwise depends on code or types introduced by the open PR; the PRs modify overlapping files in ways that would conflict; or the PRs were authored to ship together as one logical change.

Common Routine cases (informational — the Review triggers above are the real definition, not this list):

- Docs updates, test additions, mechanical refactors (renames, formatter output, import reorg).
- Bug fixes in non-sensitive code with green CI. TDD discipline per project conventions (regression test for every fix) is separate from merge authority — follow it because it's good practice, not because it gates the merge.
- Feature implementations from a plan that was adversarially reviewed upstream.
- Dependency version bumps.

### Opening-agent classification

Every PR body must include a `## Merge classification` heading with ONE of:

- `Routine — auto-merge on green CI`
- `Review — <specific trigger>` — e.g. `Review — auth code`, `Review — public API contract change`, `Review — schema migration`. The trigger should reference a Domain trigger from above.
- `Escalate — <specific concern>` — the agent encountered a Discovery trigger. State the concern concretely: what's ambiguous, what surfaced, what judgment is needed.

Missing classification defaults to `Review`.

**Classification pitfalls worth noting:**

- **Hedging to `Review` when `Routine` applies.** The rule says "when genuinely unsure, classify up — but don't reflexively choose Review as hedging." The failure mode: classifying Review because the topic *feels* important, rather than because a specific Domain or Discovery trigger applies. Observed in practice: a docs-only PR editing this very policy doc got opened as Review with justification "policy is important, design-level change." Neither clause matched a Domain trigger (not security-sensitive, not data-integrity, not architecture-as-code-structure) nor a Discovery trigger (no CI investigation, no conflict, no scope drift, no surprise). The correct classification was Routine. The test to apply before invoking Review: *which specific trigger from the Domain or Discovery lists above applies to this PR?* If you can't name one, it's Routine — ship it.

### Self-merge for Routine, user-merge for Review

The opening agent merges their own Routine PR once conditions are satisfied. The agent who did the work has the most context to verify their own PR description, confirm CI went green, and check there's no open Review-class dependency. A separate session would need to rebuild that context from scratch without adding meaningful independence.

For Review-class PRs, the opening agent MUST NOT merge — that's the user's role. Review happens because the user's judgment adds value, not as a rubber stamp.

### Mechanics for auto-merge

**Wait for CI with a dedicated monitoring primitive — not a bash sleep-and-poll loop.** Use your agent framework's event-stream / Monitor tool, `gh pr checks --watch`, or your CI system's webhook / push notification. Event-based waits are cheaper on context tokens and more reliable than polling — a tight `sleep N; check` loop burns context every iteration and still misses fast transitions.

```bash
# ALWAYS --merge. NEVER --squash. NEVER --rebase.
# Full history preserved on main; squash destroys the per-commit trail
# agents and users both rely on for bisecting.
gh pr merge <number> --merge --delete-branch

# Then in the root checkout:
cd <repo-root>
git fetch origin main
git reset --hard origin/main                   # realign local main

# And clean the worktree:
git worktree remove .claude/worktrees/<name>
git branch -D <branch-name>                     # if --delete-branch didn't reach local
```

If your project has a program-status / project-tracking doc, update it when the merge materially changes a track's state (new phase completed, experiment dispatched, etc.). Don't bother for docs-polish merges that don't move the program needle. Skip this step if no such doc exists in your project.

### Handling CI failures

When CI fails on a `Routine` PR, the opening agent investigates and fixes — do NOT surface to the user as a classification escalation unless the investigation genuinely surfaces something needing user judgment. "There's a CI error, please investigate" is exactly what the user would tell the agent anyway; skip the ping and just do it. Fixing CI errors is part of finishing the work, not a separate approval gate.

**Investigation procedure:**

1. **Identify the failure type** from the CI log:
    - Lint / format error → mechanical; fix and push.
    - Build error (type error, missing import, compile error) → usually mechanical; fix and push.
    - Test failure where your change should have kept the test passing → investigate root cause per the systematic-debugging discipline. Did your change break it, or was the test wrong to begin with?
    - Test failure in an unrelated / flaky area → retry once. If it fails again, it's not a flake — investigate.
    - Infrastructure failure (runner down, timeout, network) → retry once; if persistent, surface.
2. **Fix to root cause, not symptom.** If the obvious fix is a workaround that masks a deeper problem (per the standing "never fix symptoms" rule), don't land it — surface instead.
3. **Push the fix as a new commit on the branch.** Do not force-push over history unless the fix is a rebase onto updated `main` (see §Handling merge conflicts).
4. **Wait for CI again** using the monitoring primitive from §Mechanics.
5. **Iterate — up to 3 attempts on the SAME failure.** Fixing one error can legitimately surface another (lint → build error → test failure is a normal sequence when a change ripples); each sequential distinct error is fair game and doesn't count against the limit. But if the SAME failure recurs after 3 fix attempts, escalate — your diagnosis is wrong and looping wastes context.

**When to escalate** (classify `Escalate`, not `Review`):

- The investigation reveals an architectural or design-level issue that needs user judgment (e.g. "the test asserts behavior our new design invalidates — need to decide which is correct").
- You can't find the root cause after 3 attempts at the same failure.
- The "fix" would be a workaround masking a deeper issue.
- CI continues failing in ways your fixes don't address — your mental model of the failure is wrong.

**Do NOT escalate for:**

- Routine lint / format / build fixes — fix them.
- Flaky tests that recover after retry — note in the PR body, move on.
- Infrastructure blips — retry, then move on if stable.
- A sequence of distinct errors where each fix surfaces a new one — that's normal; work through them in order.

The escalation bar is: "does this CI failure surface something the user genuinely needs to know about, OR am I pinging because pinging is easier than investigating?" If the latter, investigate.

### Handling merge conflicts

When the PR develops conflicts with `main` (another PR landed first, touched overlapping files):

**Resolve in the worktree, not the GitHub UI.** The UI resolver is fine for trivial single-line conflicts but produces a merge commit rather than a clean rebase, can't run tests or verify build, and loses the agent's context about what each change was trying to accomplish.

**Mechanical resolution:**

```bash
cd .claude/worktrees/<name>
git fetch origin main
git rebase origin/main

# For each conflicting file:
#   1. Read both sides carefully.
#   2. Understand what each side was trying to accomplish.
#   3. Produce the correct combined result (usually not just pick-one-side).
#   4. git add <path>
# Then:
git rebase --continue   # repeat until the rebase completes

# Once rebase is clean and tests pass locally:
git push --force-with-lease   # NEVER plain --force. See note below.
```

**Why rebase, not merge-main-into-branch:** Rebasing keeps the PR's commits linear on top of `main`. Merging `main` into the branch produces tangled history that's harder to bisect and makes it unclear which commits are "yours" vs. "upstream."

**Why `--force-with-lease`, not `--force`:** `--force-with-lease` refuses to overwrite remote changes you didn't see locally. If another agent pushed to the same branch between your fetch and push (rare but possible in multi-agent setups), `--force` silently clobbers their commit; `--force-with-lease` rejects the push and forces you to reconcile. The rule: never downgrade to `--force` just because `--force-with-lease` rejected something — the rejection is the point.

**If the rebase goes wrong:**

```bash
git rebase --abort                      # Back to pre-rebase state.
# Or, if --abort doesn't recover cleanly:
git reset --hard <pre-rebase-sha>       # Find <pre-rebase-sha> in git reflog.
```

**When to escalate** (classify `Escalate`):

- The conflict is **substantive** — the two changes represent incompatible design decisions, and resolving requires a judgment about which behavior is correct. Don't silently pick one; surface the tradeoff.
- The rebase produces a state you can't cleanly recover from (repeatedly gets tangled, can't abort, reflog doesn't save you).
- You find yourself rebasing repeatedly because `main` keeps advancing — possible sign the PR's scope is too broad; surface for the user to decide whether to split it. (For campaign branches, rebase cadence is scheduled at phase boundaries — see §Campaign branches.)
- The conflict involves code that falls under a Domain review trigger (auth, data-integrity, architecture) — reclassify the whole PR as `Review` regardless of whether the mechanical resolution is easy.

**Multi-agent race — only one wins at merge time:**

Two PRs can't both cleanly merge if they touched overlapping files — the second PR through merge hits conflicts. To reduce wasted cycles:

- Before starting work that might conflict with an in-flight PR, check: `gh pr list --state open`.
- If you're about to touch the same files as an open Review PR, consider waiting for it to merge first (then rebase your branch) rather than racing.
- When the race is unavoidable (parallel work on related files), the losing PR's agent handles the rebase — that's their cost for being second, not the leading PR's problem.

## Abandoning a branch

When a PR is closed WITHOUT merging — scope was rejected, approach abandoned, duplicate of another PR that landed first — clean up the same way you would after a merge, minus the reset (local `main` hasn't moved).

**Default path: stash first, then remove.** This is cheap insurance against two failure modes: (1) tracked-but-uncommitted work in the worktree, and (2) "I thought I committed this but didn't" — the one that eats real work. Stashing makes the uncommitted state recoverable from `git stash list` for weeks; `--force` makes it gone forever. Err on the side of stashing.

```bash
cd <repo-root>

# 1. Inspect uncommitted state before touching anything:
git -C .claude/worktrees/<name> status --short

# 2. Stash whatever is there (no-op if clean — safe to run unconditionally):
git -C .claude/worktrees/<name> stash push -u \
    -m "rescue-from-<branch-name>-$(date +%Y%m%d)"
#    -u includes untracked files. The rescue label makes it findable later.
#    If the stash fails because the tree is truly clean, that's fine.

# 3. Now remove the worktree, delete the branch:
git worktree remove .claude/worktrees/<name>
git branch -D <branch-name>                  # -D since unmerged
git push origin --delete <branch-name>       # optional: remove remote ref
```

**If `git worktree remove` still refuses** (e.g. filesystem lock, untracked-file mode issues), *do not* reflexively escalate to `--force`. Re-check with `git -C .claude/worktrees/<name> status --short` and investigate the specific blocker. `--force` is a last resort after confirming the stash captured what you care about — by that point the stash is your safety net, not the status check.

**Recovering stashed work later:**

```bash
git stash list | grep rescue-from-<branch-name>
git stash apply <stash-ref>     # applies without removing from stash
git stash pop <stash-ref>       # applies and removes
```

**Stashes survive worktree removal and branch deletion.** Stashes live in the main repo's `refs/stash` ref, not in the worktree's directory or on the deleted branch. `git worktree remove` and `git branch -D` have no effect on `refs/stash`. You can stash from inside the worktree, remove the worktree, delete the branch, and the stash is still listed in `git stash list` in the main checkout — from any branch. No need to worry about losing the stash by running the cleanup steps above.

## Red flags (stop and diagnose)

- `git status` at session start shows unexpected untracked files → another agent left in-flight work here. Investigate before touching.
- `git branch --show-current` returns anything other than `main` in the root checkout → checkout roulette occurred. Figure out who did it before switching back.
- `git log --oneline origin/main..main` non-empty → local main is ahead and unpushed. Push it, or figure out why.
- `git log --oneline main..origin/main` non-empty → local main is behind. `git fetch && git reset --hard origin/main`.
- Local branch count materially higher than your in-flight-work count (e.g. 5+ branches but only 1-2 active worktrees) → zoo is regrowing; run the Recovery steps.
- Your worktree directory (by default `.claude/worktrees/`) contains more subdirectories than `git worktree list` shows → abandoned worktree state; `git worktree prune`.
- An analysis dispatch returned a large report ONLY in its response, with no persistent file written → violation of §Multi-agent coordination output-persistence rule. Re-dispatch with an explicit persistence requirement in the prompt, or recover the report from the response and write it yourself before proceeding to consolidation.
- An analysis dispatch's persistence artifact landed in the root checkout instead of the worktree (or any other wrong location) → the dispatch received a relative `<PERSISTENCE_PATH>` and the subagent's CWD didn't match the orchestrator's. Move the file to the correct worktree location, commit there, and re-craft future dispatch prompts with absolute paths derived from `git rev-parse --show-toplevel` in the orchestrator's context.

## Rationale (failure-mode table)

Each rule addresses a specific observed failure:

| Rule | Failure prevented |
|---|---|
| Root checkout stays on `main` | Checkout roulette: two agents in same checkout, one switches branches, the other commits to the wrong branch |
| Work in isolated worktrees | Concurrent edits to shared checkout producing interleaved commit histories |
| Branches ephemeral | Branch zoo — dozens of branches, agents confused about which is current, fresh agents burn turns orienting |
| Push after every merge | Local `main` diverging from `origin/main` during wave-boundary merges; three-way divergence requiring manual reconciliation |
| One writer to local main at a time | Concurrent merges by different sessions into local main produce unreconciled state at wave boundaries |
| No `git checkout` in root checkout | Handoff commits left dangling-unreachable after resets, nearly lost to gc |
| No `git add -A` / `.` / `-a` | Secrets, unrelated fixtures, and cross-agent residue accidentally committed |
| Analysis dispatches persist findings before returning | Orchestrator context compacts mid-consolidation, lossily reconstructs reports from memory, findings silently dropped |
| Persistence paths are absolute, not relative | Subagent CWD may not match orchestrator's (e.g. root checkout vs worktree); relative paths produce artifacts in the wrong location, often undetected until consolidation realizes files are missing from expected path |
| Campaign branches rebase at phase boundaries | Conflict-surface at final-merge time too large; incompatibility surfaces late when original context is gone |
| Abandon-branch cleanup stashes uncommitted state | Work silently lost via `--force` on worktrees with uncommitted or forgotten changes — especially "I thought I committed this" cases |

### Observed incidents

Concrete examples that motivated the rules above. Included as social proof so future agents considering a shortcut can see the specific failure mode the rule prevents.

**Reset on main wipes uncommitted edits (worktree discipline).** An agent edited files (docs updates plus new skill authoring) directly on the root checkout's primary branch instead of creating a worktree. Mid-session, a separate agent's PR merged upstream and something ran `git fetch origin <primary-branch> && git reset --hard origin/<primary-branch>` against local `<primary-branch>` to realign. `git reset --hard` wiped the working tree of tracked-file modifications — the first agent's edits disappeared. Untracked files (newly-created files not yet `git add`-ed) survived.

- **Recovery.** The agent replayed the edits from conversation context into a freshly-created worktree branched off current `origin/<primary-branch>`. Cost: roughly 15–20 minutes of replay plus one close call — had conversation context compacted before replay, the edits would have been unrecoverable.
- **Root cause.** Writing tracked changes on the root checkout's primary branch violated Invariant 1 ("Root checkout stays on the primary branch, but write work does NOT happen there"). The reset that caused the loss was itself correct behavior — local `<primary-branch>` had legitimately drifted behind `origin/<primary-branch>`; realigning it via `reset --hard` is exactly the sanctioned recovery path. The problem was having uncommitted tracked changes present at that moment, not the reset.
- **Prevention.** Start every write session with `git worktree add .claude/worktrees/<slug> -b <branch-name>`. The worktree's working tree is insulated from resets or pulls that target the root checkout. The "untracked files survive" quirk of `git reset --hard` is an accident of its scope, not a design to rely on — worktrees provide actual isolation.

## Exceptions

- **Emergency realignment** of local `main` via `git reset --hard origin/main`. Two modes (see §What NOT to do for full detail): *safe sync* when local `main` has no divergent commits (no approval needed); *destructive realignment* when it does and you're dropping them (requires explicit user approval). Either way, a reset is not a commit and does not violate "no commits to local main."
- **Rescue branches** created via `git branch rescue/<name> <sha>` before destructive operations. These are safety pointers, not work branches. Clean up when the rescue is no longer needed.
- **User-directed overrides.** Any rule can be waived for a specific operation if the user says so explicitly. The invariants resume as soon as the override is complete.
