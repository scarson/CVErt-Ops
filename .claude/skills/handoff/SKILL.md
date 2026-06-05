---
name: handoff
description: Use when context is about to be lost — approaching auto-compaction, ending a long session, wrapping a multi-agent coordination cycle, before dispatching a follow-up agent who won't share hot context, or when the user asks for a "handoff" / "checkpoint" / "where are we" / "session summary" / "what's left".
---

# Handoff

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

## Overview

Context built during a substantial work session costs hours of agent time to reconstruct; writing it down costs minutes. A handoff is the act of capturing that context into durable artifacts BEFORE it evaporates — compaction, session end, fresh-agent dispatch, whatever triggers the loss.

**Core principles (two asymmetries):**

1. **Cheap to document, expensive-to-impossible to reconstruct.** Hot context is a non-renewable resource. Anything worth putting in a status report to the user is worth putting in a durable artifact first — a handoff doc, a living plan, a coordination log, a pitfalls entry, an outstanding-items doc. The status report to the user is ephemeral; the artifact is persistent. Write the artifact; let the status report reference it.

2. **Review is cheap, mistakes in handoffs are expensive.** A review round that finds nothing costs ~10 minutes of agent time. A handoff that ships with an undocumented seam, a stale plan banner, or a missing follow-up can cost downstream readers 30+ minutes each to reconstruct, multiplied across every future dispatch that touches the gap. The asymmetry favors more review, not less. Err on the side of an extra round when any doubt exists.

## When to use

- Session is approaching auto-compaction (high context usage)
- Ending any session that produced non-trivial state (decisions, discoveries, in-flight work)
- Wrapping a multi-agent coordination cycle — plans shipped, PRs opened, follow-ups queued
- Before dispatching a follow-up agent whose context will not include yours
- Human partner asks for a "handoff", "checkpoint", "where are we", "session summary", "what's left"
- Noticing that state is split across status reports, PR notes, and the session transcript but not fully in any one durable place

## Core discipline

A handoff MUST do five things. Skipping any one degrades the handoff into a status report.

1. **Mine hot context at lossless detail.** The handoff author MUST make multiple passes through the session's recent work, explicitly fighting recency bias. Mid-session decisions, seams in half-shipped work, and "little follow-up to-dos" are the items that get lost — the items a status report would skim but a future agent will need.

2. **Update every living artifact that is now stale.** Plans, design docs, coord logs, outstanding-items, pitfalls, skill files — any file that described state accurately BEFORE the session and no longer does MUST be updated to match reality. State MUST NOT live only in PR notes or status reports.

3. **Create artifacts that don't exist yet but should.** A new followups doc, a new pitfall entry, a new design-decision record, a new parked-ideas entry — if the session produced durable material that no existing artifact covers, the handoff author MUST create the artifact rather than leaving the material in the handoff doc alone.

4. **Identify seams.** Anywhere two pieces of work meet — a PR that was merged while another was rebasing, a deferred task whose upstream just shipped, a merge race between concurrent branches — MUST be explicitly documented. Seams are where context is silently lost between agents.

5. **Run a minimum of 6 rounds of adversarial review on the handoff itself.** Five canonical perspectives plus at least one session-specific perspective the agent chooses based on what actually happened this session. Additional rounds are welcome. See §Adversarial review below. One-pass handoffs miss seams; multi-pass review from multiple perspectives catches them.

## Process

### Phase 1: Mine hot context

Multiple explicit passes. Do not rely on a single scan.

**Pass 1 — Recent decisions.** What decisions were made in the last hour of this session? Who made them, what was the rationale, what alternatives were considered?

**Pass 2 — Mid-session (combat recency bias).** Scroll further back. What decisions were made 2-6 hours ago that haven't been referenced recently? These are the ones most likely to be lost.

**Pass 3 — Little follow-up to-dos.** "Oh, and I should also..." items. "Worth capturing as a pitfall later." "Defer to a follow-up cycle." If you can remember saying it but don't see it in a committed artifact, it's a candidate.

**Pass 4 — Seams between work units.** Where did one track hand off to another? Where did a merge race happen? Where did a gate open or close? Where did an agent's assumption turn out wrong?

**Pass 5 — What a naive agent would need.** Read your own state from the perspective of a fresh agent who has none of your context. What glossary terms do they need? What file paths? What status at what commit? What's the next logical action and why?

Each pass SHOULD produce items. If a pass produces zero, you aren't looking hard enough — scan again with a different lens.

### Phase 2: Route to artifacts (not just the handoff doc)

Everything mined in Phase 1 goes somewhere durable. The handoff doc is ONE destination, not the only one. Route each item:

| Kind of content | Goes to |
|---|---|
| State that updates an existing plan (phase shipped, deferred, scope edited) | Plan's per-phase Execution Status banners + top-of-plan summary |
| Cross-agent coordination state (what shipped, merge SHAs, who owns what) | Project's coordination log (CHANGELOG, a dedicated coord-log doc, a section of a status doc — whatever the project uses) |
| Speculative thinking worth preserving but not committing to | Project's parked-ideas or backlog location |
| Newly-learned traps (implementation or testing pitfalls) | Project's known-issues / pitfalls / gotchas doc |
| Methodology insights worth codifying | Skill files (or a queue of skill-update candidates) |
| Everything else — session arc, priority queue, in-flight state, next actions | The handoff doc itself |

Routing correctly keeps the handoff doc focused. A handoff doc that duplicates content living in the plan is noise; a handoff doc that POINTS at the plan and summarizes status is signal.

### Phase 3: Write

Write in this order:

1. Update living artifacts first (plans, coord log, outstanding-items, pitfalls).
2. Create any new artifacts identified in Phase 2.
3. Write the handoff doc LAST, referencing the updated artifacts rather than duplicating their content.

The handoff doc structure SHOULD include:

- **Headline state** — branch, tip SHA, pushed?, worktrees live, PRs open
- **What shipped this session** — concrete artifact pointers, not narrative
- **In-flight work** — what's running, where, under whose ownership
- **Ready-to-dispatch** — queued work with prerequisites and where the prerequisites land
- **Not yet started** — items that have been scoped but not worked
- **Deferred items** — each with a semantic description of what needs to happen before the item is pickable + a link to the likely-unblocker artifact (its plan page, its task, its PR — whichever is authoritative per the project's Living Document Contract conventions). Prose condition + link is durable across paraphrases and scope edits; exact-string coordination across multiple agents is not.
- **Operational guardrails accumulated this session** — so a fresh agent doesn't re-discover them
- **Priority queue** — numbered, with dependencies
- **Continuation prompt** — paste-ready prompt for a fresh agent resuming the work

### Phase 4: Adversarial review (minimum 6 rounds)

A single-pass handoff author has blind spots the author cannot see. Five canonical perspectives plus one session-specific perspective find them.

Run these rounds sequentially, documenting findings at each:

**Round 1 — Naive fresh agent.** Would someone starting from zero context understand what to do? Where are the undefined jargon terms, assumed-context references, or missing glossary entries? Fix every instance.

**Round 2 — Recency-bias audit.** Re-read with the assumption that recent items are over-represented. What mid-session items are under-documented? What hot-context decisions haven't made it into the handoff? Add them.

**Round 3 — Seam auditor.** Where do two work units meet? Is the meeting point documented clearly enough that neither side's fresh-agent successor will be surprised? Look at: merge races, upstream-shipped-downstream-still-waiting transitions, cross-agent coord-log entries, rebases that absorbed changes from other branches, deferred-work references that depend on another agent's progress.

**Round 4 — Operational guardrails auditor.** What operational rules did this session establish or reinforce? Commit discipline, branch rules, merge patterns, dispatch conventions. Are they in a durable place (CLAUDE.md, skill files, pitfalls) or did they only live in the session transcript? If the latter, persist them.

**Round 5 — Loss-averse auditor.** What would a loss of hot context destroy that the handoff doesn't yet capture? What "oh by the way" items are still only in the transcript? Scan explicitly for the phrase "worth capturing later" or similar in-session markers.

**Round 6 — Session-specific perspective (agent-chosen).** The canonical rounds 1-5 cover known-in-general failure modes. This session has its own character — security-heavy, perf-critical, cross-platform, methodology-novel, tooling-pioneering, something else — and that character has its own failure modes the canonical rounds won't catch. The agent MUST choose a perspective specifically relevant to what actually happened this session and review from it.

Requirements for the Round 6 perspective choice:

- MUST be a perspective not already covered by rounds 1-5. Don't repeat "seam auditor" with a different label.
- MUST be specifically relevant to THIS session — grounded in the session's content, not a generic auditor template. If the session shipped auth code, "security auditor" is legitimate; if the session was pure docs, it isn't.
- MUST be named and described explicitly in the handoff under a heading like `### Round 6 — [chosen perspective] — [N findings applied]` so future readers can see the reasoning.
- SHOULD be concrete enough to produce findings. "General quality pass" is too vague; "cross-platform failure modes I haven't tested on Linux yet" is actionable.

If the agent genuinely cannot identify a session-specific perspective after trying, that itself is a finding — document "Round 6: no session-specific perspective identified; session content matches canonical rounds 1-5 adequately" with a one-sentence justification. Rare; default to finding one.

**Additional rounds (7+) — encouraged by default.** 6 is the floor, not a ceiling. If the agent identifies any additional perspective that might catch issues rounds 1-6 didn't, the agent MAY (and often SHOULD) run further rounds. Review is cheap; a handoff mistake ships downstream reconstruction cost that compounds. Err toward an extra round.

Rules for additional rounds:

- Each additional round MUST be named + described explicitly like Round 6 — a stated lens that does work. The lens MAY be high-level (e.g., "read top-to-bottom with fresh eyes for overall coherence and framing") if the canonical rounds focused on specific angles and a holistic pass might catch structural issues. What makes a round legitimate is a stated lens, not a specific level of abstraction.
- Rounds MUST NOT be re-labeled duplicates of rounds already run. A Round 7 that's actually Round 3 with a different name doesn't count. Non-redundancy is the bar.

Sessions that often reward extra rounds beyond the floor: multi-stream or multi-agent coordination cycles, security-sensitive work, technically complex work that crosses multiple layers or runtimes, handoffs into an agent that will operate with significantly reduced tooling or permissions than the current session, or any session where the agent has a nagging sense that something's still off.

**Loop rule (applies to ALL rounds — canonical + additional).** If any round produces material findings, the agent MUST re-run every round in sequence after applying fixes. Fixes can surface issues that earlier rounds missed, or introduce new issues those rounds would have caught. Exit only when a full pass through every round (1-6 canonical + any additional ones the agent elected to run) produces zero material findings. The cost of an extra clean-pass sweep is cheap; the cost of a handoff shipped with a silently-broken invariant is expensive.

## Red flags (STOP)

These mean the handoff is not yet complete:

- "The PR notes cover it" — PR notes disappear from context for anyone not looking at that specific PR. Move it to the handoff or plan.
- "I'll add it if someone asks" — They won't ask; they'll reconstruct wrong.
- "The commit messages have it" — Commit messages rot into archaeology. Not a substitute.
- "The user already saw this in chat" — User context is also ephemeral. Not a substitute.
- "The plan is accurate enough" — Run the per-phase banner check. If any phase shipped or deferred without its banner being updated, the plan is not accurate enough.
- "Only the headlines matter" — The "little follow-up to-dos" are precisely what gets lost. Headlines aren't enough.
- "One pass is fine" — Single-pass handoffs miss seams. Run 6 rounds including the session-specific one.
- "The canonical rounds covered everything" — They cover known-in-general failure modes, not this session's specific character. Round 6 exists because sessions differ.
- "I'll capture it at the end" — By the end you've forgotten the mid-session discoveries. Capture as you go or re-mine hot context in Phase 1.

## Common rationalizations (rebuttals)

| Rationalization | Reality |
|---|---|
| "The handoff is getting long" | Length is not the problem; missing content is. A handoff that captures everything beats one that loses a deferral condition or coordination seam, regardless of line count. Multi-hour sessions routinely produce handoffs well over 1,000 lines — that's fine when each line is earning its place. Trim only when content is redundant, never because the doc "feels big." |
| "This is my final session anyway" | Other agents read handoffs too. And future-you is a different agent. |
| "I'll just tell the next agent verbally" | You won't be there. The next agent will start cold. |
| "Review rounds slow me down" | They do. They also catch seams that cost hours to reconstruct later. ~10 min of review beats 30+ min of downstream archaeology — the asymmetry is ~3x and compounds. |
| "Status report to the user IS the handoff" | No. The user's chat context is ephemeral. Durable artifacts are the handoff. Status report references them. |
| "I already updated the plan" | Did you update ALL the plans that this session touched? Coord log? Outstanding-items? Pitfalls? Usually at least one is missed. |

## Checklist

Before declaring the handoff complete, verify:

- [ ] Phase 1 mining pass produced items at each of the 5 lenses (recent, mid-session, little follow-ups, seams, naive-agent)
- [ ] Every living artifact this session touched has been updated to match current reality
- [ ] Any new durable artifact that should exist (but didn't) has been created
- [ ] Each deferred item has a prose description of its unblock condition + a link to the likely-unblocker artifact (plan, task, PR). No exact-string gate-key coordination — semantic description + live link is resilient to paraphrase and scope change; exact strings break on either.
- [ ] The handoff doc points at updated artifacts rather than duplicating their content
- [ ] The continuation prompt is paste-ready and self-contained
- [ ] At least 6 adversarial review rounds complete (5 canonical + at least 1 agent-chosen session-specific; additional session-specific rounds run as judgment suggested); the final full pass through every round run produced zero material findings
- [ ] Every session-specific round (Round 6 and any 7+ the agent elected to run) is documented by name in the handoff with its findings count; perspective choices are specific to this session's content, not generic templates or re-labels of canonical rounds
- [ ] The handoff is committed to a durable location (not just a chat message)

## Social proof

Observed across multi-session coordination cycles: handoffs written with per-phase plan banners + deferred-item prose conditions + route-to-the-right-artifact discipline reduce downstream dispatch prompts from lengthy "figure out what's done" archaeology sessions to short pointers ("see plan.md Phase N banner — upstream condition now holds — execute"). The cost asymmetry favors upstream documentation heavily and compounds across every subsequent dispatch that consumes the handoff.

Handoffs written without that discipline create the opposite: state scattered across PR notes, commit messages, and session transcripts, with each downstream agent paying the reconstruction cost anew. The compounding works both directions.

## Related conventions

- **Plan banner format.** When Phase 2 routing updates a plan that follows a Living Document Contract (per-phase ✅/🚧/⏸/⬜ Execution Status banners plus a top-of-plan summary table), the handoff author MUST preserve that format when writing new banner content. If the project uses `/writing-plans-enhanced` or an equivalent convention for plan structure, that convention governs the shape of plan updates made during handoff; this skill does not redefine it.

- **Canonical coordination log.** Each project SHOULD designate ONE location for cross-agent coordination state (CHANGELOG, a dedicated coord-log doc, a section of a status doc — whatever the project uses). Phase 2 routing sends cross-agent state there. Handoffs that route to whichever location is canonical for the project stay greppable; handoffs that invent new locations fragment the record.

## The bottom line

The handoff is the session's proof of work for the next agent. Hot context costs hours to build and minutes to preserve. Mine lossy, route everywhere it belongs, update what's stale, review adversarially, and commit.

If a future agent reconstructs state you already knew, the handoff failed. If they resume in 2 minutes instead of 30, it succeeded.
