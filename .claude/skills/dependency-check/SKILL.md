---
name: dependency-check
description: Verify the maintenance status, security posture, and supply chain risk of a third-party dependency before adding it to the project. Use when proposing any new dependency, evaluating alternatives, or writing implementation plans that specify libraries.
argument-hint: "[library name or import path, e.g. 'gopkg.in/yaml.v3' or 'tidwall/gjson']"
---

# Dependency Check

Verifying supply chain risk for: **$ARGUMENTS**

---

## Why this exists

Claude's training data has a hard knowledge cutoff. Libraries can be archived, deprecated, forked, or compromised after that date. This project is a security product — we cannot ship unmaintained dependencies. Web search is the only reliable way to verify current status.

---

## Steps

**1. Identify the dependency**

Confirm the exact import path / module name. If the user gave a short name (e.g., "yaml library for Go"), identify the specific module before proceeding.

**2. Web search for current status**

Search for the library using multiple queries to get a complete picture. At minimum:

- `"<library name>" archived OR unmaintained OR deprecated`
- `"<library name>" fork OR migration OR successor`
- `"<library name>" CVE OR vulnerability OR advisory`
- Visit the GitHub/GitLab repository page directly if possible

**3. Evaluate against checklist**

For each item: **✅ OK**, **⚠️ WARNING**, or **❌ FAIL**.

| Check | Criteria |
|-------|----------|
| **Repository status** | Not archived, not marked unmaintained/deprecated on GitHub/GitLab |
| **Last commit** | Within the last 12 months (⚠️ if 12-24 months, ❌ if >24 months) |
| **Last release** | Within the last 18 months (⚠️ if 18-36 months, ❌ if >36 months) |
| **Open issues / PRs** | Maintainer is responsive — not hundreds of unanswered issues with no triage |
| **Known vulnerabilities** | No unpatched CVEs or security advisories in the version we'd use |
| **Canonical location** | Import path is the current canonical home (not a stale mirror or pre-fork path) |
| **License** | Compatible with project license (MIT/Apache-2.0/BSD preferred) |
| **Transitive deps** | Not pulling in a large or risky dependency tree |
| **Go module status** | Listed on pkg.go.dev with recent versions (for Go libraries) |

**4. Check for alternatives**

If any ❌ or ⚠️ items are found, briefly search for actively maintained alternatives that serve the same purpose.

**5. Produce verdict**

---

## Output Format

```
## Dependency: <import path>
## Version: <version or "latest">
## Checked: <date>

### Status
| Check               | Result | Notes |
|---------------------|--------|-------|
| Repository status   | ✅/⚠️/❌ | ... |
| Last commit         | ✅/⚠️/❌ | ... |
| Last release        | ✅/⚠️/❌ | ... |
| Open issues / PRs   | ✅/⚠️/❌ | ... |
| Known vulnerabilities | ✅/⚠️/❌ | ... |
| Canonical location  | ✅/⚠️/❌ | ... |
| License             | ✅/⚠️/❌ | ... |
| Transitive deps     | ✅/⚠️/❌ | ... |
| Go module status    | ✅/⚠️/❌ | ... |

### Verdict: APPROVED / NEEDS DISCUSSION / REJECTED
<1-2 sentence summary>

### Alternatives (if any ⚠️ or ❌)
- <alternative 1> — <why it's better/worse>
- <alternative 2> — <why it's better/worse>
```

---

## Rules

- **NEVER** skip the web search. Your training data is not sufficient for this check.
- If web search is unavailable or inconclusive, the verdict MUST be **NEEDS DISCUSSION** — never APPROVED without verification.
- For dependencies already in `go.mod`, this skill can be used to audit them — just note "already in use" in the output.
- When checking dependencies for an implementation plan, run this for each new dependency the plan introduces.
