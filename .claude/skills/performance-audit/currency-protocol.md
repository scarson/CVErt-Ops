# Currency Protocol (anti-stale-training)

**Load this when:** running Phase 1 of `performance-audit` — building or reusing the version-specific
performance guidance ("currency brief") for a detected framework.

## Contents
- Why this exists
- The version-aware refresh logic
- Registry commands per ecosystem
- Cache file location + format
- Offline / failure degrade

---

## Why this exists

LLM training data ages. Two failure modes this protocol counters:

- **(a) Old-fast-now-slow** — recommending a pattern that was fast in an older framework version but
  regressed or was deprecated in a newer one.
- **(b) Missed new fast-path** — not knowing about a performance API/feature/default added after the
  bulk of training data.

The brief is a small, sourced, **repo-local** cache of version-specific performance facts that
the `idiom-currency` lane (framework-idiom currency) consults. It lives in the *target repo*, not the plugin, so plugin
updates never wipe it and a team accrues + shares it via git.

## The version-aware refresh logic

The expensive operation is *researching* perf implications; the cheap operations are *consulting the
shipped version index* and *asking the registry what the latest version is*. The protocol exploits
that asymmetry — it does not use a flat calendar TTL as the primary trigger, and it does not
re-research a whole version history at runtime when a build-once index already covers it.

0. **Shipped version index first (no network).** If `version-indexes/<ecosystem>.md` exists (see
   `version-indexes/README.md`), it is the primary source of version-specific perf knowledge up to its
   `covered_through` version — consult it before any network call. Live research (steps 1–4) then only
   needs to **extend past `covered_through`** (or runs in full only when no index exists for the
   ecosystem). This keeps the expensive version-history mining a build-once cost, not a per-run one.

1. **Cheap currency check (1-day TTL), best-effort.** For each detected framework, make one registry
   call for the latest published version (table below) and record `latest_available`. If the
   registry is unreachable or the tool isn't installed, the check **fails soft**: fall through to the
   cached brief if one exists (flag it possibly-stale) and otherwise to offline-degrade. The check
   MUST NOT block or fail the audit.

2. **Cache lookup** at `docs/perf-audits/cache/<ecosystem>/<framework>@<major.minor>.md`.

3. **Reuse the cached brief** if **all** hold:
   - the in-use version still matches the brief's `researched_against_version`, AND
   - `latest_available` is **not greater than** the brief's `researched_against_version`, AND
   - the long fallback TTL (`fallback_ttl_days`, default 180) has **not** elapsed since `researched_on`.

4. **Otherwise refresh** (live research, scoped to the gap past the shipped index's `covered_through`):
   `WebSearch`/`WebFetch` for the framework + version's recent
   performance release notes, changelogs, deprecations, and performance guides. Extract: superseded
   patterns (old→new), new fast-path APIs (+ the version that introduced them), changed defaults, and
   known perf regressions/fixes by version. Rewrite the cache file (with sources). The brief covers
   the **in-use** version's characteristics *and* notes fast-paths a newer version would unlock (feeds
   upgrade-opportunity findings).

5. **Offline / no-network degrade.** Emit "currency brief unavailable (offline)". `idiom-currency` findings are
   flagged **LOW confidence** and marked for manual currency check. **Never fabricate** version-specific
   claims — absence of a brief is stated, not papered over.

The consolidated audit report MUST record which brief (and its `researched_on` date) it used, so a
finding derived from a possibly-stale brief can be re-checked.

## Registry commands per ecosystem

| Ecosystem | Latest-version check (best-effort) |
|---|---|
| npm (Node/JS/TS) | `npm view <pkg> version` |
| PyPI (Python) | `pip index versions <pkg>` (or `pip install <pkg>==` and read the error) |
| NuGet (.NET) | `dotnet package search <pkg> --exact-match` or query `api.nuget.org` |
| Go modules | `go list -m -versions <module>` |
| crates.io (Rust) | `cargo search <crate>` or query `crates.io/api/v1/crates/<crate>` |
| Maven Central (JVM) | query `search.maven.org/solrsearch/select?q=...` |
| Swift | toolchain/language version drives most perf currency — check `swift --version` locally and swift.org releases; per-package versions are git tags (no central registry version command — `swift package` resolves from git; Swift Package Index for discovery) |

These require network + the tool installed. All are best-effort per step 1. For Swift, the *language/toolchain* version (not a package registry) is the primary currency axis — the version index is keyed on Swift releases.

## Cache file format

Path: `docs/perf-audits/cache/<ecosystem>/<framework>@<major.minor>.md`

```markdown
---
schema_version: 1
framework: <name>
ecosystem: <npm|pypi|nuget|go|crates|maven>
researched_against_version: <x.y.z in use at research time>
latest_known_at_research: <x.y.z latest available at research time>
researched_on: <YYYY-MM-DD>
fallback_ttl_days: 180
sources:
  - <url>
  - <url>
---

## Superseded patterns (old → new)
- <pattern that regressed/deprecated> → <current recommended pattern> (changed in <version>)

## New fast-path APIs (and the version that introduced them)
- <API/feature> — introduced <version> — <what it speeds up>

## Changed defaults
- <setting> default changed in <version>: <old> → <new> — <perf implication>

## Known perf regressions / fixes by version
- <version>: <regression or fix> — <impact>
```

`schema_version` lets the format evolve without misreading old caches; bump it if the structure changes.
