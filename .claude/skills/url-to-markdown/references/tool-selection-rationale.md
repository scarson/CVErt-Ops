# Tool selection rationale

This document records why the skill uses the specific tool stack it does, what alternatives were considered, and what to watch for when revisiting these choices later.

## Summary

| Layer            | Choice               | Alternatives rejected                                    |
| ---------------- | -------------------- | -------------------------------------------------------- |
| Extractor        | trafilatura 2.0+     | readability-cli, newspaper3k, goose3, roll-my-own parser |
| HTTP fetcher     | curl_cffi            | requests, httpx, aiohttp, stdlib urllib                  |
| Browser cookies  | browser_cookie3      | manual cookie file, pycookiecheat, playwright profile    |
| SSRF guard       | stdlib `ipaddress` + custom 80-line validator | safeurl-py, rolling into urllib, ssrf-protect middleware |
| Env management   | Cascade: uv → venv   | Require uv only, require pipx, bundle deps               |
| Runtime          | Python 3.12+         | Node+readability, Go binary, pure Rust                  |

## Extractor: why trafilatura

**What it does:** Extracts the main article body from an HTML page, strips navigation/ads/sidebars, and returns structured markdown plus metadata. Handles the JSON-LD → microdata → OpenGraph → Twitter Card → `<meta>` fallback chain for metadata.

**Why it wins:**

1. **Academic benchmark leader.** ScrapingHub's article-extraction benchmark and multiple 2023-2024 papers consistently place trafilatura at the top for precision and recall on news/blog articles. Not marginal — it beats newspaper3k by ~15% F1 on noisy pages.

2. **Native markdown output.** `output_format='markdown' with_metadata=True include_links=True include_formatting=True` returns a complete markdown file with YAML frontmatter already emitted. No second conversion step (unlike Mozilla Readability which outputs HTML and requires turndown or similar).

3. **Metadata extraction is a first-class feature.** `extract_metadata()` returns a structured Document object with title, author, date, sitename, url, hostname, description, language, categories, tags. Handles publishers that emit metadata in any of five common formats.

4. **Active maintenance with academic backing.** Used as a research tool for web corpus construction. Funded indirectly through grant-supported projects. Unlikely to abandonware.

5. **Python stdlib + lxml is the whole dep chain.** Easy install, fast parse (C-accelerated via lxml), small wheel footprint.

**Alternatives rejected:**

- **newspaper3k** — maintenance stale, last meaningful update 2020-ish. Falls behind on modern sites with heavy JavaScript chrome.
- **goose3** — fork of newspaper, even less maintained.
- **Mozilla Readability (via @mozilla/readability + jsdom, or readabilipy wrapper)** — requires Node + jsdom, making the dep tree significantly heavier. Also outputs HTML, requiring a second markdown-conversion step. Quality is comparable to trafilatura; dep weight is not.
- **Roll-my-own DOM-density parser** — we tried this in the exploratory phase. Result was ~200 lines of brittle heuristics that got the first article right and failed on the second. Trafilatura replaces all of it with one call.
- **defuddle (2024 fork of Readability)** — too young to trust for production. Revisit in 6 months.

**Watch out:** trafilatura's markdown output dropped inline links by default in earlier 1.x versions. 2.0+ requires `include_links=True` explicitly. If a future version changes defaults again, the call site in `url_to_markdown.py:extract_markdown` needs to be re-verified. Pin `trafilatura>=2.0,<3.0` in any formal requirements file to guard against 3.x API changes.

## HTTP fetcher: why curl_cffi

**What it does:** Python bindings to a patched libcurl fork (`curl-impersonate`) that mimics real browser TLS handshakes and HTTP/2 frame ordering. The high-level `requests`-compatible API accepts an `impersonate="chrome124"` argument and magically bypasses most passive bot-detection fingerprinting.

**Why it matters:** Modern anti-bot systems (Cloudflare, PerimeterX, DataDome, Akamai Bot Manager) don't just check User-Agent headers — they fingerprint the TLS handshake (JA3/JA4 hash), the TLS cipher suite ordering, ALPN negotiation, and HTTP/2 frame ordering. Python's `requests` and `urllib3` have distinct TLS fingerprints that identify them instantly regardless of what headers you send. Trying to bypass Cloudflare with plain `requests` + spoofed User-Agent **does not work** on a meaningful fraction of modern sites.

curl_cffi impersonates Chrome's exact TLS behavior. It bypasses passive fingerprinting (does not bypass active JS challenges — that still requires a real browser).

**Alternatives rejected:**

- **`requests`** — classic, but the TLS fingerprint screams "Python" to Cloudflare. Fails on many target sites.
- **`httpx`** — modern, async-capable, but shares the same `urllib3` / Python TLS fingerprint problem. No impersonation.
- **`aiohttp`** — same fingerprint issue.
- **stdlib `urllib`** — no impersonation, no modern UX.
- **Running real curl as a subprocess** — works in principle but introduces process-management complexity and the system curl does not include the impersonation patches.

**Watch out:**

- `CURLOPT_RESOLVE` is not exposed via the high-level Session API in curl_cffi 0.15.0, which is why this skill does not pin IPs for DNS rebinding defense (see `security-model.md`). If a later version exposes it, update `fetch_with_revalidation` to use it.
- curl_cffi ships a prebuilt libcurl binary inside its wheel (~5-8MB per platform). On Python versions without prebuilt wheels, the install falls back to source compilation requiring MSVC or GCC. Verified to have Python 3.14 wheels as of v0.15.0.
- The `impersonate` profile name tracks Chrome versions. `chrome124` was current at skill creation; rotate forward when Cloudflare updates its fingerprint detection.

## Browser cookies: why browser_cookie3

**What it does:** Reads cookies from the user's local Chrome / Firefox / Edge / Brave / Opera / Safari / Arc cookie stores. Supports domain-scoped extraction so the skill can load only the cookies for the target hostname.

**Why it's the right primitive:**

1. **Active maintenance.** Regular releases tracking Chrome's cookie encryption changes.
2. **All major browsers.** One library, five browsers, same API.
3. **Cross-platform.** Handles Windows DPAPI encryption (Chrome), macOS keyring (Safari/Chrome), Linux keyring variants (Chrome/Firefox), plain SQLite (Firefox everywhere).
4. **Domain scoping is a first-class argument.** `browser_cookie3.chrome(domain_name='nytimes.com')` returns only nytimes.com cookies. The skill uses this to minimize blast radius — the skill never loads the user's full cookie jar.

**Alternatives rejected:**

- **Manually exporting cookies from DevTools** — clunky UX, breaks automation.
- **pycookiecheat** — Chrome only, less actively maintained.
- **Running Playwright with the user's existing profile** — works, but massive dep weight for the single feature of "load cookies."

**Watch out:**

- **Chrome 127+ app-bound encryption.** Google tightened Chrome's cookie encryption in July 2024. browser_cookie3 has been updated but edge cases on Windows exist. If a user reports `Could not load cookies from chrome`, Firefox is the reliable fallback (plain SQLite, no encryption).
- **On Windows, Chrome's cookie SQLite DB is locked while Chrome is running.** Users need to close Chrome before invoking with `--browser-cookies chrome`. Documented in SKILL.md and in the error message.

## SSRF guard: why stdlib + custom code

**Considered:** `safeurl-py` from Include Security — a drop-in `requests` replacement with SSRF protection built in.

**Why we rolled our own instead:** Include Security archived the `safeurl-py` repository in 2024 with a note recommending against application-layer SSRF libraries in favor of network-layer controls. Their 2023 retrospective post ([Mitigating SSRF in 2023](https://blog.includesecurity.com/2023/03/mitigating-ssrf-in-2023/)) walks through the specific failure modes of naive app-layer SSRF libraries (DNS rebinding, redirect TOCTTOU, parser differentials).

Given that the maintainer explicitly recommends against using the library, using it would create false confidence. The failure modes are real and well-documented.

**What we built instead:** ~80 lines of stdlib code (`scripts/lib/ssrf_guard.py`) that:

1. Parses the URL once with `urllib.parse` (same parser end-to-end, avoiding parser differentials)
2. Checks the scheme against an allowlist
3. Resolves DNS via `socket.getaddrinfo()`
4. Validates every returned address against `ipaddress.ip_address().is_global`
5. Hard-blocks cloud metadata IPs and hostnames unconditionally
6. Soft-blocks other non-global addresses with `--allow-private` override
7. Is re-invoked by the fetcher on every redirect hop (not just the initial URL)

This is a correctly-constructed app-layer defense. It is still not a complete SSRF mitigation — it doesn't defeat DNS rebinding (see `security-model.md`). But it is explicit about its limits, auditable at ~80 lines, and does what Include Security's own recommended "initial mitigation for companies that don't yet have network-layer controls" looks like.

**Alternatives rejected:**

- **safeurl-py** — archived, recommended against by its own maintainer.
- **Rolling the check into urllib monkeypatches** — brittle, tangles policy with plumbing.
- **Third-party SSRF middleware for `requests`** — doesn't compose with curl_cffi.

**Watch out:** the ssrf_guard module has direct test coverage in its smoke test. Adding any new policy rule (additional blocked IPs, new scheme, allowlisting specific hosts) needs a corresponding test case. Keep the module small and the test suite current.

## Env management: why cascade uv → venv

**The problem:** Shipping a Python skill with third-party deps is historically the worst part of the Python UX. Every approach has drawbacks:

- **Global pip install:** pollutes the system Python, needs `--user` or sudo, breaks on managed environments.
- **Shipped venv:** fat, version-specific, not cross-platform.
- **Require the user to manage venvs:** unacceptable friction for a skill.
- **`pipx run`:** designed for running packages that install CLI tools, not running arbitrary scripts with library dependencies.

**Why uv is the ideal primary path:** `uv run --with <dep> python <script>` creates a cached ephemeral environment on the fly. No venv management, no install step the user thinks about, ~2 seconds first run, ~100ms subsequent runs. This is the single biggest UX win in modern Python tooling for scripts like this.

**Why we don't require uv:** uv is not universally installed yet. Requiring it would make the skill fail on any user who hasn't adopted uv yet. Unacceptable for "just works" UX.

**The cascade:**

1. If the deps are already importable in whatever Python is running bootstrap.py, run in-process. Handles users who have the deps globally or are running in an existing venv.
2. If `uv` is on PATH, `exec uv run --with ...`. Fast, ephemeral, clean.
3. Otherwise, create a dedicated venv at `~/.cache/url-to-markdown/venv` (or `%LOCALAPPDATA%\url-to-markdown\venv`), pip install the deps, exec the venv's python. Slower first run, zero setup steps for the user.
4. If none of the above work, fail with install instructions for the three fix paths: install uv, install deps globally, or check that `venv` and `pip` modules are available.

**Alternatives rejected:**

- **Require uv.** Too much user friction.
- **Cascade uv → pipx → venv.** pipx is the wrong tool for this use case (see above).
- **Bundle the deps into the skill directory.** Fragile across Python versions, breaks on platform differences.

**Watch out:** the Tier 3 venv lives at a cache path, not inside the skill directory, so rebuilding the skill doesn't invalidate the venv. This is intentional — a user may clone the skill, update it, and the cached env still works. If deps are upgraded, bump the REQUIRED constants and the bootstrap will detect the partial env and rebuild.

## Runtime: why Python 3.12+

**Considered:** Python vs. Node (via @mozilla/readability + jsdom) vs. Go (single-binary via go-readability or custom) vs. Rust.

**Why Python:**

1. Trafilatura is the best extractor and is Python-only. This alone would decide the question.
2. curl_cffi is Python-native.
3. browser_cookie3 is Python-native.
4. Python is on virtually every dev machine in 2026 and on every CI runner.
5. The SSRF guard is 80 lines of stdlib code — trivial to write, audit, and maintain.

**Why 3.12 specifically, not 3.9:**

1. **Python 3.9 reached EOL in October 2025** and no longer receives security patches. Advertising `Python 3.9+` support in 2026 points users at an unpatched runtime.
2. **Python 3.10 reaches EOL in October 2026** — within the likely useful life of this skill. Picking it as a floor would force a re-bump within months.
3. **Python 3.11 and 3.12 are the current active releases**, both still getting security patches. 3.12 is the cleaner pick because it's been stable longer and is the current "stable" in the release cadence.
4. The skill has no code that actually requires features newer than 3.8 — `from __future__ import annotations` handles all the typing. The minimum version is a **policy** decision (what we'll support) not a **technical** constraint (what we can compile).
5. A user on a "modern dev machine" in 2026 either has 3.12+ natively or can run `uv python install 3.12` in ~10 seconds. Supporting older versions just to be generous leaves support debt on the table with no corresponding benefit.

The general rule: pick the LARGER of (technical floor, policy floor) when choosing a minimum Python version. Not the smaller.

**Why not Node:** Would need trafilatura's feature set in a JavaScript extractor. The closest is @mozilla/readability, which is less accurate and doesn't do metadata extraction. Net loss.

**Why not Go:** Would need to build per-platform binaries and ship them in the skill, or require the user to install a Go toolchain. Neither is acceptable for skill UX.

**Why not Rust:** Same as Go, plus a less mature extraction library ecosystem.

## Extractor seam (v1.1+): why a pluggable registry

**The problem:** url-to-markdown was originally a single-script skill with
trafilatura as the sole extraction backend. Trafilatura is excellent on
news/blog articles but strips content it shouldn't on some page shapes
(forum threads, structured KB articles). Today's choices: live with the
strip, or fork the entire skill per-site.

**Why a registry, why now:** v1.1 adds `lib.extractors.register_extractor(host, fn)`.
Site-specific extractors register against a hostname and the dispatch
table routes future fetches there. The registry starts empty — v1.1
behavior is identical to v1.0 for every URL.

Alternative considered: a config file (e.g., `extractors.toml`) where
the user maps hosts to extractor scripts. Rejected because it adds a
config-loading layer and makes the trust boundary fuzzy (where do the
extractor scripts live? Whose sandbox?). The Python-import-time
register call has clearer semantics: extractors are code that lives in
the skill repo, reviewed alongside the skill, no runtime config.

## BS4 primitives (v1.1+): why ship them with the seam

The dispatch table is necessary but not sufficient — a site-specific
extractor also needs primitives. trafilatura is awkward to compose with
because its public API expects HTML in / markdown out, with metadata
extracted from the same HTML on a side path. For sites where the right
extraction strategy is "walk the DOM, find these specific selectors,"
trafilatura is the wrong tool.

BS4 + lxml is the standard Python answer. v1.1 ships three primitives:

- `parse_html(html)` — bs4 + lxml, tolerant of malformed input.
- `extract_images(soup, base_url)` — DOM-order image dicts with
  resolved absolute URLs.
- `html_to_markdown(node)` — basic HTML-to-markdown for the common-subset
  tags (paragraphs, headings, lists, links, code, images, blockquotes, hr).

These are exposed as `lib.extractors.*` for use by future site-specific
extractors. They have no v1.1 callers; tests exercise them directly.
Adding bs4 to `bootstrap.REQUIRED` is the only dep-tree growth from this
change (~250KB wheel; lxml is already in the tree transitively via
trafilatura).

**Watch out:** the `html_to_markdown` tag set is deliberately narrow —
do not extend it to cover trafilatura's full feature set. If a future
site-specific extractor needs `<table>` or `<dl>` rendering, that's a
separate plan with its own rationale and test coverage. The primitive
exists as an ALTERNATIVE to trafilatura, not a replacement.

## Structured warnings (v1.1+): why the envelope additions are additive

**The problem:** v1.0 emitted free-text warning strings in
`warnings: [str]`. Agents had to substring-match to branch on warning
type. That's fragile (typo in the agent's substring → silent miss) and
opaque to programmatic recovery logic.

**Why structured, why now:** v1.1 adds `extraction_warnings: [dict]`
alongside the legacy `warnings: [str]`. Each structured warning has a
stable `{code, severity, recovery_action, ...extras}` shape with a
constrained code enum. Agents branch on `code` and `recovery_action`
instead of substring-matching. The `complete: bool` field is the
lowest-cost fast-fail check.

**Why additive, not replacing:** removing the legacy `warnings: [str]`
field in v1.1 would break every existing agent in the wild reading it.
The structured-warning emission auto-derives the legacy strings, so
v1.0 agents keep working with no code change. One release cycle minimum
before any deprecation of `warnings: [str]`.
