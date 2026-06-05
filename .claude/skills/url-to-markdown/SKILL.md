---
name: url-to-markdown
description: Transcribe a web article from a URL into a local markdown file with YAML frontmatter (title, author, date, source URL, word count). Use when the user asks to save, archive, transcribe, or convert an article, blog post, news story, or docs page from a URL to markdown. Handles Cloudflare-protected sites via TLS fingerprint impersonation. Gracefully reports paywalls, SPAs, and unsupported content types instead of silently producing garbage.
compatibility: Requires Python 3.12+ (3.9 and 3.10 are EOL). Third-party deps (trafilatura, curl_cffi, browser_cookie3) install automatically on first run via a cascade (uv run → dedicated venv → fail with instructions). For fastest startup, install uv from https://docs.astral.sh/uv/getting-started/installation/. Requires internet access to fetch the target URL.
metadata:
  version: "1.0"
---

# url-to-markdown

Fetches a web article and writes it to a local markdown file with YAML frontmatter containing the article's metadata.

**This file is for agents invoking the skill.** Humans should read [README.md](README.md) for a developer-oriented overview, quick start, and contribution guide. Both files cover the same skill from different angles.

## When to use

Invoke when the user asks to:

- "transcribe this article", "save this to markdown", "archive this page"
- "convert this URL to markdown", "get me a markdown copy of this article"
- "make a local copy of this post"
- provides a URL and asks you to "read", "quote", or "cite" the content in a way that benefits from having a clean local copy

Do **not** use for:

- PDFs — the script detects and refuses them; use a PDF-specific tool
- RSS/Atom/sitemap feeds — the script detects and refuses them
- JavaScript-rendered SPAs (Twitter, many dashboards) — the script fails cleanly with a diagnostic; escalate to the Playwright MCP tool
- Very short extractions — the script warns when the result looks like a paywall or extraction failure

## How to run

```
scripts/bootstrap.py <URL> [options]
```

Or use the platform wrapper (both call `bootstrap.py`):

```
scripts/bootstrap.sh <URL> [options]    # Unix/macOS
scripts/bootstrap.ps1 <URL> [options]   # Windows
```

The bootstrap auto-installs dependencies on first run. See `references/tool-selection-rationale.md` for the cascade logic.

### Options

| Flag                       | Purpose                                                                                   |
| -------------------------- | ----------------------------------------------------------------------------------------- |
| `--out DIR`                | Output directory (default: current working directory)                                    |
| `--json`                   | Emit a structured JSON envelope on stdout for agent parsing                               |
| `--allow-private`          | Permit fetches of private / loopback / link-local addresses (cloud metadata still blocked) |
| `--browser-cookies BROWSER`| Load cookies from `chrome`, `firefox`, `edge`, `brave`, or `opera`, scoped to the target host |
| `--playwright`             | (v1: informational) Signal the caller is willing to escalate on SPA detection            |
| `--timeout SECONDS`        | Per-request timeout (default 30)                                                          |
| `--max-redirects N`        | Max redirect hops (default 5)                                                             |
| `--impersonate PROFILE`    | curl_cffi browser impersonation profile (default `chrome124`)                             |
| `--cookies-from-env VAR`   | Load raw `Cookie:` header value from named env var (mutually exclusive with `--browser-cookies`) |
| `--strict`                 | Promote escalate-class extraction warnings to exit code 8 (output file still written)     |
| `--overwrite`              | Write over an existing output file instead of `-2`/`-3`-suffixed sibling                  |

### Agent invocation pattern

Prefer `--json` when invoking from an agent. The envelope shape is stable across versions; parse it as structured data rather than scraping the human-readable stdout.

**Success envelope:**

```json
{
  "status": "success",
  "output_path": "/abs/path/2026-04-02-is-ai-a-modern-day-white-whale.md",
  "metadata": {
    "title": "Is AI a Modern-Day White Whale?",
    "author": "Karl Chan",
    "published": "2026-04-02",
    "source_url": "https://www.reworked.co/digital-workplace/ai-is-a-tool/",
    "final_url": "https://www.reworked.co/digital-workplace/ai-is-a-tool/",
    "fetched": "2026-04-11T07:22:28Z",
    "word_count": 1259,
    "content_type": "text/html; charset=utf-8",
    "http_status": 200,
    "hops": 1,
    "extraction_method": "generic_trafilatura",
    "content_hash_sha256": "3f2e1a4b..."
  },
  "warnings": [],
  "extraction_warnings": [],
  "complete": true,
  "error": null
}
```

**v1.1 additions (additive — legacy fields preserved for backwards compat):**

- `extraction_warnings`: list of structured warning dicts shaped as
  `{code, severity, recovery_action, ...extras}`. Stable code enum
  defined in `scripts/lib/structured_warnings.py:KNOWN_CODES`. See
  `references/failure-modes.md` for the full catalog and emission
  conditions.
- `complete`: bool. `True` iff no entry in `extraction_warnings` has
  `recovery_action == 'escalate'`. Lowest-cost fast-fail check for
  agents — read this BEFORE iterating the warning list.
- `metadata.extraction_method`: one of `"generic_trafilatura"` (HTML
  pages, the v1.1 default path) or `"text_passthrough"` (text/plain
  or text/markdown responses such as raw.githubusercontent.com URLs).
  Future site-specific extractors emit their own names.
- `metadata.content_hash_sha256`: SHA256 hex digest of the body
  markdown (excludes YAML frontmatter so the fetched timestamp does
  not perturb the hash). Useful for re-fetch dedup and change detection.

**Field contract for the success envelope:**

| Field | Always present? | Notes |
|---|---|---|
| `status` | yes | Always `"success"` or `"error"` |
| `output_path` | yes (success only) | Absolute path to the written markdown file |
| `metadata.source_url` | yes | The URL the user passed in |
| `metadata.final_url` | yes | Where content was actually fetched from (may equal `source_url` if no redirects) |
| `metadata.fetched` | yes | ISO-8601 UTC timestamp |
| `metadata.http_status` | yes | Final HTTP status code (typically 200) |
| `metadata.hops` | yes | 1 on direct fetch, N+1 per redirect followed |
| `metadata.word_count` | yes | Body word count (excludes frontmatter) |
| `metadata.content_type` | yes | Server-reported Content-Type header |
| `metadata.title` | no | Null if no title could be extracted |
| `metadata.author` | no | Null if no author metadata found |
| `metadata.published` | no | Null if no published date found |
| `warnings` | yes | List of strings, possibly empty; non-fatal quality issues (legacy form) |
| `extraction_warnings` | yes (v1.1+) | List of structured warning dicts; same content as `warnings` but machine-readable |
| `complete` | yes (v1.1+) | Bool. False iff any `extraction_warnings` has `recovery_action: escalate` |
| `metadata.extraction_method` | yes (v1.1+) | `"generic_trafilatura"` or `"text_passthrough"` |
| `metadata.content_hash_sha256` | yes (v1.1+) | SHA256 hex digest of the body markdown |
| `error` | yes | Null on success, object on error |

**Error envelope:**

```json
{
  "status": "error",
  "error": {
    "type": "SSRFError",
    "message": "Cloud metadata IP 169.254.169.254 is blocked unconditionally",
    "exit_code": 4
  }
}
```

**Error types** (stable set — parse as strings, do not add new ones without updating this doc):

| `error.type` | `exit_code` | Meaning | What to do |
|---|---|---|---|
| `UserError` | 1 | Bad URL format, unwritable output dir, invalid args | Fix the input and retry; do not loop-retry |
| `FetchError` | 2 | Network, HTTP 4xx/5xx, redirect loop, cookie load failure, protocol downgrade refused | Investigate: site might be down, target might need `--browser-cookies`, or may need Playwright escalation |
| `CookieError` | 2 | `--browser-cookies` could not read the browser's cookie store | Try a different browser (Firefox is usually easiest), or retry without the flag |
| `ExtractError` | 3 | Trafilatura returned nothing, SPA with no server-rendered HTML | Escalate to Playwright for SPAs; not retryable with this skill |
| `UnsupportedContentType` | 3 | PDF, RSS feed, image, or other non-HTML content at that URL | Use a format-appropriate tool; do not retry |
| `SSRFError` | 4 | Target IP/host refused by SSRF policy | Cloud metadata: do not override. Private IP: add `--allow-private` if intentional. Bad scheme: URL is wrong. |
| `OutputError` | 1 | Cannot create the output directory | Check permissions and path validity |

### Decision tree for agents handling results

```
Run scripts/bootstrap.py <URL> --json

  exit_code == 0 ──────────────────────────────────────────────────►  Success
    │                                                                   │
    │ Fast-fail: check `complete: bool` FIRST.                           │
    │   • complete: true  → content fully captured; read output_path.    │
    │   • complete: false → inspect `extraction_warnings` for the        │
    │                       escalate-class entry; surface to operator    │
    │                       OR escalate to a real-browser tool. The      │
    │                       file is still written even when complete:false.│
    │                                                                    │
    │ Then check warnings / extraction_warnings:                         │
    │   • short_body_suspected_spa_or_paywall (escalate) → possibly      │
    │       paywalled or SPA                                             │
    │     ┌─ has cookies available? retry with --browser-cookies         │
    │     ├─ page is known SPA? escalate to Playwright MCP               │
    │     └─ otherwise accept and inform user                            │
    │   • paywall_phrase_detected (retry) → retry with --browser-cookies │
    │   • no_title_extracted (accept, info) → extraction may be          │
    │       incomplete; accept                                           │
    │                                                                    │
    └─ Read output_path if caller needs the content                      │
                                                                         │
  exit_code == 1 (UserError)  ─── Fix URL / args, do not retry          │
                                                                         │
  exit_code == 2 (FetchError) ─── Investigate:                          │
    • HTTP 403 + Cloudflare body? → escalate to Playwright               │
    • HTTP 5xx? → wait and retry once                                    │
    • Connection refused? → target is down, report to user               │
    • Redirect loop? → target is broken, report to user                  │
                                                                         │
  exit_code == 3 (ExtractError / UnsupportedContentType)                │
    • Trafilatura returned nothing? → Playwright escalation              │
    • PDF/feed/image? → use a format-appropriate tool                    │
                                                                         │
  exit_code == 4 (SSRFError) ─── Policy refused the URL:                │
    • Cloud metadata? → DO NOT override; use curl directly if needed     │
    • Private IP? → retry with --allow-private if intentional            │
    • Bad scheme (file://, ftp://, gopher://)? → URL is wrong            │
                                                                         │
  exit_code == 5 (DependencyError) ── Environment broken:               │
    • Python < 3.12? → install newer Python                              │
                                                                         │
  exit_code == 8 (StrictPartial) ─── Only when --strict is set AND      │
    an escalate-class extraction warning fired. Output file IS written; │
    inspect extraction_warnings for the specific gap and recovery_hint. │
    • venv/pip missing? → install python3.12-venv or use uv              │
```

## Examples

**Transcribe a single article to the current directory:**

```
scripts/bootstrap.py https://www.reworked.co/digital-workplace/ai-is-a-tool/
```

**Save to a dedicated directory:**

```
scripts/bootstrap.py https://example.com/article --out ~/articles
```

**Agent invocation with JSON output:**

```
scripts/bootstrap.py https://example.com/article --json
```

**Access a paywalled Substack using the user's existing Chrome session:**

```
scripts/bootstrap.py https://example.substack.com/p/essay --browser-cookies chrome
```

Note: Chrome may need to be closed on Windows so the cookie SQLite database is not locked.

**Fetch a local dev server article (private IP override):**

```
scripts/bootstrap.py http://localhost:4000/my-draft --allow-private
```

## Exit codes

| Code | Meaning                                                    |
| ---- | ---------------------------------------------------------- |
| 0    | Success                                                    |
| 1    | User error (bad args, malformed URL)                       |
| 2    | Fetch error (network, HTTP 4xx/5xx, redirect loop, blocked)|
| 3    | Extraction error (no content, unsupported content type)    |
| 4    | SSRF policy violation                                      |
| 5    | Dependency / environment error (Python too old, pip missing)|
| 8    | StrictPartial — only when `--strict` is set AND an escalate-class extraction warning fired (output file still written) |

## Output format

The resulting markdown file has YAML frontmatter followed by the article body. Frontmatter fields come from trafilatura's metadata extraction chain (JSON-LD → microdata → OpenGraph → Twitter Card → `<meta>`), augmented with fields the script adds:

**From trafilatura:**

- `title`, `author`, `date`, `sitename`, `description`, `url`, `hostname`, `categories`, `tags`, `language`

**Added by the script:**

- `source_url` — the URL the user passed in
- `final_url` — the URL content was actually fetched from (only emitted if different from `source_url` after redirects)
- `fetched` — ISO-8601 UTC timestamp of when the fetch occurred
- `http_status` — final response status code
- `redirect_hops` — number of redirects followed (only if > 0)
- `word_count` — rough word count of the extracted body

Filename convention: `YYYY-MM-DD-slugified-title.md`, where the date is the article's published date (or omitted if unavailable). Collisions append `-2`, `-3`, etc.

## Failure modes

See `references/failure-modes.md` for the full catalog. Summary:

- **HTTP 403 / blocked by anti-bot:** The script uses curl_cffi with Chrome TLS impersonation, which bypasses most Cloudflare-class protection. If you still get 403, the site has active challenges (not just passive fingerprinting) and requires a real browser — escalate to the Playwright MCP tool.
- **Content extracted is very short:** The script emits a warning but still writes the file. Likely a paywall (try `--browser-cookies`) or an SPA (escalate to Playwright).
- **Extraction returned no content:** JavaScript-rendered site with no server-rendered HTML body. Escalate to Playwright.
- **Content-Type is PDF/feed/binary:** Script fails with `ExtractError` exit code 3 and a clear diagnostic. Use a format-appropriate tool.
- **SSRF policy refused the URL:** Exit code 4. See the error message — cloud metadata is unconditionally blocked; private IPs can be overridden with `--allow-private`.

## Security model

This skill implements application-layer SSRF mitigation: scheme whitelist (http/https only), DNS resolution-time IP validation, per-redirect revalidation, and an unconditional block on cloud metadata endpoints. Private / loopback / link-local addresses are refused by default; `--allow-private` overrides this.

**Known limitation:** this validator does not defeat DNS rebinding attacks. For details on the threat model and the specific set of attacks this skill does and does not defend against, read `references/security-model.md`. Based on Include Security's ["Mitigating SSRF in 2023"](https://blog.includesecurity.com/2023/03/mitigating-ssrf-in-2023/).

## Reference material

For full design rationale and detailed error handling guidance, read the per-topic files on demand:

- `references/security-model.md` — threat model, policy details, honest limits
- `references/failure-modes.md` — complete catalog of failure cases and recovery steps
- `references/tool-selection-rationale.md` — why trafilatura + curl_cffi + stdlib SSRF guard, alternatives considered and rejected

## Testing

The `tests/` directory contains property-based extraction tests against cached HTML fixtures. Run from anywhere:

```
python <skill-root>/tests/test_extraction.py
```

The test file self-bootstraps: if trafilatura / curl_cffi / browser_cookie3 / PyYAML are not importable in the invoking interpreter, it re-execs itself through the cached venv. Works from any Python 3.12+ interpreter.

**Test coverage (19 tests):**

- 5 extraction tests against cached fixtures (reworked.co, MDN, arXiv, simonwillison.net, raw GitHub README)
- 9 SSRF guard tests (allow public, block cloud metadata IP + hostname + trailing-dot variant, block RFC1918, block loopback, allow loopback with override, block bad schemes, reject missing hostname, cloud-metadata-cannot-be-overridden)
- 1 protocol-downgrade unit test
- 3 YAML frontmatter round-trip regression tests (`_yaml_scalar` edge cases, all fixtures round-trip through PyYAML cleanly, reworked.co-specific C1 regression test)
- 1 GitHub raw README passthrough test

Tests are property-based (title contains X, body length in range, PyYAML parses cleanly) rather than goldenfile, so they survive minor trafilatura upgrades.
