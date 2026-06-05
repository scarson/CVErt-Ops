# url-to-markdown

Transcribe a web article from a URL into a local markdown file with YAML frontmatter. Handles Cloudflare-protected sites, paywalls with browser cookies, and refuses unsafe fetches (cloud metadata, private networks by default). Designed for humans at a terminal AND for agents (Claude Code, Codex CLI) that need to save or cite article content.

```
$ scripts/bootstrap.py https://www.reworked.co/digital-workplace/ai-is-a-tool/
OK  /your/cwd/2026-04-02-is-ai-a-modern-day-white-whale.md
    title:      Is AI a Modern-Day White Whale?
    author:     Karl Chan
    published:  2026-04-02
    words:      1259
    http:       200 (1 hop)
```

The resulting file is a valid markdown document with YAML frontmatter: title, author, publish date, source URL, fetched timestamp, word count, HTTP status, and the article body with inline links preserved. It will parse with any YAML library (Obsidian, Jekyll, Hugo, Pandoc, static site generators, etc.).

## Who should read which file

This skill has three audiences. Each reads a different file.

| If you are... | Read this first |
|---|---|
| **An agent** (Claude Code, Codex CLI) using the skill | [SKILL.md](SKILL.md) — invocation patterns, flag semantics, exit codes, JSON envelope contract |
| **A human** running the skill from a terminal | This README (keep reading) |
| **A developer** maintaining, extending, or debugging the skill | This README, then jump to [references/](references/) for deep dives |

## 30-second quick start

**Prerequisites:** Python 3.12 or newer. That's it. Everything else is installed on first run.

1. **Install the skill.** From the `agent-skills/` repo root, run `scripts/install.sh` (macOS/Linux) or `scripts/install.ps1` (Windows). This symlinks the skill into `~/.claude/skills/` and `~/.agents/skills/` so Claude Code and Codex CLI can find it automatically on their next session start.
2. **Run it on a URL.** From any terminal, in any directory:
   ```
   python <agent-skills>/skills/url-to-markdown/scripts/bootstrap.py https://example.com/article
   ```
   First invocation takes ~2 seconds (installs dependencies into a cached environment). Subsequent invocations are ~1.5 seconds including network fetch.
3. **Inspect the result.** The markdown file lands in your current directory with a filename like `YYYY-MM-DD-slug-of-title.md`.

That's the whole thing. If it worked, skip ahead to "[When it doesn't work](#when-it-doesnt-work)" for common failure modes.

## How it works (the 60-second version)

```
Your URL
    │
    ▼
┌──────────────────────┐
│  bootstrap.py        │  Finds or creates a Python env with the deps.
│  (cascade)           │  Prefers uv, falls back to a dedicated venv in
│                      │  your user cache dir. Writes a sentinel file so
│                      │  the fast path skips env verification entirely.
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  url_to_markdown.py  │  The real script. Validates the URL against
│  (main)              │  the SSRF policy, fetches via curl_cffi with
│                      │  Chrome TLS fingerprint impersonation, extracts
│                      │  via trafilatura, emits a clean markdown file
│                      │  with YAML frontmatter.
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  Your markdown file  │
└──────────────────────┘
```

Three key design points:

1. **curl_cffi with TLS impersonation** bypasses Cloudflare-class bot fingerprinting that defeats plain `requests`. The skill works on real-world sites like reworked.co, simonwillison.net, MDN, arxiv.org out of the box.
2. **trafilatura** does article body extraction — strips navigation, sidebars, ads, related-posts widgets, and extracts typed metadata from JSON-LD / OpenGraph / microdata fallback chains. Best-in-class for news/blog articles as of 2026.
3. **Stdlib SSRF guard** refuses cloud metadata endpoints unconditionally, soft-blocks private/loopback IPs (override with `--allow-private`), and re-validates every redirect hop. Based on [Include Security's 2023 SSRF guidance](https://blog.includesecurity.com/2023/03/mitigating-ssrf-in-2023/).

For the full rationale on why these specific tools and not alternatives, see [`references/tool-selection-rationale.md`](references/tool-selection-rationale.md).

## Common invocations

```bash
# Basic: fetch an article into the current directory
scripts/bootstrap.py https://example.com/article

# Target a specific output directory
scripts/bootstrap.py https://example.com/article --out ~/Documents/articles

# JSON envelope for agent parsing
scripts/bootstrap.py https://example.com/article --json

# Use your Chrome session cookies for a paywalled Substack post
scripts/bootstrap.py https://author.substack.com/p/essay --browser-cookies chrome

# Fetch your own localhost dev server (overrides SSRF private-IP refusal)
scripts/bootstrap.py http://localhost:4000/draft --allow-private

# Increase timeout for a slow server
scripts/bootstrap.py https://example.com/article --timeout 60

# Re-fetch with overwrite (default keeps prior runs as `-2`-suffixed files)
scripts/bootstrap.py https://example.com/article --overwrite

# Decoupled cookie source (avoid the Windows Chrome cookie-DB lock)
COOKIE_HEADER='session_id=abc; user_token=xyz' \
  scripts/bootstrap.py https://example.com/article --cookies-from-env COOKIE_HEADER

# Strict mode for CI: exit 8 if extraction looks like a SPA or paywall
scripts/bootstrap.py https://example.com/article --strict --json
```

Run `scripts/bootstrap.py --help` for the full flag list.

## When it doesn't work

The three most common failure modes, in order of how often they hit:

### The extraction is suspiciously short

You see `OK` on exit but the file has very little content, and stderr has a warning like `Extracted body is very short (120 chars) relative to source HTML (250KB)`.

**Cause:** The page is either paywalled or JavaScript-rendered (an SPA). Trafilatura sees only the pre-hydration skeleton.

**Fix:**

- **If it's paywalled:** rerun with `--browser-cookies chrome` (or `firefox`, `edge`, `brave`, `opera`) to use your authenticated session. On Windows, Chrome may need to be closed first so its cookie DB isn't locked.
- **If it's an SPA:** the skill is text-only and cannot run JavaScript. Ask your agent to escalate to the Playwright MCP tool instead, which renders the page in a real browser.

### HTTP 403 or Cloudflare challenge page

You see `ERROR FetchError: HTTP 403 fetching ...` with a body preview that contains CAPTCHA HTML.

**Cause:** The site has an *active* bot challenge (JavaScript challenge, CAPTCHA). curl_cffi's TLS fingerprint impersonation bypasses *passive* fingerprinting but cannot solve active challenges.

**Fix:** Escalate to Playwright. There is no way to bypass an active challenge from a headless text-only client.

### `SSRFError: ... is blocked unconditionally`

You see exit code 4 with a diagnostic mentioning cloud metadata, a private IP, or a bad scheme.

**If the target was legitimate:**

- **Local dev server** (`localhost`, `127.0.0.1`, `192.168.1.x`): add `--allow-private`. The refusal is a safety default.
- **Internal corporate wiki on VPN**: add `--allow-private`. Same reason.
- **Cloud metadata endpoint** (`169.254.169.254`, `metadata.google.internal`): no override. The skill refuses these unconditionally because they expose credentials and there is no legitimate "transcribe an article" use case targeting them. If you really need the content, use `curl` directly.

**If the target was not legitimate** (your agent was prompt-injected, or you typo'd): investigate the URL source before retrying.

For the full catalog of 15 documented failure modes and recovery steps, see [`references/failure-modes.md`](references/failure-modes.md).

## For developers: maintaining and extending the skill

### Project layout

```
skills/url-to-markdown/
├── SKILL.md                          # Agent-facing docs (loaded by Claude Code, Codex)
├── README.md                         # This file (human-facing)
├── scripts/
│   ├── bootstrap.py                  # Dep cascade: uv → venv → fail
│   ├── bootstrap.sh                  # Unix thin wrapper → bootstrap.py
│   ├── bootstrap.ps1                 # Windows thin wrapper → bootstrap.py
│   ├── url_to_markdown.py            # Main CLI (fetch + extract + emit)
│   └── lib/
│       └── ssrf_guard.py             # Stdlib SSRF validator (three-tier policy)
├── references/
│   ├── security-model.md             # Threat model + honest limits
│   ├── failure-modes.md              # F1-F15 error catalog with recovery
│   └── tool-selection-rationale.md   # Why trafilatura + curl_cffi + stdlib guard
├── examples/
│   └── reworked-example.md           # Real sample output
└── tests/
    ├── fixtures/                     # 5 cached HTML fixtures (reworked, MDN, arxiv, etc.)
    └── test_extraction.py            # Self-bootstrapping property-based tests
```

### Running the tests

```bash
python skills/url-to-markdown/tests/test_extraction.py
```

The test runner self-bootstraps through the cached venv — you can invoke it from any Python interpreter, whether or not trafilatura/curl_cffi/browser_cookie3/pyyaml are importable. First run may take ~20 seconds to install deps; subsequent runs are instant.

**Current state:** 19 tests covering extraction quality, SSRF policy enforcement, protocol downgrade refusal, YAML frontmatter round-trip (via PyYAML), and `_yaml_scalar` edge cases.

The tests are **property-based, not goldenfile**. They assert things like "title contains expected substring," "body length within expected range," "PyYAML parses the frontmatter without error" — so they survive minor trafilatura upgrades without breaking.

### Adding a new content type (e.g., PDFs)

1. Extend `classify_content_type()` in `scripts/url_to_markdown.py` to return a new category.
2. Add a new extraction path in `run()` for that category. Current paths: `html` (trafilatura), `text` (passthrough), `pdf`/`feed`/`binary` (refuse).
3. Add a cached fixture under `tests/fixtures/` and a property-based test in `tests/test_extraction.py`.
4. Update `references/failure-modes.md` if you add new failure cases.

### Adding a new SSRF policy rule

Edit `scripts/lib/ssrf_guard.py`:

- **New cloud metadata IPs/hostnames:** add to `CLOUD_METADATA_IPS` or `CLOUD_METADATA_HOSTS` frozensets. Always hard-blocked.
- **Scheme whitelist change:** edit `ALLOWED_SCHEMES`. Keep the list minimal (`http`, `https` only right now).
- **New soft-block category:** add to `validate_url()` in the per-IP validation loop. Any rule you add must be testable in `tests/test_extraction.py` — add a test alongside.

### Debugging a failure

1. Run with `--json` to get the structured envelope on stdout. That's where the error type, message, and exit code live.
2. If the issue is in extraction, load the HTML fixture into a Python REPL and call `trafilatura.extract()` directly with the same kwargs as `scripts/url_to_markdown.py:extract_markdown()`.
3. If the issue is in fetching, try `curl_cffi` directly with the same `impersonate="chrome124"` kwarg to isolate whether it's TLS fingerprinting or extraction.
4. If the issue is in SSRF policy, call `ssrf_guard.validate_url(...)` directly and inspect what it raises.

### Upgrading dependencies

The skill pins three third-party deps. To upgrade:

1. Bump the versions in your local smoke venv: `pip install --upgrade trafilatura curl_cffi browser_cookie3 pyyaml`.
2. Run the test suite. **Pay special attention to the YAML round-trip tests** — trafilatura's metadata format or the frontmatter structure could change between versions.
3. Live-test against all 4 fixture URLs (reworked, MDN, arxiv, simonw) using a real fetch. Ensure the frontmatter still round-trips through PyYAML.
4. If anything breaks, do not revert silently — add a new test case that captures the regression, fix it, then upgrade.

## Design decisions worth knowing

These are the less-obvious architectural choices. Each has a "why" behind it.

| Choice | Why |
|---|---|
| **No `requests` / `httpx`** | They share a Python-identifying TLS fingerprint that Cloudflare blocks. curl_cffi impersonates Chrome's TLS handshake to bypass passive bot detection. |
| **Build frontmatter from typed values, not trafilatura's output** | Trafilatura's `with_metadata=True` emits unquoted strings that break YAML parsers whenever a title/description contains `": "`. We call `extract_metadata()` separately and serialize every field through `_yaml_scalar()`. |
| **No `PyYAML` at runtime** | PyYAML is a test-only dependency. The skill emits YAML via a 50-line hand-crafted `_yaml_scalar()` that handles all the edge cases (flow indicators, keywords, colons, newlines, lists). This keeps the runtime dep footprint small. |
| **Three-tier SSRF policy** | Cloud metadata (hard block, no override) / private IPs (soft block, `--allow-private` override) / public (allow). The middle tier is what makes this skill usable for local dev servers without abandoning safety. |
| **No DNS rebinding defense** | curl_cffi 0.15.0 doesn't expose `CURLOPT_RESOLVE` on its Session API. Adding it would require ~50 lines of low-level libcurl wrangling for a defense against a narrow attack. Documented honestly in [`references/security-model.md`](references/security-model.md). |
| **uv → venv cascade, not uv-required** | uv isn't universally installed yet. Requiring it would break the skill for users who don't have it. The cascade falls back gracefully and prints a one-line hint pointing at the uv install URL when falling back. |
| **Python 3.12 minimum, not 3.9** | 3.9 reached EOL in October 2025. Advertising 3.9+ support in 2026 points users at an unpatched runtime. |
| **Structured warnings + complete:bool (v1.1+)** | Agents branch structurally on the `extraction_warnings` list and the `complete` bool instead of substring-matching free text. Legacy `warnings: [str]` field is preserved and auto-derived for one release cycle. |
| **Pluggable extractor seam (empty registry in v1.1)** | Future site-specific extractors register via `lib.extractors.register_extractor(host, fn)`. The empty registry means every URL falls through to the generic trafilatura path — no behavior change for v1.1 users. |

For all of these in depth: [`references/tool-selection-rationale.md`](references/tool-selection-rationale.md).

## Known limitations

Documented honestly because we think you should know what you're running:

- **JavaScript-rendered sites** are not handled. The skill fetches static HTML only. Escalate to Playwright for SPAs.
- **Active bot challenges** (Cloudflare JS challenges, CAPTCHA walls) are not bypassed. curl_cffi handles *passive* TLS fingerprinting only.
- **DNS rebinding** attacks are not defeated (see above). If your threat model includes adversarial DNS, run the skill inside a container with restricted network egress.
- **Response size** is not capped. A malicious server returning 10GB of text would exhaust memory. Mitigation is a future change.
- **Paywall detection** is English-only — the phrase list doesn't handle other languages.
- **Ordered list numbering** in article bodies renders as headings rather than numbered items when the source used CSS counters instead of text numbers. Trafilatura does the right thing semantically; the output is just not `1. 2. 3.`-style.

For the full honest catalog: [`references/security-model.md`](references/security-model.md) and [`references/failure-modes.md`](references/failure-modes.md).

## License

Inherited from the parent [`agent-skills/`](../../) repository. See [LICENSE](../../LICENSE) at the repo root.
