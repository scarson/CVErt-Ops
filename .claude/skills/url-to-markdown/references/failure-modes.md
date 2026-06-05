# Failure modes and recovery

This document catalogs the ways the skill can fail, the exit code and diagnostic it emits, and what the agent (or user) should do in response. Keep this open during development when a URL doesn't work — most symptoms have a known cause and a clear next step.

## Exit code reference

| Code | Meaning             | What went wrong                                              |
| ---- | ------------------- | ------------------------------------------------------------ |
| 0    | Success             | File written                                                 |
| 1    | User error          | Bad args, malformed URL, output path unwritable              |
| 2    | Fetch error         | Network, HTTP status 4xx/5xx, redirect loop, cookie load failure |
| 3    | Extraction error    | Empty result, unsupported content-type (PDF, feed, binary)  |
| 4    | SSRF violation      | Cloud metadata, non-public IP without `--allow-private`, bad scheme |
| 5    | Dependency error    | Python too old, pip/venv missing, can't install third-party deps |

## Failure catalog

### F1. HTTP 403 or 401 on fetch

**Symptom:** `FetchError: HTTP 403 fetching https://example.com/article`. Body preview may contain CAPTCHA HTML, Cloudflare challenge page markers, or a login wall.

**Probable causes:**

- Active Cloudflare challenge (not just passive TLS fingerprinting — a JS challenge page)
- PerimeterX / DataDome / Akamai Bot Manager issuing an active challenge
- The site requires authentication and `--browser-cookies` was not provided
- IP-based rate limiting or geoblocking

**Recovery:**

1. If it's a paywalled site where you have an account: retry with `--browser-cookies chrome` (or `firefox`, `edge`, `brave`, `opera`). Make sure the browser is closed first on Windows so the cookie DB isn't locked.
2. If that's not applicable and the site has active bot protection: escalate to the Playwright MCP tool to render the page in a real browser. The skill prints a hint when it thinks this is the issue.
3. If you're invoking from a cloud VM or datacenter IP: the site may geoblock by default. Run from a residential IP or use a proxy.

### F2. HTTP 5xx or transient network errors

**Symptom:** `FetchError: HTTP 502` / `ConnectionError` / `Failed to perform, curl: (...)`.

**Probable causes:** Temporary server issue, DNS flake, network partition.

**Recovery:**

- Retry once after a short delay. The skill does not automatically retry because retries complicate the agent error-reporting contract — leave that decision to the caller.
- If persistent over 5+ minutes, the target is broken; report and move on.

### F3. Extraction returned very short content

**Symptom:** Success (exit 0) but the warnings array contains `"Extracted body is very short (N chars) relative to source HTML (M bytes). Possible paywall, SPA, or extraction failure."`

**Probable causes:**

- **Paywall:** The publisher renders a preview of the article to anonymous visitors and gates the rest behind subscription. Trafilatura faithfully extracts whatever is visible.
- **JavaScript-rendered SPA:** The page's HTML skeleton exists but the body is hydrated client-side. Trafilatura extracts the skeleton.
- **Exotic markup:** The site uses a layout trafilatura's heuristics don't recognize well.

**Recovery:**

1. For paywalls: retry with `--browser-cookies` from a browser where you're logged in.
2. For SPAs: escalate to Playwright MCP — render the page, get the hydrated DOM, feed it to the skill as a file (future feature) or re-implement the extraction step against the rendered HTML.
3. For exotic markup: the content is probably extractable but the skill's default path doesn't get it. Consider a site-specific extractor (future feature) or manual cleanup.

### F4. Paywall phrase detected

**Symptom:** Success (exit 0) with `"Paywall phrase detected: 'subscribe to continue reading'. Try --browser-cookies to use an authenticated session."` in warnings.

**Probable cause:** Same as F3 subset — explicit paywall copy appears in the extracted text.

**Recovery:** `--browser-cookies`, as the warning suggests.

### F5. No title extracted

**Symptom:** Success (exit 0) with `"No title extracted. Metadata chain (JSON-LD -> OpenGraph -> <meta>) produced nothing. Extraction may be incomplete."`

**Probable causes:** Publisher ships no JSON-LD, no OpenGraph metadata, no Twitter Card, no `<meta name="title">`. Very rare for modern sites. The file will still be written but the filename falls back to a slug of the URL path.

**Recovery:** Check the output file — the body may still be fine. If the title matters, set it manually in the frontmatter after transcription.

### F6. ExtractError: "trafilatura returned no content"

**Symptom:** Exit code 3, `ExtractError: trafilatura returned no content — the page may be empty, JavaScript-rendered (SPA), or structured in a way the extractor does not recognize.`

**Probable causes:**

- SPA with essentially no server-rendered content in the HTML
- A page that is all JavaScript and DOM scaffolding, no article body
- An API response or error page that happens to have text/html Content-Type

**Recovery:** Escalate to Playwright MCP. The skill is not equipped to render JavaScript.

### F7. UnsupportedContentType: PDF

**Symptom:** Exit 3, `Content-Type is application/pdf. PDF transcription is not supported in v1. Use a PDF-specific tool (pdftotext, pymupdf, pdfminer.six) to extract text.`

**Recovery:** The skill is specifically for HTML articles. Use a PDF extraction tool directly. Future versions may add a PDF extractor as a second strategy.

### F8. UnsupportedContentType: RSS/Atom feed

**Symptom:** Exit 3, `Content-Type '...' looks like an RSS/Atom feed. Feed parsing is not supported in v1.`

**Recovery:** Feeds need a feed parser (`feedparser` Python library). This skill is for single-article transcription. If you want to transcribe every entry in a feed, parse the feed, then invoke this skill once per entry URL.

### F9. UnsupportedContentType: binary

**Symptom:** Exit 3, `Content-Type '...' is not a supported text format.`

**Probable causes:** Image, video, archive, unknown binary. The URL probably points to a resource, not an article.

**Recovery:** The URL is wrong. Ask the user for the article URL, not the asset URL.

### F10. SSRFError: cloud metadata

**Symptom:** Exit 4, `Cloud metadata IP/hostname ... is blocked unconditionally.`

**This is a deliberate refusal, not a bug.** Cloud metadata endpoints expose credentials and internal config. The skill will never fetch them regardless of flags.

**Recovery:** If the user specifically needs to fetch a cloud metadata endpoint, use `curl` directly — do not route it through this skill.

### F11. SSRFError: non-public IP

**Symptom:** Exit 4, `'host' resolves to non-public address ... Use --allow-private to override if this is an intentional fetch of a local resource.`

**Probable cause:** Targeting localhost, a LAN machine, a VPN-accessible internal service, or the user's home lab.

**Recovery:** If the fetch is intentional, add `--allow-private`. If it wasn't intentional (the agent fetched the wrong URL by mistake), investigate the URL source.

### F12. SSRFError: bad scheme

**Symptom:** Exit 4, `Scheme '...' is not allowed (only http and https are permitted).`

**Probable causes:** URL starts with `file:`, `gopher:`, `ftp:`, `ssh:`, `javascript:`, etc.

**Recovery:** The URL is not valid for this skill. `file://` URLs can be handled by reading the file directly. Others need format-specific tools.

### F13. FetchError: cookie load failure

**Symptom:** Exit 2, `Could not load cookies from chrome for example.com: ... On Windows, chrome may need to be closed first.`

**Probable causes:**

- Chrome is running and has the cookie SQLite DB locked (Windows-specific)
- Chrome has migrated to app-bound encryption and browser_cookie3 can't decrypt (Chrome 127+)
- The user's Chrome profile has no cookies for the target domain

**Recovery:**

1. Close Chrome and retry
2. Use Firefox instead (`--browser-cookies firefox`) — Firefox cookies are in plain SQLite
3. Manually export cookies from browser DevTools and skip this feature

### F14. FetchError: redirect loop

**Symptom:** Exit 2, `Redirect loop detected: https://a -> https://b -> https://a`

**Probable cause:** Server misconfiguration or cookie-based session redirect that cycles.

**Recovery:** The target is broken. Try fetching a different URL or wait and retry.

### F15. DependencyError on Tier 3 bootstrap

**Symptom:** Exit 5, `Could not create venv: ...` followed by install instructions, OR `Python 3.12+ required but found 3.X.Y`.

**Probable causes:**

- The user's Python is older than 3.12 (Python 3.9 reached EOL Oct 2025; 3.10 reaches EOL Oct 2026). The skill refuses to run on EOL'd Python versions.
- System Python was installed without the `venv` module (some Linux distros split it into `python3.12-venv`)
- Pip is broken or missing
- No write access to `~/.cache/url-to-markdown/venv` (Unix) or `%LOCALAPPDATA%\url-to-markdown\venv` (Windows)

**Recovery paths** (in order of preference):

1. **Install uv and let it handle everything.** uv includes `uv python install 3.12` which downloads and installs a Python 3.12 interpreter in seconds, no sudo needed. This is the cleanest path on every OS.
   See [https://docs.astral.sh/uv/getting-started/installation/](https://docs.astral.sh/uv/getting-started/installation/) for the platform-specific install command. We intentionally do NOT run the uv install one-liner from our own bootstrap — that would mean downloading and executing third-party code from our skill, and users should make that trust decision themselves.
2. **Install a newer system Python.** Download Python 3.12+ from python.org (Windows, macOS) or your distro's package manager (Linux).
3. **On Debian/Ubuntu**, install the `venv` package for your Python version:
   `sudo apt install python3.12-venv`
4. **Install deps globally** if you prefer to manage Python yourself:
   `pip install trafilatura curl_cffi browser_cookie3`

## When to escalate to Playwright

The skill is intentionally text-only (no JavaScript execution). If any of these apply, escalate to the Playwright MCP tool to render the page:

1. Exit 3 with `ExtractError: trafilatura returned no content`
2. Success with warning `"Extracted body is very short"` and the target is known to be a SPA (Twitter/X, single-page dashboards, some docs sites)
3. Success with a very short body that includes no recognizable article text

**How to escalate:** Use `mcp__plugin_playwright_playwright__browser_navigate` to load the URL, then `browser_snapshot` or `browser_evaluate('() => document.body.innerText')` to get the rendered text. Pass that text through a markdown converter (or save as-is if plain text is acceptable).

## When to NOT retry

- Exit 1 (user error): the URL or args are wrong. Fix the input, don't retry.
- Exit 4 (SSRF): the refusal is deliberate. Use `--allow-private` if the private target is legitimate; otherwise investigate why the URL was chosen.
- Exit 3 with `UnsupportedContentType`: the content type is fundamentally wrong for this skill. Use a different tool.
- Exit 5 (dependency): fix the environment, then invoke again.

Retrying any of these without fixing the underlying cause will produce the same error.

## Structured warning catalog (v1.1+)

The skill emits structured warnings in `extraction_warnings: [dict]`
alongside the legacy `warnings: [str]`. Each structured warning has
shape `{code, severity, recovery_action, ...extras}` and conforms to
the schema in `scripts/lib/structured_warnings.py`.

| code | severity | recovery_action | extras | When emitted |
|---|---|---|---|---|
| `short_body_suspected_spa_or_paywall` | warning | escalate | body_bytes, html_bytes, recovery_hint=js_render_required | Body < 500 chars when HTML > 20KB |
| `paywall_phrase_detected` | warning | retry | matched_phrase, recovery_hint=try_browser_cookies | Known paywall phrase found in body |
| `no_title_extracted` | info | accept | — | Metadata chain produced no title |
| `extraction_returned_no_content` | warning | escalate | recovery_hint=js_render_required | RESERVED in v1.1 — no call site emits this; the ExtractError hard-fail (exit 3) covers the empty-extraction case. A translation branch exists in `format_structured_warning_as_string` so a future plan can convert that hard-fail to a soft-fail (structured warning + complete:false + exit 0/8) without churning KNOWN_CODES. |

Agents reading `extraction_warnings` should branch on `code` and
`recovery_action`. The legacy `warnings: [str]` field is preserved for
backwards compat — same human-readable strings as v1.0.

`complete: bool` is the fast-fail check: `true` iff no warning has
`recovery_action == 'escalate'`. Agents should read this before
iterating `extraction_warnings`.

## New exit code (v1.1+)

- Exit 8 (StrictPartial): emitted ONLY when `--strict` is set AND any
  `extraction_warnings` entry has `recovery_action: escalate`. The
  output file is still written; the exit code signals "partial result"
  to CI/agent pipelines. Without `--strict`, the same situation
  produces exit 0 with `complete: false` in the envelope.
