"""Transcribe a URL to a markdown file with YAML frontmatter.

Fetches an article via curl_cffi (with Chrome TLS fingerprint impersonation to
bypass Cloudflare-class bot protection), validates against the SSRF policy on
every hop, then extracts body + metadata via trafilatura and writes a markdown
file with YAML frontmatter to the output directory.

See ../SKILL.md for usage and ../references/ for design details.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

# Force UTF-8 on stdout/stderr — Windows Python defaults to cp1252, which
# crashes on Unicode in article titles, quotes, dashes, emoji, etc. Wrapped
# in try/except because pytest capture, StringIO, and agent harnesses may
# replace stdout with a non-TextIOWrapper object that has no reconfigure().
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except (AttributeError, OSError):
        pass
del _stream

# Local lib
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE / "lib"))
from ssrf_guard import SSRFError, validate_url  # noqa: E402
from structured_warnings import warning  # noqa: E402
from extractors import dispatch, ExtractResult  # noqa: E402


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

EXIT_OK = 0
EXIT_USER_ERROR = 1       # bad args, bad URL format
EXIT_FETCH_ERROR = 2      # network, HTTP error, redirect loop, blocked
EXIT_EXTRACT_ERROR = 3    # no content, unsupported content-type
EXIT_SSRF_VIOLATION = 4   # SSRF policy refused the URL
EXIT_DEPENDENCY_ERROR = 5 # required package not installed
# Exit codes 6 and 7 are intentionally unallocated; reserved for future use
# without renumbering. v1.1 cookie failures still emit EXIT_FETCH_ERROR (2).
EXIT_STRICT_PARTIAL = 8   # --strict promoted an escalate-class structured warning


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class FetchError(Exception):
    """Network, HTTP, or redirect-handling failure."""


class ExtractError(Exception):
    """Content could not be extracted (unsupported type, empty result, etc.)."""


class CookieError(Exception):
    """Cookie loading failed (browser DB locked, env var missing, parse error)."""


# ---------------------------------------------------------------------------
# Content-type dispatch
# ---------------------------------------------------------------------------


HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
TEXT_TYPES = frozenset({"text/plain", "text/markdown"})
FEED_TYPES = frozenset({
    "application/rss+xml", "application/atom+xml",
    "application/xml", "text/xml",
})


def classify_content_type(content_type: str) -> str:
    """Return 'html', 'text', 'pdf', 'feed', or 'binary'."""
    ct = (content_type or "").lower().split(";")[0].strip()
    if ct in HTML_TYPES:
        return "html"
    if ct in TEXT_TYPES:
        return "text"
    if ct == "application/pdf":
        return "pdf"
    if ct in FEED_TYPES:
        return "feed"
    return "binary"


# ---------------------------------------------------------------------------
# Fetcher
# ---------------------------------------------------------------------------


REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


def _is_scheme_downgrade(initial_scheme: str, next_scheme: str) -> bool:
    """Return True if going from initial_scheme to next_scheme weakens security.

    Only downgrade we treat as a violation: https -> http. Any other transition
    (http -> https, http -> http, https -> https) is fine. Non-http(s) schemes
    are refused earlier by the SSRF guard.
    """
    return initial_scheme == "https" and next_scheme == "http"


def fetch_with_revalidation(
    url: str,
    *,
    allow_private: bool = False,
    timeout: float = 30.0,
    max_redirects: int = 5,
    cookies: Any = None,
    impersonate: str = "chrome124",
) -> tuple[Any, str, list[str]]:
    """Fetch a URL, following redirects manually and re-validating each hop.

    Uses a single curl_cffi Session across all hops so that Set-Cookie
    headers from hop N are visible to hop N+1. This is required for
    handshake flows (Substack email links, generic login-bounce-to-article
    redirects) where the final target depends on a session cookie set by
    an earlier redirect.

    Refuses https -> http protocol downgrade in the redirect chain.
    Re-runs the full SSRF policy check on every hop. Tracks visited URLs
    and fails on cycles before exhausting the depth counter.

    Returns (response, final_url, visited_urls). Raises FetchError or SSRFError.
    """
    try:
        from curl_cffi import requests as ccr
    except ImportError as exc:
        raise FetchError(
            "curl_cffi is not installed. Run via scripts/bootstrap.py, "
            "which installs dependencies automatically."
        ) from exc

    initial_scheme = urlparse(url).scheme.lower()
    visited: list[str] = []
    current = url

    session = ccr.Session()
    if cookies is not None:
        # browser_cookie3 returns a CookieJar-compatible object; Session.cookies
        # supports update() from a jar-like.
        session.cookies.update(cookies)

    for hop in range(max_redirects + 2):
        if hop > max_redirects:
            raise FetchError(
                f"Exceeded maximum redirect depth ({max_redirects}). "
                f"Chain: {' -> '.join(visited + [current])}"
            )
        if current in visited:
            raise FetchError(
                f"Redirect loop detected: {' -> '.join(visited + [current])}"
            )
        visited.append(current)

        # SSRF policy check — enforced on every hop, not just the initial URL.
        validate_url(current, allow_private=allow_private)

        try:
            response = session.get(
                current,
                impersonate=impersonate,
                allow_redirects=False,
                timeout=timeout,
            )
        except Exception as exc:
            raise FetchError(
                f"Network error fetching {current}: {type(exc).__name__}: {exc}"
            ) from exc

        if response.status_code in REDIRECT_CODES:
            location = response.headers.get("location") or response.headers.get("Location")
            if not location:
                raise FetchError(
                    f"Redirect response {response.status_code} from {current} "
                    f"with no Location header"
                )
            next_url = urljoin(current, location)
            if _is_scheme_downgrade(initial_scheme, urlparse(next_url).scheme.lower()):
                raise FetchError(
                    f"Refusing protocol downgrade in redirect chain: "
                    f"initial URL used https but redirect target {next_url!r} uses http. "
                    f"If this is intentional, re-run with the target as the initial URL."
                )
            current = next_url
            continue

        if 400 <= response.status_code < 600:
            raise FetchError(
                f"HTTP {response.status_code} fetching {current}. "
                f"Body preview: {response.text[:200]!r}"
            )

        return response, current, visited

    raise FetchError("Redirect loop guard fell through — should not be reachable")


# ---------------------------------------------------------------------------
# Browser cookies (opt-in)
# ---------------------------------------------------------------------------


def parse_cookie_header_value(raw: str) -> dict[str, str]:
    """Parse a raw `Cookie:` header value into a {name: value} dict.

    Tolerant of trailing semicolons and whitespace. Cookie values may
    contain '=' characters (e.g., base64-padded session tokens); split
    only on the first '=' per pair.

    Values are passed through VERBATIM -- no percent-decoding, no quote
    stripping. RFC 6265 allows `%XX`-encoded values but real-world
    cookie consumers vary in whether they expect decoded or encoded
    forms. Keeping the parser dumb means whatever the user (or upstream
    agent) put in the env var is exactly what the target server sees.
    Agents whose use case requires decoded values must decode externally.
    """
    result: dict[str, str] = {}
    if not raw:
        return result
    for chunk in raw.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" not in chunk:
            # Malformed: `Cookie: foo` with no value. Skip — RFC 6265 does
            # not allow this but real-world inputs may have it.
            continue
        name, value = chunk.split("=", 1)
        result[name.strip()] = value.strip()
    return result


def load_env_cookies(var_name: str) -> dict[str, str]:
    """Read the raw `Cookie:` header value from the named env var and parse.

    Raises CookieError if the env var is not set. An empty-string env var
    is treated as a successful zero-cookie load (returns {}).

    Note: cookies loaded this way are NOT host-scoped — they travel through
    every redirect hop to whatever host the URL resolves to. Agents that
    need host scoping must produce a host-scoped env-var value externally.
    """
    import os
    if var_name not in os.environ:
        raise CookieError(
            f"Env var {var_name!r} is not set. Set it to a raw Cookie header "
            f"value (e.g., 'session_id=abc; user_token=xyz') before invoking."
        )
    return parse_cookie_header_value(os.environ[var_name])


def load_browser_cookies(browser: str, hostname: str) -> Any:
    """Return a cookie jar scoped to `hostname` from the named browser.

    Raises FetchError if the browser is unsupported or the cookie store
    can't be read (e.g. Chrome is running and has the SQLite DB locked).
    """
    try:
        import browser_cookie3
    except ImportError as exc:
        raise FetchError(
            "browser_cookie3 is not installed. Run via scripts/bootstrap.py "
            "to install dependencies automatically."
        ) from exc

    loaders = {
        "chrome": browser_cookie3.chrome,
        "firefox": browser_cookie3.firefox,
        "edge": browser_cookie3.edge,
        "brave": browser_cookie3.brave,
        "opera": browser_cookie3.opera,
    }
    loader = loaders.get(browser)
    if loader is None:
        raise FetchError(
            f"Unsupported browser {browser!r}. Supported: {', '.join(sorted(loaders))}"
        )

    try:
        return loader(domain_name=hostname)
    except Exception as exc:
        raise FetchError(
            f"Could not load cookies from {browser} for {hostname}: "
            f"{type(exc).__name__}: {exc}. "
            f"On Windows, {browser} may need to be closed first."
        ) from exc


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def extract_via_dispatch(html: str, *, url: str) -> ExtractResult:
    """Run the hostname-dispatched extractor against `html`.

    For v1.1 the registry is empty and this always falls through to
    extract_generic_trafilatura. Future site-specific extractors register
    via lib.extractors.register_extractor(hostname, fn).

    Wraps lib.extractors.dispatch so the call site in run() can stay
    self-contained -- no direct import of lib.extractors required for the
    main flow.
    """
    extractor = dispatch(url)
    return extractor(html, url=url)


def extract_markdown(html: str, url: str) -> tuple[str, Any]:
    """Extract body markdown + typed metadata from HTML via trafilatura.

    Returns (body_markdown_without_frontmatter, metadata_document).
    Raises ExtractError on empty / unrecognized content.

    Note: trafilatura's with_metadata=True emits a frontmatter block with
    unquoted string values, which produces invalid YAML for any value
    containing ": " (colon + space). We deliberately pass with_metadata=False
    and rebuild the frontmatter ourselves via build_frontmatter() so every
    value goes through _yaml_scalar() for correct quoting.
    """
    try:
        import trafilatura
    except ImportError as exc:
        raise ExtractError(
            "trafilatura is not installed. Run via scripts/bootstrap.py "
            "to install dependencies automatically."
        ) from exc

    body = trafilatura.extract(
        html,
        url=url,
        output_format="markdown",
        with_metadata=False,          # we build frontmatter ourselves
        include_comments=False,
        include_tables=True,
        include_links=True,
        include_formatting=True,
        favor_precision=True,
    )
    if body is None or not body.strip():
        raise ExtractError(
            "trafilatura returned no content — the page may be empty, "
            "JavaScript-rendered (SPA), or structured in a way the extractor "
            "does not recognize. If the page requires JS rendering, try again "
            "with --playwright to use a headless browser."
        )

    meta = trafilatura.extract_metadata(html)
    return body, meta


# ---------------------------------------------------------------------------
# Short-output heuristic — warn but don't refuse
# ---------------------------------------------------------------------------


PAYWALL_PHRASES = (
    "subscribe to continue reading",
    "subscribe to read",
    "this article is for subscribers",
    "sign in to read",
    "become a member to read",
    "create a free account to continue",
)


def detect_quality_warnings_on_body(
    body: str,
    raw_html_size: int,
    metadata: Any,
) -> list[dict[str, Any]]:
    """Return a list of STRUCTURED warning dicts about extraction quality.

    Each dict is shaped per lib/structured_warnings.py:warning(). The legacy
    free-text `warnings: [str]` envelope field is auto-derived from this list
    by run() via format_structured_warning_as_string().

    Accepts the article body AFTER frontmatter has been separated. The caller
    is responsible for passing body-only text; this function does not strip
    frontmatter itself.
    """
    warnings_out: list[dict[str, Any]] = []
    body_stripped = body.strip()
    body_len = len(body_stripped)

    if body_len < 500 and raw_html_size > 20_000:
        warnings_out.append(warning(
            "short_body_suspected_spa_or_paywall",
            recovery_action="escalate",
            recovery_hint="js_render_required",
            body_bytes=body_len,
            html_bytes=raw_html_size,
        ))

    lowered = body.lower()
    for phrase in PAYWALL_PHRASES:
        if phrase in lowered:
            warnings_out.append(warning(
                "paywall_phrase_detected",
                recovery_action="retry",
                recovery_hint="try_browser_cookies",
                matched_phrase=phrase,
            ))
            break

    if metadata is None or not getattr(metadata, "title", None):
        warnings_out.append(warning(
            "no_title_extracted",
            recovery_action="accept",
            severity="info",
        ))

    return warnings_out


def format_structured_warning_as_string(w: dict[str, Any]) -> str:
    """Render a structured warning as the human-readable string the legacy
    `warnings: [str]` envelope field uses.

    Keep this in lockstep with detect_quality_warnings_on_body -- every
    structured-warning code emitted by the skill MUST have a corresponding
    branch here, otherwise backwards-compat agents see truncated lists.
    """
    code = w["code"]
    if code == "short_body_suspected_spa_or_paywall":
        return (
            f"Extracted body is very short ({w['body_bytes']} chars) relative to "
            f"source HTML ({w['html_bytes']} bytes). Possible paywall, SPA, "
            f"or extraction failure."
        )
    if code == "paywall_phrase_detected":
        return (
            f"Paywall phrase detected: {w['matched_phrase']!r}. "
            f"Try --browser-cookies to use an authenticated session."
        )
    if code == "no_title_extracted":
        return (
            "No title extracted. Metadata chain (JSON-LD -> OpenGraph -> "
            "<meta>) produced nothing. Extraction may be incomplete."
        )
    if code == "extraction_returned_no_content":
        # Reserved-but-unused in v1.1 (see KNOWN_CODES comment in
        # structured_warnings.py). No v1.1 call site emits this; the
        # ExtractError hard-fail path covers the case. Branch retained
        # so a future soft-fail conversion has the translation already.
        return (
            "trafilatura returned no content -- the page may be empty, "
            "JavaScript-rendered (SPA), or structured in a way the extractor "
            "does not recognize."
        )
    # Defensive: unknown structured code falls back to a generic representation
    # so we never silently drop a warning. The "BUG:" prefix flags the
    # missing translation loudly when a human reads stderr. DO NOT soften
    # this prefix or downgrade to a quieter form -- it is the only signal
    # that a structured-warning code is in KNOWN_CODES but missing a
    # translation branch here, and dropping it makes the gap silent.
    return f"BUG: untranslated structured warning code {code!r}: {w}"


def build_success_envelope(
    *,
    output_path: str,
    metadata_payload: dict[str, Any],
    legacy_warnings: list[str],
    structured_warnings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Construct the JSON success envelope. Adds the v1.1 fields
    `extraction_warnings` (structured) and `complete` (bool) alongside the
    existing `warnings: [str]` for backwards compat.

    `complete` is True iff no structured warning has recovery_action='escalate'.
    """
    has_escalate = any(
        w.get("recovery_action") == "escalate" for w in structured_warnings
    )
    return {
        "status": "success",
        "output_path": output_path,
        "metadata": metadata_payload,
        "warnings": legacy_warnings,
        "extraction_warnings": structured_warnings,
        "complete": not has_escalate,
        "error": None,
    }


# ---------------------------------------------------------------------------
# Frontmatter construction (typed → YAML, single source of truth)
# ---------------------------------------------------------------------------


# YAML reserved keywords that must be quoted to avoid parser misinterpretation.
YAML_KEYWORDS = frozenset({
    "null", "Null", "NULL", "~",
    "true", "True", "TRUE", "false", "False", "FALSE",
    "yes", "Yes", "YES", "no", "No", "NO",
    "on", "On", "ON", "off", "Off", "OFF",
})

# YAML flow indicators — if a string starts with any of these it may be
# parsed as something other than a plain scalar.
YAML_FLOW_LEADING = "-?:,[]{}#&*!|>'\"%@`"


# Order of metadata fields in emitted frontmatter. Identity first
# (title/author/date), then provenance (url/hostname/sitename),
# then descriptive (description/categories/tags/language).
ORDERED_META_KEYS: tuple[str, ...] = (
    "title",
    "author",
    "date",
    "url",
    "hostname",
    "sitename",
    "description",
    "categories",
    "tags",
    "language",
)


def _yaml_scalar(value: Any) -> str:
    """Emit a value as a YAML scalar, quoting when needed for safe round-trip.

    Quotes any string that:
      - is empty or has leading/trailing whitespace
      - matches a reserved YAML keyword (null/true/false/yes/no/on/off/~)
      - starts with a YAML flow indicator (-?:,[]{}#&*!|>'"%@`)
      - contains ": " (mapping-ambiguous) or " #" (comment-ambiguous)
      - contains a newline

    Lists and tuples are emitted as YAML flow sequences with each element
    independently passed back through _yaml_scalar() for correct quoting.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        if not value:
            return "[]"
        items = ", ".join(_yaml_scalar(v) for v in value)
        return f"[{items}]"

    s = str(value)

    # Any colon followed by whitespace OR end-of-string is a YAML flow
    # mapping boundary and must be quoted. This catches both "has: colon"
    # (colon mid-string) and "ends with colon:" (colon at end) forms.
    has_colon_ambiguity = False
    if ":" in s:
        for i, ch in enumerate(s):
            if ch == ":":
                next_char = s[i + 1] if i + 1 < len(s) else ""
                if next_char == "" or next_char.isspace():
                    has_colon_ambiguity = True
                    break

    # Newlines need double-quoted form because YAML's single-quoted form
    # folds newlines to spaces. Double-quoted form supports \n escape.
    if "\n" in s:
        escaped = (
            s.replace("\\", "\\\\")
             .replace('"', '\\"')
             .replace("\n", "\\n")
             .replace("\t", "\\t")
             .replace("\r", "\\r")
        )
        return '"' + escaped + '"'

    needs_quote = (
        s == ""
        or s != s.strip()
        or s in YAML_KEYWORDS
        or s[0] in YAML_FLOW_LEADING
        or has_colon_ambiguity
        or " #" in s
    )
    if needs_quote:
        # Single-quoted form; escape embedded single quotes by doubling.
        return "'" + s.replace("'", "''") + "'"
    return s


def build_frontmatter(metadata: Any, extras: dict[str, Any]) -> str:
    """Build a YAML frontmatter block from typed metadata + extras.

    Emits a fenced YAML block of the form:

        ---
        title: ...
        author: ...
        ...extras...
        ---

    Every value passes through _yaml_scalar() for safe quoting. Keys in
    `extras` override same-named keys in `metadata`. Null / empty values
    are omitted. Returns a string ending with "---\\n" (ready to prepend
    to the body).
    """
    lines: list[str] = ["---"]

    if metadata is not None:
        for key in ORDERED_META_KEYS:
            if key in extras:
                # Extras override metadata with the same key
                continue
            value = getattr(metadata, key, None)
            if value is None or value == "" or value == []:
                continue
            lines.append(f"{key}: {_yaml_scalar(value)}")

    for key, value in extras.items():
        if value is None:
            continue
        lines.append(f"{key}: {_yaml_scalar(value)}")

    lines.append("---")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Filename slugification
# ---------------------------------------------------------------------------


WINDOWS_RESERVED_NAMES = frozenset({
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
})


def safe_filename(title: str | None, date: str | None = None, max_len: int = 80) -> str:
    """Convert a title to a cross-platform-safe markdown filename."""
    if not title:
        title = "untitled"

    normalized = unicodedata.normalize("NFKD", title)
    ascii_only = "".join(c for c in normalized if not unicodedata.combining(c))
    lowered = ascii_only.lower()
    slug = re.sub(r"[^a-z0-9]+", "-", lowered)
    slug = re.sub(r"-+", "-", slug).strip("-")
    slug = slug[:max_len].strip("-")

    if slug.upper() in WINDOWS_RESERVED_NAMES:
        slug = f"{slug}-file"
    if not slug:
        slug = "untitled"

    if date:
        return f"{date}-{slug}.md"
    return f"{slug}.md"


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def resolve_unique_path(
    directory: Path, filename: str, *, overwrite: bool = False
) -> Path:
    """Return a path in `directory` for `filename`.

    If `overwrite=True`, always returns `directory / filename` even if it
    exists (caller will write over the existing file).

    If `overwrite=False` (default), returns a non-colliding path by
    appending -2, -3, ... to the stem until a free name is found.
    """
    candidate = directory / filename
    if overwrite or not candidate.exists():
        return candidate
    stem = candidate.stem
    suffix = candidate.suffix
    counter = 2
    while True:
        candidate = directory / f"{stem}-{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def word_count(body: str) -> int:
    """Rough word count of an article body. Caller passes body only, no frontmatter."""
    return len(re.findall(r"\b\w+\b", body))


def compute_content_hash(body: str) -> str:
    """SHA256 hex digest of the article body (caller MUST pass body only,
    no frontmatter). Used for re-fetch dedup -- same body -> same hash."""
    import hashlib
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def compute_exit_code(
    *,
    structured_warnings: list[dict[str, Any]],
    strict: bool,
) -> int:
    """Return the success-path exit code given the structured-warning list.

    Returns 8 (EXIT_STRICT_PARTIAL) if --strict is set AND any structured
    warning has recovery_action='escalate'. Returns 0 otherwise. Does NOT
    handle hard errors (UserError, FetchError, etc.) -- those return their
    own exit codes earlier in run().
    """
    if strict:
        for w in structured_warnings:
            if w.get("recovery_action") == "escalate":
                return EXIT_STRICT_PARTIAL
    return EXIT_OK


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="url_to_markdown",
        description="Transcribe a web article to a markdown file with YAML frontmatter.",
    )
    p.add_argument("url", help="URL of the article to transcribe")
    p.add_argument(
        "--out", "-o",
        type=Path,
        default=Path.cwd(),
        help="Output directory (default: current working directory)",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit a structured JSON envelope to stdout (for agent invocation)",
    )
    p.add_argument(
        "--allow-private",
        action="store_true",
        help="Permit fetches of private / loopback / link-local addresses. "
             "Cloud metadata endpoints remain blocked regardless.",
    )
    cookie_group = p.add_mutually_exclusive_group()
    cookie_group.add_argument(
        "--browser-cookies",
        choices=["chrome", "firefox", "edge", "brave", "opera"],
        help="Load cookies from the named browser, scoped to the target "
             "hostname, to support authenticated fetches (e.g. paywalled "
             "subscription content). Browser may need to be closed.",
    )
    cookie_group.add_argument(
        "--cookies-from-env",
        metavar="VAR",
        help="Load cookies from the named env var (raw `Cookie:` header value "
             "such as 'session_id=abc; user_token=xyz'). Decouples from the "
             "live browser's locked SQLite store. Mutually exclusive with "
             "--browser-cookies. Note: cookies sent on every redirect hop; "
             "scope to the target host externally before exporting if that "
             "matters.",
    )
    p.add_argument(
        "--playwright",
        action="store_true",
        help="(v1: informational only) Signal that the caller is willing to "
             "escalate to a headless browser on SPA-detection failures. "
             "Automatic Playwright escalation is not implemented in v1; this "
             "flag reserves the CLI surface and is logged as a hint.",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Per-request timeout in seconds (default: 30)",
    )
    p.add_argument(
        "--max-redirects",
        type=int,
        default=5,
        help="Maximum redirect hops to follow (default: 5)",
    )
    p.add_argument(
        "--impersonate",
        default="chrome124",
        help="curl_cffi browser impersonation profile (default: chrome124)",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="Promote any escalate-class extraction warning (short body / SPA / "
             "no content) to exit code 8. The output file is still written; "
             "the exit code signals 'partial result' to CI/agent pipelines.",
    )
    p.add_argument(
        "--overwrite",
        action="store_true",
        help="If the output path already exists, overwrite it instead of "
             "creating a `-2`/`-3`-suffixed sibling. Default is to uniquify "
             "(safer for re-fetch workflows that should not stomp prior runs).",
    )
    return p


def emit_result(args: argparse.Namespace, payload: dict[str, Any], output_path: Path | None) -> None:
    """Write the result to stdout in the requested mode."""
    if args.json:
        print(json.dumps(payload, indent=2, default=str))
        return

    status = payload.get("status")
    if status == "success":
        meta = payload.get("metadata", {})
        print(f"OK  {output_path}")
        print(f"    title:      {meta.get('title', '(none)')}")
        print(f"    author:     {meta.get('author', '(none)')}")
        print(f"    published:  {meta.get('published', '(none)')}")
        print(f"    words:      {meta.get('word_count', 0)}")
        print(f"    http:       {meta.get('http_status')} "
              f"({meta.get('hops', 1)} hop{'s' if meta.get('hops', 1) != 1 else ''})")
        warnings = payload.get("warnings") or []
        for w in warnings:
            print(f"    WARNING:    {w}", file=sys.stderr)
    else:
        err = payload.get("error", {}) or {}
        print(
            f"ERROR {err.get('type', 'Unknown')}: {err.get('message', '')}",
            file=sys.stderr,
        )


def run(args: argparse.Namespace) -> int:
    # ----- URL validation up front -----
    parsed = urlparse(args.url)
    if not parsed.scheme or not parsed.hostname:
        emit_result(args, {
            "status": "error",
            "error": {
                "type": "UserError",
                "message": f"URL is malformed: {args.url!r}. Expected a full URL with scheme and host.",
                "exit_code": EXIT_USER_ERROR,
            },
        }, None)
        return EXIT_USER_ERROR

    # ----- Cookies, if requested (mutually exclusive sources via argparse) -----
    cookies = None
    if args.browser_cookies:
        try:
            cookies = load_browser_cookies(args.browser_cookies, parsed.hostname)
        except FetchError as exc:
            emit_result(args, {
                "status": "error",
                "error": {
                    "type": "CookieError",
                    "message": str(exc),
                    "exit_code": EXIT_FETCH_ERROR,
                },
            }, None)
            return EXIT_FETCH_ERROR
    elif args.cookies_from_env:
        try:
            cookies = load_env_cookies(args.cookies_from_env)
        except CookieError as exc:
            emit_result(args, {
                "status": "error",
                "error": {
                    "type": "CookieError",
                    "message": str(exc),
                    "exit_code": EXIT_FETCH_ERROR,
                },
            }, None)
            return EXIT_FETCH_ERROR

    # ----- Fetch with SSRF revalidation on every hop -----
    try:
        response, final_url, visited = fetch_with_revalidation(
            args.url,
            allow_private=args.allow_private,
            timeout=args.timeout,
            max_redirects=args.max_redirects,
            cookies=cookies,
            impersonate=args.impersonate,
        )
    except SSRFError as exc:
        emit_result(args, {
            "status": "error",
            "error": {
                "type": "SSRFError",
                "message": str(exc),
                "exit_code": EXIT_SSRF_VIOLATION,
            },
        }, None)
        return EXIT_SSRF_VIOLATION
    except FetchError as exc:
        emit_result(args, {
            "status": "error",
            "error": {
                "type": "FetchError",
                "message": str(exc),
                "exit_code": EXIT_FETCH_ERROR,
            },
        }, None)
        return EXIT_FETCH_ERROR

    # ----- Content-type dispatch -----
    content_type = response.headers.get("content-type") or response.headers.get("Content-Type") or ""
    kind = classify_content_type(content_type)

    if kind == "pdf":
        emit_result(args, {
            "status": "error",
            "error": {
                "type": "UnsupportedContentType",
                "message": (
                    f"Content-Type is application/pdf. PDF transcription is not "
                    f"supported in v1. Use a PDF-specific tool (pdftotext, "
                    f"pymupdf, pdfminer.six) to extract text."
                ),
                "exit_code": EXIT_EXTRACT_ERROR,
            },
        }, None)
        return EXIT_EXTRACT_ERROR

    if kind == "feed":
        emit_result(args, {
            "status": "error",
            "error": {
                "type": "UnsupportedContentType",
                "message": (
                    f"Content-Type {content_type!r} looks like an RSS/Atom feed. "
                    f"Feed parsing is not supported in v1. Use a feed reader or "
                    f"feedparser library."
                ),
                "exit_code": EXIT_EXTRACT_ERROR,
            },
        }, None)
        return EXIT_EXTRACT_ERROR

    if kind == "binary":
        emit_result(args, {
            "status": "error",
            "error": {
                "type": "UnsupportedContentType",
                "message": (
                    f"Content-Type {content_type!r} is not a supported text "
                    f"format. Expected HTML, plain text, markdown, or a feed."
                ),
                "exit_code": EXIT_EXTRACT_ERROR,
            },
        }, None)
        return EXIT_EXTRACT_ERROR

    # ----- Extract (or pass through plain text) -----
    structured_warnings: list[dict[str, Any]] = []

    if kind == "text":
        # text/plain or text/markdown — skip extraction, treat as already-clean
        # content. Gives us free support for raw.githubusercontent.com URLs,
        # gist raw URLs, and hand-served markdown files.
        body = response.text
        metadata = None
        extraction_method = "text_passthrough"
        title_hint = parsed.path.rsplit("/", 1)[-1] or parsed.hostname
    else:
        try:
            extraction_result = extract_via_dispatch(response.text, url=final_url)
        except ExtractError as exc:
            emit_result(args, {
                "status": "error",
                "error": {
                    "type": "ExtractError",
                    "message": str(exc),
                    "exit_code": EXIT_EXTRACT_ERROR,
                },
            }, None)
            return EXIT_EXTRACT_ERROR

        body = extraction_result.body
        metadata = extraction_result.metadata
        extraction_method = extraction_result.extraction_method
        structured_warnings.extend(extraction_result.warnings)  # extractor-internal warnings
        structured_warnings.extend(
            detect_quality_warnings_on_body(body, len(response.text), metadata)
        )
        title_hint = getattr(metadata, "title", None) if metadata else None

    # ----- Build frontmatter from typed metadata + extras -----
    fetched_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    extras: dict[str, Any] = {
        "source_url": args.url,
        "fetched": fetched_at,
        "http_status": response.status_code,
    }
    if final_url != args.url:
        extras["final_url"] = final_url
    if len(visited) > 1:
        extras["redirect_hops"] = len(visited) - 1

    wc = word_count(body)
    content_hash = compute_content_hash(body)
    extras["word_count"] = wc
    extras["content_hash_sha256"] = content_hash

    frontmatter = build_frontmatter(metadata, extras)
    markdown = frontmatter + body

    # ----- Filename & write -----
    date_prefix = None
    if metadata is not None:
        raw_date = getattr(metadata, "date", None)
        if raw_date and re.match(r"^\d{4}-\d{2}-\d{2}", str(raw_date)):
            date_prefix = str(raw_date)[:10]

    filename = safe_filename(title_hint, date=date_prefix)

    out_dir = args.out.expanduser().resolve()
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        emit_result(args, {
            "status": "error",
            "error": {
                "type": "OutputError",
                "message": f"Could not create output directory {out_dir}: {exc}",
                "exit_code": EXIT_USER_ERROR,
            },
        }, None)
        return EXIT_USER_ERROR

    out_path = resolve_unique_path(out_dir, filename, overwrite=args.overwrite)
    out_path.write_text(markdown, encoding="utf-8")

    # ----- Emit success -----
    meta_payload: dict[str, Any] = {
        "title": getattr(metadata, "title", None) if metadata else None,
        "author": getattr(metadata, "author", None) if metadata else None,
        "published": str(getattr(metadata, "date", None)) if metadata else None,
        "source_url": args.url,
        "final_url": final_url,
        "fetched": fetched_at,
        "word_count": wc,
        "content_type": content_type,
        "http_status": response.status_code,
        "hops": len(visited),
        "extraction_method": extraction_method,
        "content_hash_sha256": content_hash,
    }
    # Build legacy_warnings FROM structured_warnings first (every structured
    # warning gets a translation, regardless of severity, for backwards compat).
    legacy_warnings = [
        format_structured_warning_as_string(w) for w in structured_warnings
    ]
    # --playwright is a CLI-surface-reserve message, not a content-extraction
    # signal; it deliberately does NOT get a structured-warning code, and it
    # MUST appear only in the legacy strings list (agents reading the
    # structured field will not see it).
    if args.playwright:
        legacy_warnings.append(
            "--playwright flag was set but automatic escalation is not "
            "implemented in v1. Fetch proceeded via curl_cffi as usual."
        )

    envelope = build_success_envelope(
        output_path=str(out_path),
        metadata_payload=meta_payload,
        legacy_warnings=legacy_warnings,
        structured_warnings=structured_warnings,
    )
    emit_result(args, envelope, out_path)

    return compute_exit_code(
        structured_warnings=structured_warnings,
        strict=args.strict,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
