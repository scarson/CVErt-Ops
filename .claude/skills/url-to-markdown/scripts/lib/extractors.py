"""Pluggable extractor dispatch + BS4 primitives for url-to-markdown.

The skill defaults to trafilatura for body extraction (see
extract_generic_trafilatura). Future site-specific extractors can register
via register_extractor(hostname, fn); dispatch(url) returns the registered
extractor or extract_generic_trafilatura for unknown hostnames.

The BS4 primitives (parse_html / extract_images / html_to_markdown) are
exposed for use by future site-specific extractors when trafilatura's
heuristics strip content that should be preserved (forum replies, KB
articles in non-standard layouts, etc.). They have no callers in v1.1 of
the skill -- they're a deliberate extension seam, not dead code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import urljoin, urlparse


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class ExtractResult:
    """Uniform return shape for any registered extractor.

    `body` -- markdown body (no frontmatter; main script wraps).
    `metadata` -- trafilatura metadata object, or any object with .title /
      .author / .date / .description / .url / .hostname / .sitename /
      .categories / .tags / .language attributes (duck-typed).
    `extraction_method` -- short string identifying which path produced this
      result. v1.1 emits "generic_trafilatura"; future extractors emit their
      own names. Surfaced in the JSON envelope as the same field.
    `warnings` -- structured warnings emitted DURING extraction (not the
      post-extraction quality warnings, which the main script generates).
    `images` -- DOM-order list of {src, alt, width, height} dicts. Empty
      in v1.1 because trafilatura's extracted markdown already preserves
      <img> tags. Reserved for site-specific extractors that produce
      structured image inventories.
    """

    body: str
    metadata: Any
    extraction_method: str
    warnings: list[dict[str, Any]] = field(default_factory=list)
    images: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Dispatch registry
# ---------------------------------------------------------------------------


_REGISTRY: dict[str, Callable[..., ExtractResult]] = {}


def register_extractor(
    hostname: str, fn: Callable[..., ExtractResult]
) -> None:
    """Register a site-specific extractor for the given hostname.

    The hostname is matched case-insensitively. Re-registering the same
    hostname overwrites the prior registration (deliberate -- allows the
    skill to be re-imported in tests / agent sessions).
    """
    _REGISTRY[hostname.lower()] = fn


def dispatch(url: str) -> Callable[..., ExtractResult]:
    """Return the extractor for `url`'s host, or extract_generic_trafilatura.

    Falls back to the generic extractor for any URL whose hostname is not
    registered. The registry starts empty in v1.1; everything dispatches
    to the generic path.
    """
    host = (urlparse(url).hostname or "").lower()
    return _REGISTRY.get(host, extract_generic_trafilatura)


def _RESET_REGISTRY_FOR_TESTS() -> None:
    """Test-only: clear the registry between tests so they're isolated."""
    _REGISTRY.clear()


# ---------------------------------------------------------------------------
# Generic trafilatura extractor (the default path)
# ---------------------------------------------------------------------------


def extract_generic_trafilatura(html: str, *, url: str) -> ExtractResult:
    """Generic extractor: run trafilatura on the page, return ExtractResult.

    This is the v1.0 extraction path lifted into the new shape. The main
    script's run() loop calls dispatch(url)(response.text, url=final_url)
    and uses the returned ExtractResult.body / .metadata directly.

    Raises the existing url_to_markdown.ExtractError if trafilatura returns
    no content -- the main script catches that and emits exit code 3 as it
    does today.

    Why ExtractError is imported locally inside this function rather than
    at module top:
      url_to_markdown.py imports `extract_via_dispatch` from this module
      at its own top level. If this module imported ExtractError at the
      top level, we'd have a circular-import scenario at module-load
      time. Deferring the import to call time avoids the cycle because
      by the time any extractor is dispatched, url_to_markdown.py is
      fully loaded. ExtractError stays defined in url_to_markdown.py
      (do NOT move it) so existing call sites continue to find it.
    """
    import trafilatura
    from url_to_markdown import ExtractError  # noqa: E402 — deliberate local import; see docstring

    body = trafilatura.extract(
        html,
        url=url,
        output_format="markdown",
        with_metadata=False,
        include_comments=False,
        include_tables=True,
        include_links=True,
        include_formatting=True,
        favor_precision=True,
    )
    if body is None or not body.strip():
        raise ExtractError(
            "trafilatura returned no content -- the page may be empty, "
            "JavaScript-rendered (SPA), or structured in a way the extractor "
            "does not recognize. If the page requires JS rendering, escalate "
            "to a headless browser."
        )
    meta = trafilatura.extract_metadata(html)
    return ExtractResult(
        body=body,
        metadata=meta,
        extraction_method="generic_trafilatura",
    )


# ---------------------------------------------------------------------------
# BS4 primitives -- for future site-specific extractors
# ---------------------------------------------------------------------------


def parse_html(html: str) -> Any:
    """Parse HTML with bs4 + lxml for speed.

    lxml is tolerant of malformed input (unclosed tags, mixed content).
    Empty/whitespace-only input yields an empty document -- soup.find()
    returns None rather than raising.
    """
    from bs4 import BeautifulSoup
    return BeautifulSoup(html or "", "lxml")


def extract_images(soup: Any, *, base_url: str) -> list[dict[str, Any]]:
    """Extract <img> elements with src/alt/width/height in DOM order.

    Filters:
    - <img> without src or with empty/whitespace-only src is excluded.
    - data: / file: / javascript: / mailto: schemes excluded; only
      http(s) sources are emitted.

    Field shape:
    - src -- resolved absolute URL (whitespace-trimmed).
    - alt -- empty string (not None) when absent, for downstream str-safe ops.
    - width / height -- int when parseable, else None.

    DOM order is preserved.
    """
    images: list[dict[str, Any]] = []
    for img in soup.find_all("img"):
        src = (img.get("src") or "").strip()
        if not src:
            continue
        resolved = urljoin(base_url, src)
        lowered = resolved.lower()
        if not (lowered.startswith("http://") or lowered.startswith("https://")):
            continue
        images.append({
            "src": resolved,
            "alt": img.get("alt") or "",
            "width": _to_int(img.get("width")),
            "height": _to_int(img.get("height")),
        })
    return images


_HEADING_TAGS = {"h1", "h2", "h3", "h4", "h5", "h6"}
_INLINE_BOLD_TAGS = {"strong", "b"}
_INLINE_ITALIC_TAGS = {"em", "i"}
_WHITESPACE = re.compile(r"\s+")


def html_to_markdown(node: Any) -> str:
    """Convert a bs4 element (or HTML string) to a markdown body.

    Handles ONLY: paragraphs, headings (h1-h6), <br>, <strong>/<b> bold,
    <em>/<i> italic, inline <code>, <pre>/<pre><code> fenced blocks,
    <a href> links, <img>, <ul>/<ol> with <li>, <blockquote>, <hr>.
    Drops <script>/<style>/<noscript> entirely. Unknown tags pass through
    by recursing into children.

    DO NOT extend the tag set beyond this list in v1.1. Rationale:
    trafilatura already produces high-quality markdown across the full
    tag space for v1.1's only caller (extract_generic_trafilatura).
    These BS4 primitives exist as ALTERNATIVE building blocks for future
    site-specific extractors where trafilatura strips content it
    shouldn't (forum threads, structured KB articles); they are not
    intended as a trafilatura replacement and should not grow toward
    feature parity with it. Adding <table> / <dl> / <figure> support
    here would be a separate plan with its own rationale and test
    coverage.

    `node` may be a BeautifulSoup doc, a Tag, or an HTML string.
    """
    if isinstance(node, str):
        node = parse_html(node)
    out = _convert(node).strip("\n")
    return re.sub(r"\n{3,}", "\n\n", out)


def _convert(node: Any) -> str:
    from bs4 import NavigableString, Tag
    if isinstance(node, NavigableString):
        return _WHITESPACE.sub(" ", str(node))
    if not isinstance(node, Tag):
        return "".join(_convert(c) for c in getattr(node, "children", []))

    name = node.name.lower()

    if name in _HEADING_TAGS:
        level = int(name[1])
        text = "".join(_convert(c) for c in node.children).strip()
        return f"\n\n{'#' * level} {text}\n\n"

    if name == "p":
        text = "".join(_convert(c) for c in node.children).strip()
        return f"\n\n{text}\n\n" if text else ""

    if name == "br":
        return "\n"

    if name in _INLINE_BOLD_TAGS:
        text = "".join(_convert(c) for c in node.children).strip()
        return f"**{text}**" if text else ""

    if name in _INLINE_ITALIC_TAGS:
        text = "".join(_convert(c) for c in node.children).strip()
        return f"*{text}*" if text else ""

    if name == "code":
        parent = node.parent
        if parent is not None and parent.name and parent.name.lower() == "pre":
            return "".join(_convert(c) for c in node.children)
        text = "".join(_convert(c) for c in node.children).strip()
        return f"`{text}`" if text else ""

    if name == "pre":
        text = node.get_text()
        return f"\n\n```\n{text.strip(chr(10))}\n```\n\n"

    if name == "a":
        href = (node.get("href") or "").strip()
        text = "".join(_convert(c) for c in node.children).strip()
        if not text:
            text = href
        if not href:
            return text
        return f"[{text}]({href})"

    if name == "img":
        src = (node.get("src") or "").strip()
        alt = (node.get("alt") or "").strip()
        return f"![{alt}]({src})" if src else ""

    if name == "ul":
        items = [
            _convert_li(c, ordered=False)
            for c in node.children
            if isinstance(c, Tag) and c.name and c.name.lower() == "li"
        ]
        return "\n\n" + "\n".join(items) + "\n\n" if items else ""

    if name == "ol":
        lis = [
            c for c in node.children
            if isinstance(c, Tag) and c.name and c.name.lower() == "li"
        ]
        items = [_convert_li(c, ordered=True, index=i + 1) for i, c in enumerate(lis)]
        return "\n\n" + "\n".join(items) + "\n\n" if items else ""

    if name == "li":
        return _convert_li(node, ordered=False)

    if name == "blockquote":
        inner = "".join(_convert(c) for c in node.children).strip()
        if not inner:
            return ""
        quoted = "\n".join(
            f"> {line}" if line else ">" for line in inner.split("\n")
        )
        return f"\n\n{quoted}\n\n"

    if name == "hr":
        return "\n\n---\n\n"

    if name in {"script", "style", "noscript"}:
        return ""

    return "".join(_convert(c) for c in node.children)


def _convert_li(node: Any, *, ordered: bool, index: int = 1) -> str:
    inner = "".join(_convert(c) for c in node.children).strip()
    prefix = f"{index}. " if ordered else "- "
    return f"{prefix}{inner}"


def _to_int(value: Any) -> Optional[int]:
    """Parse an HTML attribute as int; tolerate suffix-bearing values."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
