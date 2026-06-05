# HTML performance module: Web fonts
> Load when the page uses web fonts — `@font-face`, a `<link>` to Google Fonts / a font CDN, or `.woff2`/`.woff`/`.ttf` assets — see the module map in `../html.md`. Core HTML lanes + Rendering-path notes live in `../html.md`; this file is the Web fonts lens only.

## Web fonts

> Scope: `@font-face` declarations, font CDN `<link>`s, and the WOFF2/WOFF/TTF assets they
> reference. The recurring theme is that web fonts are discovered late, block or delay text
> rendering by default, and cause layout shift when the fallback and the webfont have different
> metrics. The corrective levers are: make text visible immediately (`font-display`), pull the
> critical font earlier (preload), eliminate the swap-shift by matching fallback metrics
> (`size-adjust` / metric overrides), and ship only the bytes the page actually needs (WOFF2,
> subsetting, no unused weights).

- **`font-display` default hides text until the font loads (FOIT)**: the browser default for
  `@font-face` is effectively `block` — text is invisible for up to ~3 s while the font
  downloads, directly harming FCP and perceived LCP (see the Rendering-path notes in
  `../html.md`). `font-display: swap` shows the fallback immediately and swaps on load (FOUT —
  text is readable, shift may occur); `font-display: optional` uses the webfont only if it
  arrives within a short window and suppresses the swap entirely, eliminating both the block and
  the layout shift at the cost of the webfont being skipped on slow connections. Pick per use
  case: `swap` for body copy where readability matters most, `optional` for decorative fonts
  where the webfont is a cosmetic enhancement (verify against the currency brief for your
  version).

- **Fonts are discovered late — the critical font should be preloaded**: a `@font-face` URL is
  embedded in a stylesheet, so the browser cannot fetch the font until it has downloaded,
  parsed, and applied the CSS and determined which rules are used — pushing the fetch well into
  the waterfall. A `<link rel="preload" as="font" type="font/woff2" crossorigin>` for the
  one or two fonts used above the fold moves the fetch to the preload scanner and removes that
  cascade delay. Over-preloading (every weight, every style) competes with higher-priority
  resources (see the payload-startup lane in `../html.md`) and can hurt LCP; limit preloads
  to the fonts that gate above-the-fold text render (verify against the currency brief for
  your version).

- **Layout shift on font swap from mismatched fallback metrics**: when a webfont swaps in with
  different glyph widths, ascenders, or line heights than the fallback, text reflows — directly
  registering as CLS (see the Rendering-path notes in `../html.md`). `size-adjust`,
  `ascent-override`, `descent-override`, and `line-gap-override` on a `@font-face` fallback
  declaration tune the fallback font's metrics to closely match the webfont so the swap causes
  little or no reflow. The shift is often large enough (0.1 + CLS) to fail Core Web Vitals on
  its own; metric overrides are one of the few reliable ways to eliminate it without removing
  the webfont (verify against the currency brief for your version).

- **Serving TTF / OTF / WOFF where WOFF2 would do**: WOFF2 uses Brotli compression
  internally and is ~30% smaller than WOFF and significantly smaller than TTF/OTF; all modern
  browsers support it. Shipping uncompressed or less-compressed formats wastes bytes on every
  font load. Check `@font-face` `src` order: the first matching `format()` hint the browser
  accepts wins — if TTF is listed before WOFF2 a modern browser will take the larger file.
  WOFF/TTF/EOT/SVG font fallbacks are only relevant for legacy targets that should be a
  deliberate decision, not an accidental default (verify baseline browser support for your
  target audience).

- **Shipping a full character set when only a subset is used**: a single font file can be
  300–600 KB when it covers Latin Extended, Cyrillic, Greek, CJK, and symbol ranges — most of
  which the page never renders. `unicode-range` in `@font-face` splits a font into range
  subsets so the browser fetches only the slices whose characters actually appear on the page.
  Build-time subsetting (pyftsubset, glyphhanger, or similar) further reduces file size by
  removing glyphs not in the design's character set before the file is served. Look for a
  single monolithic `@font-face` with no `unicode-range` on a page that serves a single
  language.

- **Loading multiple static weight files where a variable font would be fewer requests**: a
  design using four weights (regular, medium, semibold, bold) and their italic variants loads
  up to eight separate font files — eight requests, eight round trips. A single variable font
  file covering the same axes is fewer requests and often smaller total payload when multiple
  weights are actually rendered. The calculus reverses when only one weight is used: a static
  subset of that weight is smaller than the variable font, which must encode the full variation
  data. Audit which `font-weight` values `getComputedStyle` resolves to on rendered text before
  deciding (verify against the currency brief for your version).

- **Third-party font hosting adds a cross-origin connection to the critical path**: a Google
  Fonts `<link>` or other font CDN requires a DNS lookup, TCP handshake, and TLS negotiation
  to a new origin before any font byte can be received — this is on the critical path for
  above-the-fold text. `<link rel="preconnect">` to the font origin warms the connection
  earlier, reducing the penalty; `<link rel="dns-prefetch">` is a lighter fallback. Self-hosting
  WOFF2 from the same origin removes the cross-origin cost entirely, enables same-origin caching
  headers, and avoids third-party availability and privacy dependencies. If a font CDN is
  unavoidable, preconnect is a low-effort partial mitigation, not a substitute (verify
  against the currency brief for your version).

- **Loading weights and styles the design never renders**: every `@font-face` block with a
  distinct `font-weight` or `font-style` value is a separate file and a separate network
  request — even if no element on the page ever matches that combination. Audit the stylesheet
  for declared `@font-face` blocks versus the `font-weight`/`font-style` values that
  `getComputedStyle` actually resolves to on rendered elements; drop declarations for
  unmatched combinations. Where the design allows it, a system-font stack (`system-ui`,
  platform defaults) carries zero network cost and renders immediately — worth considering for
  body copy on performance-constrained targets.
