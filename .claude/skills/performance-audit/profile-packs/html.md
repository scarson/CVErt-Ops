# Profile Pack: HTML (plain documents & the rendering path)

A **companion** pack for **plain HTML / the document layer** — the performance of the markup the
browser receives and renders, *independent of any JS framework*. It loads **alongside** whatever
backend emits the HTML (Django/Jinja, Rails/ERB, Laravel/Blade, .NET Razor, Express/Nunjucks, PHP, or a
static-site generator), and also applies to the *rendered HTML output* of JS frameworks. It is about
the **document, its subresources, and the critical rendering path** — **not** the JS bundle: for
bundler concerns (tree-shaking, code-splitting, transpile target) see the JS/TS `bundling-build` module
when a bundler is in use; this pack is the markup/document/delivery/rendering layer that exists even
with little or no JavaScript.

**Content-detected** (`.html`/`.htm`, server templates — `*.erb`, `*.jinja`/`*.j2`, `*.twig`,
`*.blade.php`, `*.cshtml`/Razor, `*.njk` — static-site generators, `<!DOCTYPE html>` markup). Signals
are durable and browser-agnostic; concrete baseline/feature claims are tagged "(verify against the
currency brief for your version)" because browser support and defaults move. Deep **image** and **font**
lenses load as modules — see the map at the bottom.

---

## Algorithmic / rendering & layout cost (lane `algorithmic`)
- **A very large DOM makes every style recalc and layout pass more expensive** — cost scales with node
  count, so a page that emits tens of thousands of nodes (usually an un-paginated server-side loop over
  rows) is slow to lay out and heavy in memory regardless of CSS. Paginate, virtualize, or summarize
  server-side rather than shipping the whole set as markup.
- **CSS that forces wide style recalc**: very large stylesheets re-matched against a large DOM, and
  broad/deeply-descendant or universal (`* {}`) selectors, make style recalculation a measurable cost
  on big pages — keep selectors shallow and stylesheets scoped to what the page uses.
- **Everything laid out up front on a long page**: `content-visibility: auto` (with
  `contain-intrinsic-size` so the scrollbar stays honest) lets the browser skip layout/paint for
  off-screen sections until they approach the viewport — a large win on long documents (verify against
  the currency brief for your version).
- **Animating layout- or paint-triggering CSS properties**: animating `top`/`left`/`width`/`height`/
  `margin` re-runs layout every frame, and `box-shadow`/`background` re-runs paint — both jank. Animate
  the **compositor-only** properties `transform` and `opacity`, which the GPU handles without layout or
  paint. Promote an element to its own layer (`will-change`, or `transform: translateZ(0)`) *sparingly*
  — each layer costs memory, so promoting many elements backfires (verify against the currency brief
  for your version).

## Memory & document size (lane `memory`)
- **DOM node count is itself a cost**: every element retains memory and slows traversal/style/layout;
  thousands of nodes from un-paginated loops, deeply wrapped markup, or builder-generated `<div>` soup
  is the signal (see the algorithmic lane for the layout-cost side).
- **Heavy inline payloads in the document**: a large inline `<script>`/`<style>`, a big `data:` URI, or
  a large inline JSON/state blob bloats the HTML, cannot be cached separately from the document, and
  delays parse — weigh inlining (saves a request, no separate caching) against an external, cacheable
  file.
- **Bytes shipped the page never uses**: large `display:none`/hidden subtrees rendered server-side
  "just in case", dead or commented-out markup, and unused inline CSS all ship and parse for nothing —
  emit them lazily or not at all.

## Data access & I/O — delivery (lane `data-access`)
- **Text resources served without compression**: HTML/CSS/JS/SVG without Brotli (or gzip) at the
  server/CDN is a large, cheap first-load win — confirm the response `Content-Encoding` (verify against
  the currency brief for your version).
- **Caching not set up for the asset's lifetime**: fingerprinted static assets (CSS/JS/images) want a
  long-lived `Cache-Control: immutable`; the HTML document usually wants short/`no-cache` with
  revalidation (`ETag`/`Last-Modified`). Re-downloading unchanged assets every visit is the signal.
- **Critical-path request count and obsolete bundling**: under HTTP/2/3 many small multiplexed files
  are fine and improve caching granularity, so **domain sharding and aggressive concatenation/spriting
  are counter-productive** on a modern protocol — but uncached third-party requests and unbounded
  blocking requests still cost. Verify the served protocol before recommending either direction (verify
  against the currency brief for your version).
- **Cross-origin connections set up lazily**: required third-party origins (font host, image CDN, API)
  not warmed with `preconnect`/`dns-prefetch` pay DNS+TCP+TLS on first use, on the critical path.
- **No CDN/edge for static assets** where user latency matters; TTFB dominated by a slow origin (the
  backend pack owns server time — this pack flags the delivery *shape*, not the server logic).

## Payload / startup / critical rendering path (lane `payload-startup`)
- **Render-blocking CSS**: every `<link rel="stylesheet">` blocks the first paint until it is downloaded
  and parsed — inline the critical (above-the-fold) CSS and load the rest non-blocking
  (`media`-attribute toggling or `rel=preload`+swap), and remove unused CSS so the blocking stylesheet
  is small. Avoid CSS `@import` in stylesheets: the imported sheet isn't discovered until its parent has
  downloaded and parsed, serializing fetches into a waterfall — prefer top-level `<link>`s the preload
  scanner can start in parallel.
- **Parser-blocking scripts**: a `<script>` without `async`/`defer` in `<head>` halts HTML parsing
  while it downloads and runs — use `defer` (run after parse, in order) or `async` (run ASAP, unordered)
  and place scripts deliberately; native module scripts are deferred by default.
- **`<head>` order and the preload scanner**: put `<meta charset>` first and critical CSS early, and
  keep critical subresources as discoverable `<link>`/`<img>` in the markup — a resource hidden behind
  JS or CSS (`background-image`, dynamically injected) is found late, after the preload scanner could
  have started it.
- **Missing hints for the late-discovered critical resource**: `<link rel="preload">` the LCP image or
  a critical font (discovered late, in CSS), `modulepreload` a critical module graph — but
  over-hinting de-prioritizes everything, so reserve it for the genuinely critical few (verify against
  the currency brief for your version).
- **Heavy third-party scripts**: analytics, tag managers, ads, chat/social widgets each add
  render-blocking or main-thread cost and a network dependency — load them `async`/`defer`, lazy-load
  the non-critical ones, use a click-to-load facade for heavy embeds, and audit tag-manager sprawl.
- **Un-minified or unused payload shipped to production**: un-minified HTML/CSS/JS, or a large CSS/UI
  framework pulled in whole for a few components — minify and trim to what the page uses.
- **Speculative loading for the next navigation, where it pays**: `<link rel="prefetch">` or the
  Speculation Rules API can prefetch/prerender a likely next page for near-instant navigation — weigh
  the wasted bandwidth on the pages users *don't* visit (verify against the currency brief for your
  version).

## Framework-idiom currency (lane `idiom-currency`)
- **JavaScript reinventing a now-native platform feature**: a JS library doing what the platform now
  does natively — e.g. lazy-loading (`loading="lazy"`), modals/disclosure (`<dialog>`/`<details>`),
  layout reservation (CSS `aspect-ratio`), or off-screen skipping (`content-visibility`), among other
  newly-Baseline primitives — ships script weight and main-thread cost the native element doesn't.
  Flag the library where the native feature now covers the use case (verify against the currency brief
  for your version).
- **Legacy formats/loading where modern ones win**: old image formats and font formats, and
  fixed-size images without `srcset`, where AVIF/WebP, WOFF2, and responsive images would cut bytes —
  see the `images-media` and `fonts` modules.
- Consult the currency brief for changed browser defaults and newly **Baseline** features the markup
  could adopt; offline, note candidate idiom concerns at LOW confidence for manual currency check.

---

## Rendering path & Core Web Vitals (use for every HTML audit)

HTML performance is judged against how the browser turns bytes into pixels, and against the user-centric
metrics — this is the HTML analog of a runtime-notes section: how to reason and measure before
concluding.

- **The critical rendering path**: the browser streams HTML into the **DOM**, blocks rendering on CSS
  (the **CSSOM**) and on parser-blocking scripts, then runs style → layout → paint → composite. The
  three durable levers are: *don't block the parser/renderer* (async/defer JS, non-blocking non-critical
  CSS), *let the preload scanner discover subresources early* (keep them in the markup), and *ship the
  above-the-fold content first*.
- **Core Web Vitals are the measurement frame**: **LCP** (largest contentful paint — usually the hero
  image or heading; make it discoverable, prioritized, not lazy-loaded, and served fast), **CLS**
  (cumulative layout shift — reserve space for images, embeds, ads, and font swaps so nothing jumps),
  **INP** (interaction latency — mostly a JS main-thread concern, minimal on a no-JS page), and **TTFB**
  (server response — owned by the backend but it caps everything downstream).
- **Measure with lab *and* field tools**: Lighthouse / WebPageTest / DevTools give a controlled lab
  number; CrUX / RUM give what real users on slow devices and networks actually experience — a fast
  lab score can hide a poor field result, so confirm against field data where available, and throttle
  the lab to a realistic device/network.
- **Judgment, not a scorecard**: a heavy hero image on a landing page may be the entire point; flag the
  *avoidable* delay, shift, and bytes on the critical path — not every byte. A region that is inherent
  to the page's job is not automatically a defect.

## Framework / sub-stack modules (load on detection)

Load the lanes + Rendering-path notes above for *every* HTML audit. Additionally load a module when its
surface is material to the page.

| Detected (signals) | Load module |
|---|---|
| **Images & media** — significant imagery or embeds: `<img>`/`<picture>`/`srcset`, `<video>`, `<iframe>` embeds, inline SVG | [`html/images-media.md`](html/images-media.md) |
| **Web fonts** — `@font-face`, a `<link>` to Google Fonts / a font CDN, or `.woff2`/`.woff`/`.ttf` assets | [`html/fonts.md`](html/fonts.md) |

## Sources

Durable signals here are grounded in platform/standards documentation; version-specific support belongs
in the currency brief.

- **web.dev** — "Learn Core Web Vitals", "Critical rendering path", LCP/CLS/INP optimization guides,
  "Preload critical assets", third-party/facade patterns.
- **MDN** — `loading`, `fetchpriority`, `<link rel=preload/preconnect/modulepreload>`, `font-display`,
  `srcset`/`sizes`, `content-visibility`, `<dialog>`, Speculation Rules.
- **HTTP Archive / Web Almanac** — real-world distributions for markup, CSS, fonts, media; Lighthouse
  audit definitions.
