# HTML performance module: Images & media
> Load when the HTML carries significant imagery or embeds — `<img>`/`<picture>`/`srcset`, `<video>`,
> `<iframe>` embeds, or inline SVG — see the module map in `../html.md`. Core HTML lanes + Rendering-path
> notes live in `../html.md`; this file is the Images & media lens only.

## Images & media

> Scope: `<img>`, `<picture>`, `<video>`, `<iframe>`, and SVG in HTML documents. The recurring theme is
> that images are typically the largest bytes transferred and the most common LCP element — right-size and
> right-format them first, reserve their layout space to avoid CLS (see the Rendering-path notes in
> `../html.md`), then prioritize the LCP image and defer everything else.

- **Serving a single fixed image to every viewport/DPR**: without `srcset` + `sizes` on `<img>`, every
  device receives the largest image the layout ever needs — a mobile user at 1× DPR downloads the same
  asset as a 4K desktop at 3× DPR. The trade-off is markup complexity vs. systematic byte savings (often
  50–80% on small viewports); `<picture>` with `<source media="...">` is the right tool when the image
  crop or subject changes across breakpoints (art direction), while plain `srcset`+`sizes` on `<img>` is
  sufficient for resolution switching on the same crop.

- **Serving legacy formats when modern alternatives are supported**: AVIF offers significantly better
  compression than WebP, which in turn beats JPEG/PNG at equivalent visual quality — serving legacy
  formats at 2–10× the byte cost for the same perceived quality is the single biggest image-weight lever.
  Use a `<picture>` fallback chain (`<source type="image/avif">` → `<source type="image/webp">` →
  `<img>` JPEG/PNG) so browsers that support the better codec use it without breaking older ones (verify
  against the currency brief for your version).

- **Missing `width`/`height` attributes causing layout shift**: when an `<img>` or `<video>` element has
  no explicit `width`/`height` (or equivalent CSS `aspect-ratio`), the browser can't reserve space in the
  layout before the resource loads — the image arrives and pushes surrounding content down, which is a
  primary cause of poor CLS scores (see the Rendering-path notes in `../html.md`). The fix is either HTML
  attributes matching the intrinsic size or a CSS `aspect-ratio` rule; the browser uses the ratio, not the
  literal pixel value, so responsive images with `max-width:100%` still work correctly.

- **`loading="lazy"` on the LCP or above-the-fold image**: the browser defers lazy-loaded images until
  the element is near the viewport — for the hero/LCP image, this means the fetch doesn't start until
  after layout, making it self-defeating; the image is discovered late and fetched late, directly worsening
  LCP (cross-reference the LCP framing in `../html.md`). Lazy-loading belongs only on images that are
  reliably below the fold. The inverse failure — omitting `loading="lazy"` on images that are always far
  below the fold — wastes bandwidth on initial load for assets the user may never scroll to.

- **LCP image not discoverable by the preload scanner**: when the LCP image is set via CSS
  `background-image` or injected by JavaScript, the browser's preload scanner (which finds `<img src>`
  and `<link rel=preload>` in the raw HTML) cannot see it — the fetch is blocked behind CSS/JS parse and
  execution, delaying LCP substantially (cross-reference the payload-startup lane in `../html.md`). Prefer
  a real `<img>` element for the LCP candidate, or add `<link rel="preload" as="image"
  imagesrcset="..." imagesizes="...">` so the scanner can start the fetch immediately (verify against the
  currency brief for your version).

- **Deprioritizing or not prioritizing the LCP image**: the browser assigns images a low-to-medium fetch
  priority by default; for the LCP image that priority is too low when there is competing resource
  contention. `fetchpriority="high"` on the LCP `<img>` (or on the corresponding `<link rel=preload>`)
  signals the browser to promote it in the request queue. Conversely, non-critical below-fold images
  benefit from `fetchpriority="low"`, and `decoding="async"` prevents any image from blocking the main
  thread during decode. Stacking all three attributes on every image indiscriminately defeats the signal
  (verify against the currency brief for your version).

- **Oversized intrinsic dimensions relative to the displayed size**: an image served at 4000 × 3000 px
  and rendered at 400 × 300 CSS px transfers 100× more pixels than needed at 1× DPR, amplified further at
  higher DPR. This is distinct from format choice — even a well-compressed AVIF is wasteful if it encodes
  far more pixels than the layout uses. Right-sizing at the origin or at a CDN image-transform layer (which
  can resize, reformat, and cache on request) eliminates the waste without client-side changes; look for
  images whose intrinsic dimensions dwarf the `sizes`/CSS display size as the condition.

- **Eagerly loaded `<video>` or third-party `<iframe>` embeds**: a `<video preload="auto">` or a
  `<video>` without `preload="none"` starts buffering media on page load regardless of whether the user
  ever plays it; a YouTube, map, or chat iframe loaded eagerly fires dozens of third-party sub-requests
  that consume connection budget and bandwidth before any user interaction. Use `preload="none"` + a
  `poster` image for video; use `loading="lazy"` on off-screen iframes; replace third-party embeds with a
  lightweight facade element (a static thumbnail + play button) that loads the real embed only on click
  (cross-reference the payload-startup lane in `../html.md` for connection-budget impact).

- **Large or unoptimized inline SVG**: SVG inlined directly in HTML avoids a separate request and can be
  styled/animated with CSS, but unoptimized SVG (editor cruft, redundant paths, excessive precision, large
  path data for complex illustrations) bloats the HTML document — defeating HTTP compression gains on the
  page and making the document non-cacheable as a standalone asset. Run inlined SVG through an optimizer
  (e.g., SVGO) and evaluate whether the inline benefit outweighs extractability; for icons used repeatedly,
  a referenced SVG sprite sheet or symbol-based sprite is usually both smaller per-use and independently
  cacheable compared to many separate inline SVGs or per-icon `<img>` requests.
