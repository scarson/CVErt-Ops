# Expected Findings — HTML fixture (companion pack + images-media + fonts)

**Purpose:** exercise the **HTML companion pack** + the **`images-media`** and **`fonts`** modules +
the **Rendering path & Core Web Vitals** notes. Plain document; loads alongside whatever backend emits
it.

**Pack slice to provide:** `html.md` lane slices (payload-startup heavy) + the **Rendering path & CWV**
notes + `html/images-media.md` + `html/fonts.md`. Scope = `index.html`. Do NOT let the agent read this
rubric.

## Planted issues (should be found)

| # | Location | Lane / module | Issue |
|---|----------|---------------|-------|
| 1 | `<head>` `<script src=analytics>` | payload-startup | parser-blocking third-party script in `<head>` (no `async`/`defer`) |
| 2 | `app.css` link + `@import theme.css` | payload-startup | render-blocking CSS + an `@import` waterfall (imported sheet discovered late); inline critical CSS, use top-level `<link>` |
| 3 | hero `<img loading="lazy">` | `images-media` | the **LCP image is lazy-loaded** (delays LCP) **and** has no `width`/`height` (→ CLS). Identify it as the LCP element |
| 4 | `@font-face` (no `font-display`) | `fonts` | default `block` → FOIT (invisible text ~3s); critical font not preloaded (late discovery) |
| 5 | hero `<img src="/img/hero-4000w.jpg">` | `images-media` | a fixed 4000px-wide image served to every viewport/DPR — no `srcset`/`sizes` (and a legacy format); 10–100× excess pixels on mobile |

## Beyond-the-pack (floor-not-ceiling — bonus)

| Location | Issue | Why beyond the pack |
|----------|-------|---------------------|
| `<img src="data:image/jpeg;base64,…">` | a full-res hero embedded as a base64 `data:` URI in the markup | The agent should reason about the *compounding* costs — bloats/blocks the HTML parse, the bytes can't be cached or `fetchpriority`-prioritized separately, it defeats the preload scanner, and it can't be a responsive `srcset` candidate. The memory lane names "big `data:` URIs"; the multi-faceted rendering-path reasoning is the bonus. |

## Decoy (should NOT be flagged)

| Location | Why ignored |
|----------|-------------|
| footer-promo `<img loading="lazy" width height>` | a below-the-fold thumbnail, correctly lazy-loaded **and** sized — this is the *right* use of `loading="lazy"`. Flagging it ("remove lazy-loading", "it causes CLS") is a precision/checklist failure (it has dimensions; no shift). |

## Scoring

- **Recall** = (# of {1..5} found) / 5. #3 should name *both* the lazy-LCP and the missing-dimensions
  halves and identify the hero as the LCP candidate.
- **Precision** = the correctly-lazy-loaded sized footer image NOT flagged.
- **Beyond-the-pack** = the `data:` URI hero flagged with rendering-path reasoning.

## How to run

Dispatch payload-startup (+ a memory pass) subagents with the shared preamble + lane body from
`../../lane-prompts.md`, the `html.md` slices + Rendering-path notes + the two modules, and
`index.html` as scope. Score against the tables above.

## Last run

**2026-06-04, Sonnet — GREEN.** Recall 5/5 (#3 named both the lazy-LCP and missing-dimensions halves
and identified the hero as LCP); beyond-the-pack (data-URI hero) found with full multi-faceted
rendering-path reasoning; the correctly-lazy+sized footer decoy rejected; `fetchpriority`/`preconnect`/
standalone-`<link>` candidates correctly subordinated; zero fabrications.
