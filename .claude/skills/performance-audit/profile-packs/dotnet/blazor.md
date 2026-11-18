# .NET performance module: Blazor
> Load when `*.razor` (etc.) is detected — see the module map in `../dotnet.md`. Core lanes + Variant notes live in `../dotnet.md`; this file is the Blazor lens only.

## Blazor
- **Render-model choice is the dominant performance decision**: Blazor Server adds a
  network round-trip and server-side memory (one SignalR circuit per active user) for every
  interaction; Blazor WebAssembly shifts CPU to the client and incurs a large initial payload;
  the unified `.NET 8+` Auto render mode uses Server for first load and migrates to WASM once
  downloaded — pick the model intentionally based on latency, payload, and scale requirements
  (verify against the currency brief for your version).
- **Unnecessary component re-renders**: every parent re-render recursively re-renders children
  unless suppressed; override `ShouldRender()` to return `false` when parameters are unchanged
  complex types; use primitive or immutable parameters where possible so Blazor's built-in
  change-detection skips re-rendering automatically; set `@key` on list items so the differ
  matches components to data by identity rather than position (verify against the currency
  brief for your version).
- **Large lists without `<Virtualize>`**: rendering thousands of items in a `foreach` loop
  materialises every row into the DOM; wrap large lists in `<Virtualize Items="…">` to render
  only the visible viewport rows, reducing both render time and DOM node count (verify against
  the currency brief for your version).
- **Heavy work in lifecycle methods**: `OnInitialized`/`OnParametersSet` run synchronously
  before the first render; expensive synchronous work here blocks the render thread on Server
  or the WASM main thread; use `OnInitializedAsync`/`OnParametersSetAsync` with `await` and
  cache results that are stable across re-renders to avoid re-executing on every parameter
  update.
- **Chatty JS interop**: calling `IJSRuntime.InvokeAsync` inside a render loop, from
  `OnAfterRenderAsync`, or once per component instance in a large list adds latency (especially
  on Blazor Server, where each call crosses the SignalR wire); batch JS calls where possible,
  avoid per-render invocations, and prefer `IJSInProcessRuntime` on Blazor WebAssembly for
  synchronous, zero-round-trip JS calls (verify against the currency brief for your version).
- **`StateHasChanged` called too broadly**: calling `StateHasChanged()` unconditionally or
  from high-frequency events (scroll, mouse-move, timer) re-renders the entire component
  subtree; call it only when state has actually changed, throttle high-frequency sources, and
  use `IHandleEvent` or `EventUtil.AsNonRenderingEventHandler` to suppress automatic
  re-renders for event handlers that do not change visible state.
- **WebAssembly payload and startup**: large WASM initial download (runtime + assemblies)
  directly affects Time-to-Interactive; enable AOT compilation for CPU-intensive apps
  (improves runtime speed at the cost of larger download), enable IL trimming, and use
  lazy-loaded assemblies (`@attribute [DynamicDependency]` + lazy routing) to defer loading
  feature assemblies until their routes are first visited (verify against the currency brief
  for your version).
- **Missing prerendering / streaming rendering**: Blazor Server and Blazor Web App (`.NET 8+`)
  can prerender components to static HTML for fast first-paint before the circuit connects;
  streaming rendering (`[StreamRendering]`) allows long async operations to return a
  placeholder immediately and push the final content when ready — omitting both leaves users
  watching a blank screen during circuit negotiation or slow data fetches (verify against the
  currency brief for your version).
