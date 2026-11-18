# .NET performance module: WPF
> Load when `*.xaml` (etc.) is detected — see the module map in `../dotnet.md`. Core lanes + Variant notes live in `../dotnet.md`; this file is the WPF lens only.

## WPF

> WPF runs on **both** .NET Framework and modern .NET / Windows Desktop (`net8.0-windows`+); the
> retained-mode composition model, layout system, binding engine, and `Freezable`/rendering-tier
> behavior are the same across runtimes, so these are *conditions to look for* on any WPF target.
> Microsoft's "Optimizing WPF Application Performance" series is the canonical source for the items
> below. APIs are durable; verify exact members against the currency brief for your version.

### Collections & virtualization

- **Large `ItemsControl`/`ListBox`/`DataGrid`/`TreeView` without UI virtualization**: by default the
  layout system creates a container for *every* item and measures/arranges it, even off-screen.
  UI virtualization defers container generation to visible items only; it is **on by default** for
  `ListBox`/`ListView` data-bound, but `TreeView` and custom `ItemsControl`s need it turned on
  (`VirtualizingStackPanel.IsVirtualizing="True"`, set `ItemsPanel` to `VirtualizingStackPanel` for
  controls like `ComboBox`). Add `VirtualizationMode="Recycling"` to reuse containers instead of
  churning them while scrolling (verify against the currency brief for your version).
- **Virtualization silently defeated**: wrapping the items host in a `ScrollViewer`/`StackPanel`, or
  placing the list inside an `Auto`-sized / unbounded-height container, gives the panel infinite
  available space so it realizes every item; `ScrollViewer.CanContentScroll="False"` (pixel scrolling)
  and grouping without `VirtualizingPanel.IsVirtualizingWhenGrouping="True"` also disable it. Confirm
  the dedicated scrollbar belongs to the control's own virtualizing panel and isn't bypassed.
- **`ObservableCollection<T>` bulk updates raising `CollectionChanged` per item**: it has no
  `AddRange`; adding N items in a loop fires N change notifications, each walking bindings and
  re-running layout. Build the data first and assign/replace the collection (or `Reset` once), use a
  collection type that supports range operations, or suspend notifications during the load.
- **Binding `IEnumerable` instead of `IList`/`IList<T>` to an `ItemsControl`**: forces WPF to wrap it
  in a generated `IList`, an avoidable second object and indexing overhead — bind an `IList<T>`
  directly. Prefer `ObservableCollection<T>` over a plain `List<T>` when the UI must reflect
  add/remove (a plain list forces full regeneration on change).

### Binding

- **Silent binding failures are a real perf cost**: each failed binding walks the visual tree
  searching for a source and logs a `System.Windows.Data Error` to the trace output — repeated over
  many elements / on every layout this is measurable. Treat trace-window binding errors as bugs to
  fix; use `PresentationTraceSources.TraceLevel` to locate noisy ones (verify against the currency
  brief for your version).
- **Binding to sources without `INotifyPropertyChanged`**: a plain CLR source forces the engine
  through reflection/`TypeDescriptor` to resolve and to *poll* for changes — the costliest path.
  Implement `INotifyPropertyChanged` (cheaper) on bound view models; for values that never change,
  use `Mode=OneTime` so no change-tracking machinery is set up at all.
- **Converters / `StringFormat` on hot, frequently-updated bindings**: an `IValueConverter` or
  `MultiBinding` runs on every update and every re-evaluation; keep them cheap, avoid allocation, and
  prefer pre-computed view-model properties for values updated at high frequency.
- **Noisy two-way inputs without throttling**: `UpdateSourceTrigger=PropertyChanged` on a `TextBox`
  pushes to the source (and re-runs validation/converters/dependent bindings) on every keystroke;
  use `Delay` on the binding, or `UpdateSourceTrigger=LostFocus`, for chatty inputs (verify against
  the currency brief for your version).

### Visual tree & layout

- **Deep / over-nested visual trees**: layout is a recursive measure+arrange pass whose cost scales
  with element count and depth; gratuitous nested panels, redundant `Border`/`Grid` wrappers, and
  heavyweight templates multiply per-frame `Measure`/`Arrange` work. Flatten the tree, reduce element
  count, and build trees **top-down** (adding a node invalidates its parent and all children, so
  bottom-up construction re-validates repeatedly).
- **Wrong panel for the job**: panel cost tracks functionality — `Canvas` is cheapest, `Grid`/
  `StackPanel`/`DockPanel` do more measuring. Don't pay for a `Grid` where a `Canvas` or simple
  `StackPanel` suffices; avoid `StackPanel` for large lists (it doesn't virtualize unless it's the
  virtualizing variant).
- **Layout-invalidation storms**: animating or repeatedly setting properties flagged
  `AffectsMeasure`/`AffectsArrange` (size, margin, alignment) on elements high in the tree forces
  whole-subtree relayout each frame; prefer transforms (which don't invalidate layout) over
  layout-affecting property changes for movement/scaling.
- **`Visibility.Hidden` vs `Collapsed`**: a `Hidden` element is still measured and arranged (it
  occupies layout space, just isn't drawn); use `Collapsed` to remove it from layout entirely when
  it shouldn't participate. For frequently toggled large subtrees, collapsing avoids the relayout
  cost of an invisible-but-measured tree.

### Rendering

- **Unfrozen `Freezable`s on the hot path**: brushes, pens, geometries, transforms, and animations
  are `Freezable`s that, while unfrozen, maintain `Changed`-event machinery and cannot be shared
  across threads. Call `.Freeze()` on ones that never change — it drops the change-notification
  overhead, lowers working set, and makes them thread-safe to create off the UI thread. (Unfrozen
  `Freezable` `Changed` handlers also keep listeners alive — a subtle leak; remove the brush from
  the property to detach.)
- **Software-rendered effects on subtrees**: `DropShadowEffect`/`BlurEffect` (and other bitmap
  effects) are expensive and can force a software/temporary-surface render over a whole subtree;
  apply sparingly, scope them tightly, and consider `BitmapCache` (cache the rendered result) for
  static decorated content. Set `Brush.Opacity` rather than an element's `UIElement.Opacity`
  (element opacity can spawn a temporary surface).
- **Ignoring the render tier**: WPF classifies the GPU into rendering tiers (0 = software, 1/2 =
  increasing hardware acceleration); on Tier 0 / RDP / VMs much falls back to the CPU-bound software
  rasterizer where fill-rate (overdraw, transparency layering) dominates. Query
  `RenderCapability.Tier` and degrade gracefully (drop effects, reduce overdraw) on low tiers; for
  bitmaps being animated/scaled, `RenderOptions.SetBitmapScalingMode(..., LowQuality)` trades
  resampling quality for frame rate.
- **Large opacity/transform animations over big subtrees & `Dispatcher` flooding**: animating
  opacity or transforms over a large visual subtree re-composites a lot of pixels per frame;
  similarly, posting high-frequency or low-priority work to the `Dispatcher` (per-tick UI updates,
  chatty `BeginInvoke`) starves input/layout. Throttle/coalesce dispatcher work, animate the
  smallest possible subtree, and prefer cached or transformed rendering over per-frame relayout.
- **Per-instance resources instead of shared**: defining brushes/geometries in a custom control's
  own `ResourceDictionary` allocates a fresh copy per control instance; hoist shared,
  performance-intensive resources to `Window`/`Application` level (or the control's default theme)
  so instances share them — large working-set savings when many instances exist.
