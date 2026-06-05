# .NET performance module: WinForms
> Load when `System.Windows.Forms` (etc.) is detected — see the module map in `../dotnet.md`. Core lanes + Variant notes live in `../dotnet.md`; this file is the WinForms lens only.

## WinForms

> Windows desktop UI on **both** .NET Framework and modern .NET / Windows Desktop
> (`net8.0-windows`+). The performance model — a single STA UI thread pumping a Win32
> message loop, GDI/GDI+ painting, handle-backed controls — is essentially identical across
> runtimes, so these are *conditions to look for* on any WinForms target unless noted. The
> async/await idioms below are richer on modern .NET; `BackgroundWorker` is the Framework-era
> fallback that still works everywhere.

- **Long synchronous work on the UI thread**: any blocking I/O, database query, web call, or
  heavy computation run directly in an event handler freezes the message pump (the app stops
  repainting and responding, shows "Not Responding"). Move it off-thread via `async`/`await` over
  truly-async APIs, `Task.Run` for CPU-bound work, or `BackgroundWorker` (Framework-era but
  portable); never `.Result`/`.Wait()` it back on the UI thread (sync-over-async deadlocks under
  the WinForms `SynchronizationContext`).
- **Cross-thread results marshaled per-item**: UI controls may only be touched on the thread that
  created their handle — worker results must come back via `Control.Invoke`/`BeginInvoke` (or
  `IProgress<T>`/`await`, which capture the UI context for you). `Invoke` is **synchronous** (blocks
  the worker until the UI thread runs the delegate); `BeginInvoke` is async (fire-and-forget). A
  per-item `Invoke` inside a tight loop floods the message queue and serializes the worker against
  the UI thread — batch results and marshal once per chunk.
- **Bulk list/tree/combo population without batching**: adding many items to `ListView`/`TreeView`/
  `ComboBox`/`ListBox` one-by-one repaints (and re-sorts) per item. Wrap the loop in
  `BeginUpdate()`/`EndUpdate()` to suppress repaint, or prefer `AddRange` (which applies internal
  batching/optimizations for you). Calls nest: `EndUpdate` must balance every `BeginUpdate`.
  (Handle-creation timing also matters: populate a `ListView` *after* its handle exists — e.g. in
  `Load`/`Shown` — but a `TreeView` populates fastest *before* handle creation or via `AddRange`.)
- **Bulk layout changes without `SuspendLayout`/`ResumeLayout`**: mutating many child controls'
  `Bounds`/`Size`/`Location`/`Visible`/`Text` (especially on `AutoSize` controls, especially in
  `Form.Load` where handles already exist) fires a `Layout` event per change. Bracket bulk changes
  with `SuspendLayout()`/`ResumeLayout()` — and call them on the **container actually receiving the
  children** (e.g. the panel), not the parent form. Note `SuspendLayout` only suppresses the managed
  `OnLayout`; it does not stop Win32 size messages, so set the property carrying the most info at
  once (`Bounds` over separate `Size`+`Location`).
- **`DataGridView` over large data without VirtualMode**: a `DataGridView` materializing thousands
  of rows holds a cell object per cell and is slow to scroll/resize. Set `VirtualMode = true` and
  serve cells from your own cache via the `CellValueNeeded` events for very large/just-in-time data
  sets; enable double-buffering; avoid recomputing per-cell/per-row styling on every paint (share
  `DataGridViewCellStyle` objects, avoid `AutoSizeColumnsMode`/`AutoSizeRowsMode` that re-measure
  all rows). Use shared rows where possible.
- **Missing double-buffering on custom/heavy-painted controls**: progressive redraw of a
  drawing-intensive surface flickers and feels slow. Enable `DoubleBuffered = true`, or for custom
  controls `SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint, true)`
  so painting happens off-screen and blits once. (`DataGridView` exposes double-buffering only via a
  protected member / reflection.)
- **Heavy work inside `OnPaint`**: `Paint` fires often; creating `Font`/`Brush`/`Pen` objects,
  measuring strings, or doing expensive computation per paint is a hot-path cost. Hoist object
  creation to construction/`Resize` and cache it; avoid `TextFormatFlags.WordBreak` on single-line
  measurement and use `TextRenderer` overloads that don't take an `IDeviceContext` (they reuse a
  cached memory DC).
- **`Application.DoEvents()` misuse**: pumping the message queue mid-operation to "keep the UI
  responsive" invites re-entrancy bugs and burns CPU (it busy-pumps). Use async/await or
  `BackgroundWorker` with `ProgressChanged` instead of `DoEvents`.
- **Leaked GDI/GDI+ objects and handles**: `Font`, `Brush`, `Pen`, `Bitmap`, `Graphics`,
  `Region`, `Icon` wrap native GDI handles — not disposing them leaks handles (the process has a
  finite GDI handle quota; exhaustion degrades then breaks rendering). Wrap them in `using`/dispose
  deterministically; cache long-lived ones rather than recreating per paint; handle large images
  with care (dispose source bitmaps, watch LOH for big `Bitmap` buffers).
- **Event-handler / component leaks keeping forms alive**: subscribing a long-lived publisher to a
  form/control handler (timers, static events, parent-to-child wiring) roots the form so it (and its
  whole control tree + GDI handles) never collects after close. Unsubscribe on `FormClosed`/`Dispose`;
  dispose `Timer`/`BackgroundWorker`/components.
- **Heavy data binding on large/complex bindings**: deep or large `BindingSource`/`DataGridView`
  bindings, especially with `IBindingList` change notifications firing per row, can dominate populate
  time; suspend binding/notifications during bulk loads (`BindingSource.RaiseListChangedEvents = false`,
  or `SuspendBinding`) and resume once.
