# .NET performance module: Native / COM interop (incl. Office automation)
> Load when `[DllImport]`/`[LibraryImport]` (etc.) is detected — see the module map in `../dotnet.md`. Core lanes + Variant notes live in `../dotnet.md`; this file is the Native / COM interop (incl. Office automation) lens only.

## Native / COM interop (incl. Office automation)

> Generalizes to **any** native/COM interop — Office automation is the most common offender but the
> same costs apply to any P/Invoke or COM library. Windows-centric; COM interop is .NET Framework
> plus .NET Core 3.0+/.NET 5+ on Windows (the `ComWrappers` API arrived in .NET 6, a COM source
> generator in .NET 8). Bullets are *conditions to look for*.

- **Chatty cross-boundary calls in a loop**: every managed↔native or managed↔COM transition has
  fixed overhead (marshaling, RCW dispatch, security checks). A loop making one P/Invoke or COM
  call per item multiplies that overhead — **batch** into a single coarse call that moves all the
  data at once (verify against the currency brief for your version).
- **COM apartment marshaling (STA/MTA)**: calls that cross apartment boundaries are **proxied and
  serialized** through the COM marshaler rather than direct vtable calls — a hidden per-call cost.
  An STA object touched from MTA/thread-pool threads (or vice versa) pays this on every call; keep
  COM objects on a compatible apartment and avoid cross-apartment chatter.
- **COM RCWs not released deterministically**: the runtime holds one RCW per COM object and only
  releases the underlying COM reference when the RCW is garbage-collected — relying on the GC
  orphans server processes (the classic leftover `EXCEL.EXE` / `WINWORD.EXE`). Release RCWs
  deterministically with `Marshal.ReleaseComObject` (decrements the ref count) or
  `Marshal.FinalReleaseComObject` (zeros it), releasing **every** intermediate object you touch
  (no two-dot expressions like `book.Worksheets[1]` that create an unreleased RCW).
- **Office automation — per-cell access**: reading/writing an Excel `Range` cell-by-cell makes one
  cross-process COM call per cell. Read/write the **whole `Range` in one call via an `object[,]`
  array** (`Range.Value` / `Range.Value2`) — orders of magnitude fewer round-trips.
- **Server-side Office automation is unsupported by Microsoft**: automating Office apps (Excel,
  Word, Outlook) from a service/ASP.NET/unattended process is explicitly **unsupported** — Office
  assumes an interactive desktop (modal dialogs hang the process), is not reentrant or scalable for
  concurrent server use, has session/identity and stability issues, and can run untrusted macros.
  Use a document library instead: the **Open XML SDK** (`DocumentFormat.OpenXml`) for `.xlsx`/
  `.docx`/`.pptx`, or a third-party reporting/spreadsheet library — no Office install, faster, and
  supported.
- **Late-bound `dynamic`/IDispatch COM vs early-bound interop**: late binding through `IDispatch`
  (C# `dynamic` over COM, or `Type.InvokeMember`) resolves members by name at runtime and is much
  slower than early-bound calls through a generated interop assembly / typed interface — prefer
  early-bound interop (a referenced Primary Interop Assembly or typed wrapper) on hot paths.
- **P/Invoke marshaling cost**: prefer **blittable** types (integers, pointers, blittable structs
  with `LayoutKind.Sequential`) which need no conversion; **non-blittable** parameters (`string`,
  `bool`, non-blittable structs, arrays) allocate and **copy** on every call. Avoid tiny P/Invoke
  calls in tight loops; note `SetLastError = true` adds per-call overhead (capturing the OS error);
  on modern .NET prefer the `[LibraryImport]` source generator over `[DllImport]` for AOT-friendly,
  lower-overhead marshaling (verify against the currency brief for your version).
- **Native handles not wrapped in `SafeHandle`**: raw `IntPtr` handles from native APIs leak on
  exceptions and race with finalization/`P/Invoke`; wrap them in a `SafeHandle`-derived type (or
  `CriticalHandle`) for reliable, deterministic release of OS resources.

---
