# .NET performance module: ASP.NET Core (hosting & pipeline)
> Load when `Microsoft.AspNetCore.*` (etc.) is detected — see the module map in `../dotnet.md`. Core lanes + Variant notes live in `../dotnet.md`; this file is the ASP.NET Core (hosting & pipeline) lens only.

## ASP.NET Core (hosting & pipeline)
- **Hosting model for IIS**: prefer in-process hosting (the default since ASP.NET Core 3.0) over
  out-of-process (ANCM reverse-proxy); out-of-process forwards each request over a localhost
  loopback adapter, adding a measurable round-trip per request — check `<AspNetCoreHostingModel>`
  in the project file or `web.config` `hostingModel` attribute.
- **Middleware ordering**: order cheap, short-circuiting middleware (static files, authentication
  short-circuits, health checks) before expensive middleware; placing heavy middleware (logging,
  response buffering, authorisation) before short-circuit middleware means they run even on
  requests that will be rejected or served from cache — review `app.Use*` ordering in `Program.cs`.
- **Per-request allocations in custom middleware**: middleware that allocates objects (DTOs,
  buffers, service resolution via `GetService`) on every request contributes to GC pressure;
  use constructor-injected singletons, `ArrayPool<T>`, or `ObjectPool<T>` for reusable state
  and avoid per-invocation `new` in the `InvokeAsync` hot path.
- **Missing response compression + output caching**: cacheable endpoints returning JSON, HTML,
  or plain text without `AddResponseCompression`/`UseResponseCompression` or `AddOutputCache`/
  `UseOutputCache` miss significant payload savings; output caching also prevents redundant
  re-execution of expensive handlers — both should be intentional defaults on public-facing
  APIs (verify against the currency brief for your version).
- **Buffering large collections instead of streaming**: returning `IEnumerable<T>` from a
  controller/minimal-API handler causes the serialiser to enumerate the full set before
  flushing; prefer `IAsyncEnumerable<T>` to stream JSON rows as they arrive from the database,
  reducing peak memory and time-to-first-byte for large result sets (verify against the
  currency brief for your version).
- **Synchronous I/O in the pipeline**: reading `HttpRequest.Body` or writing `HttpResponse.Body`
  synchronously blocks a Kestrel I/O thread; Kestrel does not support synchronous reads by
  default (`AllowSynchronousIO` defaults to `false`); synchronous action filters and result
  filters similarly stall the pipeline — verify all pipeline code uses async overloads.
- **Static files via the app instead of CDN / with missing cache headers**: `UseStaticFiles`
  serves files without an upstream CDN layer and without aggressive `Cache-Control` headers
  by default; long-lived assets (versioned JS/CSS) should carry `Cache-Control: max-age` and
  ideally be offloaded to a CDN to reduce origin load and round-trip latency.
- **Minimal APIs vs MVC controllers on hot endpoints**: minimal APIs have lower per-request
  overhead (no model-binding pipeline, no action-filter chain, no view-engine plumbing) for
  simple request/response patterns; consider minimal APIs for throughput-sensitive endpoints
  and reserve MVC for endpoints that genuinely use filters, model validation, or view
  rendering (verify against the currency brief for your version).
