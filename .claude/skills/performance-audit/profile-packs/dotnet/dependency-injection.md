# .NET performance module: Dependency injection (containers)
> Load when `Microsoft.Extensions.DependencyInjection` (etc.) is detected — see the module map in `../dotnet.md`. Core lanes + Variant notes live in `../dotnet.md`; this file is the Dependency injection (containers) lens only.

## Dependency injection (containers)

> Cross-cutting on **both** runtimes (MS `Microsoft.Extensions.DependencyInjection` on modern .NET;
> Autofac / Unity / Ninject / StructureMap / SimpleInjector / Castle Windsor on Framework). Bullets
> are *conditions to look for*. Lifetime terms below use MS DI names (Singleton / Scoped /
> Transient); other containers have equivalents.

- **Slow container on deep graphs resolved per request**: resolving a deep object graph on every
  request has real cost, and **container choice matters** — reflection/expression-heavy containers
  (Ninject, older Unity) are markedly slower than fast ones (MS DI, SimpleInjector, DryIoc, Lamar).
  Flag a hot path resolving a large graph through a known-slow container (verify against the
  currency brief / benchmark for the specific container and version).
- **Lifetime misconfiguration — Transient/Scoped where Singleton fits**: registering an expensive-
  to-build, stateless, thread-safe object (mapper/`MapperConfiguration`, serializer settings,
  compiled regex, a configured `HttpClient`/typed client) as Transient or Scoped rebuilds it on
  **every resolve** instead of once. Promote genuinely shareable, expensive objects to Singleton.
- **Captive dependency**: a longer-lived service capturing a shorter-lived one — e.g. a **Singleton
  injecting a Scoped/Transient** — pins the short-lived instance for the captor's whole lifetime
  (a leak *and* a correctness bug: per-request state shared across requests, e.g. a captured
  `DbContext`). Enable scope validation (`validateScopes: true` / dev default) to catch "Cannot
  consume scoped service from singleton".
- **Transient `IDisposable` tracked by the container**: MS DI **tracks** transient and scoped
  services that implement `IDisposable` and only disposes them when their scope (or the root
  container) is disposed. Transient disposables resolved from the **root/long-lived container** are
  never released until shutdown — an accumulating leak. Don't register `IDisposable` as transient
  resolved at root; use a factory / explicit scope (`IServiceScopeFactory.CreateScope`) instead.
- **Service-locator / resolving inside loops on the hot path**: calling `GetService`/
  `GetRequiredService` (or injecting `IServiceProvider`/a factory and resolving at runtime) inside
  a request loop pays repeated lookup/allocation cost and hides the dependency — prefer
  constructor injection so the graph is built once per scope.
- **Container build/warm-up not amortized at startup**: first-resolve compilation (expression-tree
  /reflection registration) adds cold-start latency — build the provider once at startup and warm
  expensive singletons during initialization rather than on the first user request (see the
  payload-startup lane).
- **Property / reflection-based activation vs constructor injection**: property injection and
  convention/reflection-based registration are slower to resolve and harder to validate than
  constructor injection; the built-in MS DI container doesn't support property injection (a reason
  to reach for a third-party container) — prefer constructor injection where the container allows.
