# .NET performance module: Object mapping (AutoMapper / Mapperly)
> Load when `AutoMapper`, `Riok.Mapperly`, `IMapper`, `.Map<`, `.ProjectTo<` is detected — see the module map in `../dotnet.md`. Core lanes + Variant notes live in `../dotnet.md`; this file is the Object mapping (AutoMapper / Mapperly) lens only.

## Object mapping (AutoMapper / Mapperly)

> Cross-cutting on **both** runtimes. Two distinct models: reflection-based **AutoMapper**
> (`IMapper.Map<>` / `ProjectTo<>`, configured via `MapperConfiguration` / `Profile`s) and
> source-generated **Mapperly** (`[Mapper]` partial classes, compile-time, zero reflection).
> Bullets are *conditions to look for* — the recurring theme is reflection/config cost paid in hot
> loops or over large collections, and missed query-side projection.

- **Configure once, reuse the mapper**: building a `MapperConfiguration` or `new Mapper(...)` per
  call re-scans `Profile`s by reflection and rebuilds the type maps — a real per-call cost. Build
  the config **once** and register `IMapper` as a **singleton**, then reuse it (it is thread-safe);
  resolving or constructing it per request defeats AutoMapper's internal plan caching
  (cross-reference the **Dependency injection (containers)** module — this is the canonical
  "expensive, stateless, thread-safe object registered as Transient/Scoped" case).
- **`ProjectTo<TDto>()` over `IQueryable` instead of `Map<>` after materializing**: `ProjectTo`
  emits the projection into the SQL `SELECT` so the database returns **only the mapped columns** and
  EF never materializes or change-tracks full entities. The anti-pattern is `.ToList()` (or
  `.ToListAsync()`) **then** `.Map<List<TDto>>(...)`, which pulls whole entities into memory first
  and maps in-process — far more I/O, allocation, and tracking overhead (cross-reference the
  **Data access — SQL Server** module: over-fetching and missing `AsNoTracking()`).
- **Reflection cost of complex / nested / conditional maps**: custom `ITypeConverter`,
  `MapFrom`/`ConvertUsing` resolvers, `AfterMap`/`BeforeMap` hooks, and deep member-by-member
  mapping run per element — in a hot loop or over a large collection this dominates. Measure before
  assuming the map is cheap; the cost scales with map complexity × element count.
- **Mapping very large collections element-by-element**: even a well-configured map allocates and
  invokes per item. On the hottest paths a hand-written projection (`Select(x => new TDto { ... })`)
  — pushed into the query via `ProjectTo`/`Select` where the source is `IQueryable` — is often
  measurably faster; reserve the generic mapper for cooler paths where developer ergonomics win.
- **Source-generated mapping (Mapperly) for hot paths / AOT**: `Riok.Mapperly` generates the
  mapping code at **compile time** with **zero runtime reflection** and **no runtime configuration**,
  making it trimming-safe and Native-AOT-friendly and typically several times faster (and
  lower-allocation) than reflection-based AutoMapper on the same map. Prefer it for hot paths and
  AOT/trimmed apps; the generated code is plain readable C# and accepts hand-written partial methods
  for custom cases (verify against the currency brief for your version).
- **Over-mapping**: mapping fields the consumer never reads wastes work on every call — map only the
  members the DTO actually exposes, and right-size the DTO to the screen/endpoint that consumes it.
- **Deep graph mapping triggering lazy loads**: mapping a navigation property that isn't eagerly
  loaded fires a lazy-load query per access during the map — a classic accidental N+1 hidden inside
  the mapper (cross-reference the **Data access — SQL Server** module N+1 bullet). `ProjectTo`
  sidesteps this by projecting the whole graph in one query; in-memory `Map<>` over partially-loaded
  entities does not.
