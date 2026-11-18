# Profile Pack: JVM (Java / Kotlin)

Specializes the generic lanes for Java/Kotlin stacks (Spring, Hibernate/JPA, standard library).
Load alongside `generic-pack.md`; signals here augment, not replace, the generic signals.

---

## Algorithmic complexity & data structures (lane `algorithmic`)
- `List.contains` / `List.remove` / `List.indexOf` inside a loop — O(n²); replace the list with a `HashSet` or `LinkedHashSet` for membership tests, or pre-build a lookup `Map` keyed on the relevant field.
- Repeated computation of a loop-invariant value (regex compile, format-string parse, expensive factory call) inside the loop body; hoist before the loop or use a static final.
- Nested stream pipelines that each traverse the same collection independently; flatten into a single pass or restructure with a `Map`/`Multimap` grouping.
- `LinkedList` used for random access or indexed iteration (O(n) per `get`); `ArrayList` used for frequent head removal or FIFO queuing — wrong structure for the access pattern.
- `TreeMap`/`TreeSet` chosen for unsorted data where only hashing is needed — log(n) overhead with no ordering benefit; prefer `HashMap`/`HashSet`.
- Comparing or sorting by a field computed inside the comparator (e.g., `Comparator.comparing(x -> expensiveDerive(x))`) without memoization — the derivation runs O(n log n) times; extract to a decorated sort.

## Memory & allocation (lane `memory`)
- Autoboxing primitives in hot paths (`int` → `Integer`, `long` → `Long`, etc.); prefer primitive streams (`IntStream`, `LongStream`, `DoubleStream`) or primitive-specialised collections (verify against the currency brief for your version).
- `String` concatenation (`+`) inside a loop — the compiler does not always collapse these; use `StringBuilder` explicitly, or `String.join` / `StringJoiner` for delimiter-separated values.
- Stream pipelines in tight inner loops where lambda capture allocates a closure object per call and intermediate stages allocate wrapper spliterators; a plain `for` loop is zero-allocation.
- `collect(toList())` or `collect(toSet())` on a very large dataset that is then immediately reduced to a scalar — pipeline lazily to the terminal without materialising the intermediate collection.
- `ThreadLocal` caching expensive mutable objects (e.g., `SimpleDateFormat`, heavyweight parsers) — safe with platform thread pools, but each virtual thread is never pooled, so one object is allocated per task and never reused; use a shared immutable alternative (e.g., `DateTimeFormatter`) or an explicit pool (verify against the currency brief for your version).
- Large allocations that exceed the G1 region-size threshold become "humongous objects", bypass the young generation, and are collected only at mixed/full GC — look for very large byte arrays, large `ArrayList`/`HashMap` literals, or bulk-copy patterns in hot paths.
- Unbounded `static` caches or maps that grow without eviction, causing sustained heap pressure and increasingly frequent GC cycles.

## Data access & I/O (lane `data-access`)
- Hibernate/JPA N+1: lazy associations accessed inside a loop trigger one `SELECT` per row; fix with `JOIN FETCH` in JPQL, `@EntityGraph` at the repository method, or `@BatchSize` on the collection mapping to batch proxy loads (verify against the currency brief for your version).
- Multiple `@OneToMany` associations loaded simultaneously with `FetchType.EAGER` — can produce a Cartesian-product result set whose row count is the product of collection sizes; use explicit `JOIN FETCH` for one association at a time or separate queries.
- Per-row inserts/updates inside a loop (`save` inside `for`); use `saveAll` / `executeBatch` and confirm batch mode is enabled in the datasource config — Hibernate silently skips batching if identity generators are used (verify against the currency brief for your version).
- `SELECT *` or fetching full entities when only a subset of columns is needed downstream; prefer interface-based projections or DTO query results to limit the transferred payload.
- Missing pagination: `findAll()` or unbounded `@Query` on a table with unbounded growth; always apply `Pageable` / `LIMIT`+`OFFSET` or cursor-based pagination.
- Chatty round-trips inside a loop — sequential calls to an external service or cache for each element; coalesce into a single batched call and look up from the returned map.
- Lazy-association access outside a transaction boundary — causes `LazyInitializationException` at runtime or forces an implicit session open, masking latency; ensure the service layer opens a transaction that covers all association traversals.

## Concurrency & parallelization (lane `concurrency`)
- **Defend:** `synchronized` block enclosing more work than necessary (I/O, network, heavy computation); narrow the critical section to the minimum shared-state mutation, or replace with `ReentrantLock` / `ReadWriteLock` when reads vastly outnumber writes, or with `ConcurrentHashMap` / `AtomicReference` for lock-free access.
- `synchronized` block wrapping blocking I/O when virtual threads are in use — pinning keeps the carrier OS thread blocked and defeats the concurrency model; replace with `ReentrantLock` for long-lived critical sections (verify against the currency brief for your version).
- `ThreadPoolExecutor` core/max sizes not matched to workload type: CPU-bound pools should not exceed available cores; I/O-bound pools can safely exceed core count; a shared pool mixing both starves one kind.
- Blocking calls (`Thread.sleep`, synchronous JDBC, blocking HTTP client) on reactive or async dispatch threads (Netty event-loop, RxJava scheduler, Reactor `parallel`); offload to a bounded `Schedulers.boundedElastic()` or equivalent blocking-capable pool.
- **Exploit:** sequential `for` loops over large, truly independent items — consider `parallelStream()` or `CompletableFuture.allOf`; but verify independence (stateless lambdas, no shared mutable state, no ordering dependency, no `synchronized`/blocking inside the lambda) before suggesting parallel execution.
- `parallelStream()` on small collections, or with stateful intermediate operations (`distinct`, `sorted`, `limit`, `skip`) on ordered sources — parallel overhead exceeds benefit; add `.sequential()` or switch to a plain loop.
- `CopyOnWriteArrayList` used for write-heavy scenarios — every mutation copies the full array; prefer `ConcurrentLinkedQueue` or a lock-guarded structure for write-heavy cases.

## Framework-idiom currency (lane `idiom-currency`)
- Consult the currency brief/index for Spring Boot, Hibernate/JPA, and Jackson.
- Flag any patterns the brief marks superseded or deprecated; flag fast-path APIs the brief lists that the code doesn't use; flag changed defaults the code still overrides unnecessarily.
- Offline (no brief): flag candidate idiom concerns at LOW confidence, marked for manual currency check.

## Payload / startup / build (lane `payload-startup`)
- Spring component scan over a broad base package (e.g., the root application package) forces the container to inspect every classpath entry at boot; narrow `@ComponentScan` to the smallest meaningful sub-packages, or switch to explicit `@Bean` registration in `@Configuration` classes.
- Default eager singleton initialisation: expensive beans that are rarely exercised at runtime delay startup and inflate initial heap; apply `@Lazy` (or `spring.main.lazy-initialization=true` globally) where safe — but note that a lazy bean depended on by an eager singleton is still initialised at startup.
- Reflection-heavy frameworks (annotation processors, classpath scanners, dynamic proxy generators) block native-image compilation and increase startup cost on standard JVM; prefer AOT-friendly construction or explicit configuration (verify against the currency brief for your version).
- Unused dependencies on the classpath are scanned, loaded, and sometimes auto-configured; audit for dead weight that inflates startup time and heap footprint.
- `@PostConstruct` or `InitializingBean.afterPropertiesSet` performing I/O (schema validation, remote config fetch, warm-up queries) on the main thread blocks the entire application context refresh; move to a background `ApplicationRunner` or `CommandLineRunner` if not strictly required before first request.

---

## Kotlin notes

The runtime/GC/JIT and Spring/Hibernate signals above apply equally to Kotlin-on-JVM. These are the Kotlin-specific *language* idioms with distinct perf characteristics:

- Higher-order functions allocate a `Function` object (and capture closure) per call; mark hot HOFs `inline` to eliminate that allocation (also enables `reified`) — but avoid `inline`-ing large bodies, which bloats bytecode at every call site.
- Boxing of nullable/boxed primitives: `Int?`/`Long?`/`Boolean?` and `Array<Int>` box to `java.lang.Integer` etc.; in hot paths and large collections use non-null primitives and primitive arrays (`IntArray`/`LongArray`/`DoubleArray`).
- Eager collection-operator chains (`list.map{ }.filter{ }…`) allocate a new intermediate `List` at each step; for large collections use `.asSequence()` for lazy single-pass evaluation (plain loops or eager ops win for small ones).
- `runBlocking` on a request/hot path, or blocking calls on a dispatcher not meant for blocking, starve the coroutine pool; use `withContext(Dispatchers.IO)` for blocking work and keep CPU work on `Dispatchers.Default`.
- `const val` (compile-time inlined at call sites) vs `val` (field read); `@JvmStatic` / `@JvmField` avoid synthetic accessor/getter overhead on Java-interop hot paths.
- Delegated properties (`by lazy`, `Delegates.observable`) add a per-property delegate object + indirection — fine generally, but watch in hot, frequently-instantiated types.

---

## Sources

Durable signals in this pack are grounded in these authoritative sources (version-specific facts and
their per-entry citations live in `../version-indexes/jvm.md`):

- Hibernate ORM User Guide — fetching / N+1 (docs.hibernate.org)
- Oracle JDK docs — virtual threads, `java.util.concurrent`, Stream API, GC tuning guide
- Spring Framework / Spring Boot reference — lazy initialization, bean registration, AOT/native
