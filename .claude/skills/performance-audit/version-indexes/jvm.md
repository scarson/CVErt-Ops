---
index_schema_version: 1
ecosystem: jvm
covered_through: "Java 21 LTS / Spring Boot 3.2 / Hibernate 6.6"
built_on: 2026-06-03
sources:
  - https://docs.oracle.com/en/java/javase/21/migrate/significant-changes-jdk-release.html
  - https://www.oracle.com/java/technologies/javase/21-relnote-issues.html
  - https://www.oracle.com/java/technologies/javase/22-relnote-issues.html
  - https://www.oracle.com/java/technologies/javase/9-new-features.html
  - https://docs.oracle.com/en/java/javase/21/core/virtual-threads.html
  - https://docs.oracle.com/en/java/javase/21/gctuning/available-collectors.html
  - https://docs.oracle.com/en/java/javase/21/gctuning/garbage-first-g1-garbage-collector1.html
  - https://docs.oracle.com/en/java/javase/21/gctuning/z-garbage-collector.html
  - https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-3.2-Release-Notes
  - https://docs.spring.io/spring-boot/reference/features/spring-application.html
  - https://spring.io/blog/2022/09/26/native-support-in-spring-boot-3-0-0-m5
  - https://hibernate.org/orm/releases/6.6/
  - https://docs.hibernate.org/orm/6.0/migration-guide/migration-guide.html
  - https://in.relation.to/2024/08/08/orm-660/
---
# JVM (Java/Kotlin) performance version index
> Build-once lookup. The idiom-currency lane consults this first; live research only extends past
> `covered_through`.

## Support cadence (LTS)
Java ships every 6 months but enterprises track **LTS releases only**: **8, 11, 17, 21, 25** (~2-yr
cadence since 17). Non-LTS feature releases (18, 19, 20, 22, 23, 24, …) get ~6 months of updates, so a
perf feature that landed in a non-LTS release is usually **not adoptable** by an LTS-bound project until
it rolls into the next LTS. Recommend the best option on the project's LTS line, or flag the
support-track tradeoff explicitly — do not blanket-recommend "upgrade to the latest Java." (Most entries
below are anchored to an LTS; preview/incubator features are marked.)

## Concurrency

- **Virtual threads (`Thread.ofVirtual()` / `Executors.newVirtualThreadPerTaskExecutor()`)** — GA in **Java 21 (JEP 444)** — lightweight JVM-managed threads scheduled on a carrier thread pool; enables thread-per-request at millions of concurrent tasks without the OS-thread overhead; benefit is throughput (scale), not per-task latency — supersedes thread-pool sizing gymnastics for I/O-bound blocking code — use when: every concurrent I/O-bound task gets its own virtual thread; write plain blocking code (JDBC, HttpClient, `sleep`) inside the thread body; never pool virtual threads.
- **`synchronized` pinning caveat (Java 21)** — **Java 21** — a virtual thread entering a `synchronized` block pins to its OS carrier thread for the duration, limiting concurrency; the JIT does NOT unpin on I/O — use `ReentrantLock` (or `StampedLock`) in place of `synchronized` on hot I/O paths inside virtual threads; detect pinning events with JFR event `jdk.VirtualThreadPinned` or `-Djdk.tracePinnedThreads=full`; Java 24 (JEP 491) partially resolves this for some cases but Java 21 LTS users must use `ReentrantLock`.
- **`ThreadLocal` memory explosion with virtual threads (Java 21)** — **Java 21** — each virtual thread is a distinct thread object; `ThreadLocal` caching patterns (e.g., `SimpleDateFormat`) that rely on thread-pool reuse instantiate one copy per task and bloat heap — supersedes `ThreadLocal`-cached objects for virtual-thread workloads — use immutable, shared objects or Scoped Values (preview in Java 21, stable in Java 23) instead; `ThreadLocal` remains fine for per-request context values (user ID, trace ID).
- **Scoped Values (JEP 446, preview Java 21; JEP 487, second preview Java 22)** — **preview, not stable in Java 21 LTS** — immutable, per-thread-hierarchy values shared down a call tree without method parameters; lower overhead than `ThreadLocal` with virtual threads — do not use in production on Java 21 LTS without preview flag; target stable release.
- **Structured Concurrency (JEP 453, preview Java 21)** — **preview, not stable in Java 21 LTS** — `StructuredTaskScope` treats fan-out subtasks as a single unit with coordinated cancellation and error propagation; pairs with virtual threads for readable fan-out — do not use without `--enable-preview`; target Java 23+ for stable API.

## Garbage Collection

- **G1GC as default collector** — default since **Java 9** — balanced pause-time + throughput GC; target 200 ms pauses via `-XX:MaxGCPauseMillis`; supersedes Parallel GC (Java 8 default) for most server workloads — use Parallel GC only when throughput is the sole goal and pauses are irrelevant.
- **G1 humongous object allocation** — **Java 9+** (G1 default) — objects ≥ 50% of a G1 region (1–32 MB, ergonomically ~1–32 MB, usually 1 MB at 2 GB heap) bypass the young generation and go directly to old-gen regions, triggering more frequent Full GCs — monitor with `-Xlog:gc+humongous` or JFR; reduce oversized allocations (large byte arrays, unbounded `ArrayList.toArray()`) to stay below the threshold; use `-XX:G1HeapRegionSize=<n>m` to raise the threshold.
- **G1 string deduplication** — **Java 8u20+ / Java 9+** — background thread deduplicates equal `String` char arrays on the heap; can reduce heap by 10–20% in string-heavy apps — enable with `-XX:+UseStringDeduplication`; disabled by default; no API change required.
- **ZGC — production-ready** — production-ready since **Java 15 (JEP 377)**; experimental since Java 11 — concurrent collector with sub-millisecond GC pause times independent of heap size (100 MB–16 TB); all expensive work concurrent — enable with `-XX:+UseZGC`; replaces G1 when pause-time SLA < 10 ms is required.
- **Generational ZGC (JEP 439)** — GA in **Java 21** — ZGC extended with separate young/old generations; collects short-lived objects more frequently; reduces overall GC CPU overhead compared to non-generational ZGC while preserving sub-millisecond pauses — enable with `-XX:+UseZGC -XX:+ZGenerational` (Java 21); becomes default in Java 23+; preferred over legacy `-XX:+UseZGC` for Java 21 targets.
- **G1 Region Pinning for JNI (JEP 423)** — GA in **Java 22** — eliminates the need to pause/disable GC during JNI critical regions; reduces latency spikes for JNI-heavy code (Unsafe, off-heap access) — automatic when using Java 22+; no flag or API change; backport not available for Java 21 LTS.

## Language & Runtime

- **Compact Strings (JEP 254)** — GA in **Java 9** — `String`, `StringBuilder`, `StringBuffer` store Latin-1 content as one byte per char instead of two; reduces heap footprint of typical String-heavy apps by ~50% — automatic; disable only if profiling shows encoding overhead on non-Latin-1 dominated workloads with `-XX:-CompactStrings`.
- **Records (JEP 395)** — GA in **Java 16** (preview Java 14–15) — concise, immutable data carriers with compiler-generated `equals`, `hashCode`, `toString`, and accessors; zero overhead vs a hand-written equivalent; ideal as DTOs, result tuples, and value objects — supersedes verbose POJO classes for data transfer shapes; use as Hibernate projections and Spring controller response types to avoid entity-graph mutation.
- **Pattern matching for `instanceof` (JEP 394)** — GA in **Java 16** — eliminates explicit cast after type check: `if (obj instanceof String s) { s.length(); }` — no runtime overhead difference; eliminates defensive cast allocation on some JIT paths — supersedes `instanceof` + cast idiom.
- **Pattern matching for `switch` (JEP 441)** — GA in **Java 21** — switch over type patterns and guarded patterns; compiler exhaustiveness checking; enables concise multi-type dispatch without `instanceof` chains — use when dispatching on sealed-type hierarchies or mixed-type unions.
- **Record patterns (JEP 440)** — GA in **Java 21** — deconstruct record components inline in `instanceof` and `switch` pattern positions, avoiding intermediate variable extraction — composable with nested patterns for deep data navigation without boilerplate.
- **Sealed classes (JEP 409)** — GA in **Java 17** — restrict the set of permitted subtypes; enables exhaustive `switch` and removes the need for a default branch that would hide missing cases at compile time — pair with record patterns and pattern-matching switch for algebraic-data-type style dispatch.
- **`String` concatenation via `invokedynamic` (JEP 280)** — GA in **Java 9** — `+` string concatenation compiled to `invokedynamic`; JIT can optimise and specialise per call site; eliminates intermediate `StringBuilder` objects on many paths — automatic; no API change; benefit is most visible in JDK 9+ without `-source 8` mode.

## SIMD & Native (Incubator / Preview — not stable)

- **Vector API (JEP 448, sixth incubator Java 21; JEP 460, seventh incubator Java 22)** — **INCUBATOR — do not use in production without `--add-modules jdk.incubator.vector`** — expresses SIMD computations (add, multiply, FMA, blend, shuffle) over `FloatVector`, `IntVector`, etc. that compile to AVX/AVX2/AVX-512 or NEON on capable hardware; performance superior to equivalent scalar loops — API is still in incubator as of Java 22; subject to breaking changes; target stabilisation in a future Java release; only suitable for internal tooling or performance experiments.
- **Foreign Function & Memory API (JEP 454)** — GA in **Java 22** (third preview in Java 21, JEP 442) — call native C libraries and access off-heap memory without JNI; `MemorySegment` + `Arena` for safe deterministic off-heap lifecycle; `Linker` for calling conventions; avoids JNI performance penalties and class-loading overhead — supersedes JNI for new off-heap and native-interop code; Java 21 LTS users have third-preview only (requires `--enable-preview`); use GA form on Java 22+.
- **Project Valhalla (value types / primitive classes)** — **NOT YET GA** — inline/primitive class types would eliminate heap allocation and identity overhead for small, immutable value objects (e.g., `Complex`, `Coordinate`); JIT can pass them in registers — do not code against Valhalla APIs; watch JEP pipeline for a future LTS delivery.

## Spring & Hibernate

- **Spring Boot 3.0 AOT engine + GraalVM native image** — GA in **Spring Boot 3.0 (Nov 2022)** — build-time `spring-aot-maven-plugin` / Gradle equivalent pre-computes bean definitions, evaluates `@Conditional` branching, and generates reachability metadata; enables `native-image` compilation to a static binary with near-instant startup and reduced heap; supersedes the experimental Spring Native 0.x project — use `-Pnative mvn package` or `bootBuildImage`; requires trimming-compatible code (no unregistered reflection, no dynamic proxy not annotated); trade-off: classpath and profile selection fixed at build time.
- **Spring Boot 3.2 virtual thread support** — GA in **Spring Boot 3.2 (Nov 2023)** (requires Java 21) — setting `spring.threads.virtual.enabled=true` makes Tomcat and Jetty serve requests on virtual threads; `applicationTaskExecutor` becomes `SimpleAsyncTaskExecutor` (virtual); task scheduler, RabbitMQ, Kafka, and Pulsar consumers also switch to virtual-thread executors — supersedes manual `Executors.newVirtualThreadPerTaskExecutor()` bean wiring for Spring MVC apps — ensure `synchronized`-heavy third-party code (e.g., legacy JDBC drivers) does not cause pinning; test with JFR before rolling out.
- **Spring Boot lazy initialization** — available since **Spring Boot 2.2** — `spring.main.lazy-initialization=true` defers all non-essential bean creation to first use; reduces startup time significantly for large apps — caveat: misconfigured beans fail at first request, not at startup; use `-Dspring.main.lazy-initialization=true` in dev; review carefully before enabling in production; pair with `@Lazy(false)` on beans that must initialise at startup (health checks, data sources).
- **Hibernate 6.0 `jakarta.persistence` migration** — **Hibernate 6.0** (shipped with Spring Boot 3.0) — all JPA annotations and settings moved from `javax.persistence.*` to `jakarta.persistence.*`; also: `ResultSet` reads now by column position (not name), improving JDBC fetch throughput; HQL/Criteria queries compiled directly to SQM (Semantic Query Model) without intermediate HQL rendering — required migration step for Spring Boot 3.x; no opt-in needed, but legacy `javax.persistence` imports break compilation.
- **Hibernate 6.0 bulk DML via CTE** — **Hibernate 6.0** — SQM bulk `UPDATE`/`DELETE` statements use a CTE strategy that executes as a single database statement rather than fetching IDs to a temporary table first; removes O(n) round-trips for bulk mutations — automatic when using Hibernate 6.x; no API change; reduces network overhead for `DELETE FROM … WHERE …` / `UPDATE … SET …` HQL/Criteria patterns.
- **Hibernate 6.6 `StatelessSession` for Jakarta Data** — **Hibernate 6.6** — `StatelessSession` enhanced and promoted as the backing session for Jakarta Data 1.0 repositories (via `hibernate-jpamodelgen` annotation processor); `StatelessSession` bypasses first-level cache, change tracking, and proxies, giving lower overhead for bulk read or write-once pipelines — use `StatelessSession` directly (or via Jakarta Data) for ETL, reporting, and batch-insert workloads where change tracking adds no value.
- **Records as Hibernate projections** — **Hibernate 6.x** (Java 16+ records) — HQL `SELECT new com.example.MyRecord(e.id, e.name) FROM Entity e` and JPQL constructor expressions work with records as the target type; records' canonical constructor is used; avoids materialising full entity objects for read-only query results — supersedes result-bean POJO constructors for projection queries.
