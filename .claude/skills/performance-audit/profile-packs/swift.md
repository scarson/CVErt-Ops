# Profile Pack: Swift

Specializes the generic lanes for Apple-platform Swift (SwiftUI/UIKit, Core Data/SwiftData, Xcode/SwiftPM) and server Swift (Vapor). Signals below are durable idioms; volatile version details live in the currency brief / version index, not here.

---

## Algorithmic complexity & data structures (lane `algorithmic`)
- `Array.contains(_:)` / `firstIndex(where:)` called inside a loop over a second collection — accidental O(n²); replace the inner lookup with a `Set` or `Dictionary` keyed on the relevant field.
- Existential `any Protocol` in hot loops: dynamic dispatch + heap boxing on every call; prefer constrained generics (`some P` or `<T: P>`) where the concrete type is knowable at the call site (verify against the currency brief for your version).
- `String` is not integer-indexable in O(1) — subscripting by `Int` offset requires walking grapheme clusters; offset-arithmetic loops over `String` are O(n²); use `String.Index` iteration, `Substring` slicing, or convert to `[Character]` / UTF-8 bytes once.
- Repeated pure computations inside loops that depend only on loop-invariant values — hoist before the loop or cache in a local `let`; applies equally to computed properties accessed in tight render/update cycles.
- Re-sorting or re-filtering the same collection on every data-read or view-update; sort/filter once on input change and store the result.

## Memory & allocation (lane `memory`)
- ARC retain/release overhead on reference types inside hot loops — consider passing `inout` or using value types; each assignment to a `class` instance increments a reference count.
- Retain cycles in closure captures: `self` captured strongly by a long-lived callback, timer, or notification handler; use `[weak self]` or `[unowned self]` capture lists and confirm the object's lifetime before choosing `unowned`.
- Copy-on-Write (CoW) semantics of `Array`, `Dictionary`, `Set`, and `String`: a mutation on a shared buffer triggers a full copy; the hidden performance bug is passing a collection `inout` or assigning it through a non-uniquely-referenced path — check that the buffer is uniquely referenced before mutating.
- Large `struct` values copied repeatedly on assignment or as function arguments — consider `class` semantics, an `inout` parameter, or splitting into a reference-typed backing store for the mutable part.
- `reserveCapacity(_:)` on `Array`/`Dictionary`/`String` when the final size is known — avoids repeated geometric reallocation (verify against the currency brief for your version).
- Foundation bridging toll: implicit `NSArray`/`NSString`/`NSDictionary` ↔ Swift bridging in hot loops allocates intermediary objects; prefer pure-Swift types and defer bridging to the call boundary.
- Missing `autoreleasepool { }` around tight Objective-C-interop loops — Objective-C autoreleased objects accumulate in the run-loop pool until the loop exits; wrap the loop body to bound peak memory (verify against the currency brief for your version).

## Data access & I/O (lane `data-access`)
- Core Data N+1: iterating fetched objects and triggering fault resolution per item instead of using `fetchBatchSize` and `relationshipKeyPathsForPrefetching` to prefetch relationships in bulk; look for `for obj in results { _ = obj.relationship }` patterns.
- SwiftData equivalent: accessing a lazy relationship on each element of a `@Query` result in a loop without a prefetch descriptor — same N+1 pattern, different API surface (verify against the currency brief for your version).
- `JSONDecoder` / `JSONEncoder` allocated fresh on every hot-path call; both types are expensive to create — allocate once and reuse, or use a pool; also check for unnecessary `Data` copies before decoding.
- Main-thread file I/O or synchronous `NSManagedObjectContext` fetch on the main context — blocks the UI thread; move to a background context (`performBackgroundTask`) or `async` fetch.
- Over-fetching: Core Data `NSFetchRequest` returning full objects (all attributes) when only one or two fields are needed — set `resultType` to `NSDictionaryResultType` with `propertiesToFetch` for read-only aggregation.
- `URLSession` task created per request rather than reusing a shared session — loses connection pooling, TLS session resumption, and HTTP/2 multiplexing; create one session (or a small set by configuration) and reuse it (verify against the currency brief for your version).

## Concurrency & parallelization (lane `concurrency`)
- **Exploit:** sequential `await` of independent async operations in a function body — replace with `async let` bindings or `withTaskGroup` / `withThrowingTaskGroup` to run concurrently; verify independence (no shared mutable state, no ordering dependency) before parallelizing.
- **Exploit:** `AsyncSequence` / `AsyncStream` available but code buffers full results into an array before processing — pipeline item-by-item with `for await` to reduce peak memory and improve time-to-first-result.
- **Defend:** heavy CPU or I/O work dispatched directly on `@MainActor` (or the main `DispatchQueue`) — move it off-main via an `actor`, a detached `Task`, or `Task.detached(priority:)` and only marshal UI updates back.
- **Defend:** blocking the Swift cooperative thread pool with synchronous work (long loops, `Thread.sleep`, `DispatchSemaphore.wait`) inside an `async` context — cooperative threads are not OS threads; blocking them starves other async tasks.
- **Defend:** excessive actor hops: calling across actor boundaries for each item in a loop — batch the work inside a single actor method rather than hopping per-element.
- **Defend:** `DispatchQueue.sync` from a queue into itself (deadlock risk) or `.concurrent` queue with shared mutable state (data race); audit `DispatchQueue` usage when mixing GCD with Swift Concurrency.
- **Defend:** parallelizing without verifying `Sendable` conformance — confirm shared values are either value types with no mutable state or actors before using `withTaskGroup`; non-`Sendable` types shared across task boundaries are data-race risks (verify against the currency brief for your version).

## Framework-idiom currency (lane `idiom-currency`)
- Consult the version index and currency brief. Flag patterns the brief marks superseded/deprecated (e.g., `ObservableObject`/`@Published` where `@Observable` is available; `DispatchQueue`-based concurrency where Swift Concurrency actors/tasks are the fast path; legacy `NSFetchedResultsController` patterns vs modern SwiftData); flag fast-path APIs the index lists that the code doesn't use; flag changed defaults the code still fights.
- Offline (no brief): note candidate idiom concerns at LOW confidence, flagged for manual currency check.

## Payload / startup / build (lane `payload-startup`)
- `+load` methods, static initializers, and `__attribute__((constructor))` C functions run before `main()` during dyld startup — any expensive work here (I/O, network, large allocations) directly increases cold-start time; audit for slow `+load` in Objective-C categories.
- Whole-Module Optimization (WMO) and cross-module optimization disabled in the release build configuration — WMO enables cross-function inlining and dead-code removal that is impossible with per-file compilation; verify the Xcode/SwiftPM release config enables it (verify against the currency brief for your version).
- Binary size / dead-code stripping: unused code linked into the final binary increases cold-start load time on Apple platforms; ensure linker dead-strip and Swift whole-module optimization are both enabled for release.
- Expensive synchronous work in `application(_:didFinishLaunchingWithOptions:)` or `@main` `init` — database migration, network calls, large JSON parsing — blocks the first frame; defer to background tasks or lazy initialization.
- Large or unoptimized asset catalogs: uncompressed images or assets included in the app bundle that are never loaded at startup still inflate the binary and slow initial dyld mmap; audit with the build report.
- Dynamic framework linking adds a dyld load time cost per framework; consolidating rarely-used dynamic frameworks or preferring static linking reduces pre-`main` time (verify linker settings against the currency brief for your version).

---

## Framework notes

### SwiftUI
- Unnecessary `body` re-evaluation from observable objects with broad invalidation scope: a single `@ObservedObject` / `@StateObject` whose any property changes re-renders the entire view tree — split into smaller observed objects or migrate to `@Observable` for fine-grained property-level tracking (verify against the currency brief for your version).
- Misuse of `@StateObject` vs `@ObservedObject`: `@StateObject` creates and owns the object (created once per view identity); `@ObservedObject` borrows it from outside — using `@ObservedObject` where `@StateObject` is intended causes re-creation on every parent render, losing state and wasting allocations.
- Expensive or side-effectful work inside `body` — network calls, large computations, sorting — executes on every SwiftUI rendering pass; move to `task {}`, `.onAppear`, or a view model; `body` must be a pure, fast function of its inputs.
- Missing `LazyVStack` / `LazyHStack` / `LazyVGrid` for large or unbounded lists — `VStack` eagerly materializes all child views; replace with lazy equivalents or `List` (which is lazy by default) when rendering more than ~50 items.
- Unstable view identity from volatile `.id()` modifier or index-as-identity: changing an element's identity forces SwiftUI to destroy and recreate the full subtree (animations break, state resets); use a stable, persistent identifier.
- Over-broad `@Environment` or `@EnvironmentObject` scope: a high-level environment value that changes frequently invalidates all descendant views that read it; narrow the scope or use a more targeted observable (verify against the currency brief for your version).
- `EquatableView` / `View.equatable()`: wrapping a view whose inputs rarely change prevents re-evaluation when the parent re-renders and `Equatable` confirms equality — use where the view's `Equatable` conformance is cheap and the body re-evaluation is demonstrably costly (verify against the currency brief for your version).

---

## Sources

Durable signals in this pack are grounded in these authoritative sources (version-specific facts and
their per-entry citations live in `../version-indexes/swift.md`):

- swift.org — release blogs (Swift 5.5–6.2), "Announcing Swift 6", migration guide
- Swift Evolution proposals — SE-0390 (`~Copyable`), SE-0381 (`DiscardingTaskGroup`), SE-0412, SE-0423
- Apple Developer — Observation (`@Observable`, WWDC23 s10149), SwiftData, Core Data `fetchBatchSize`
