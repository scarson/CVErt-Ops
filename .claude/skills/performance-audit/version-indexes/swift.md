---
index_schema_version: 1
ecosystem: swift
covered_through: "Swift 6.2 / iOS 18"
built_on: 2026-06-03
sources:
  - https://www.swift.org/blog/swift-5.5-released/
  - https://www.swift.org/blog/swift-5.6-released/
  - https://www.swift.org/blog/swift-5.7-released/
  - https://www.swift.org/blog/swift-5.9-released/
  - https://www.swift.org/blog/swift-5.10-released/
  - https://www.swift.org/blog/announcing-swift-6/
  - https://www.swift.org/blog/swift-6.2-released/
  - https://developer.apple.com/videos/play/wwdc2023/10149/
  - https://github.com/swiftlang/swift-evolution/blob/main/proposals/0390-noncopyable-structs-and-enums.md
  - https://github.com/swiftlang/swift-evolution/blob/main/proposals/0423-dynamic-actor-isolation.md
---
# Swift performance version index
> Build-once lookup. The idiom-currency lane consults this first; live research only extends past
> `covered_through`.

## Concurrency — Structured Concurrency & Actors

- **`async`/`await`, `async let`, structured concurrency (`TaskGroup`, `withTaskGroup`)** — landed in **Swift 5.5** (SE-0296, SE-0304, SE-0317) — eliminates callback pyramids and manual `DispatchQueue` fan-out; `async let` runs independent work concurrently with zero-boilerplate — supersedes `DispatchQueue.async` + `DispatchGroup` for structured parallel work — use when launching ≥2 independent async operations in the same scope.
- **Actors and `@MainActor`** — landed in **Swift 5.5** (SE-0306, SE-0316) — actors serialize access to mutable state without locks, eliminating data races; `@MainActor` replaces manual `DispatchQueue.main.async` dispatches back to the UI thread — supersedes `DispatchQueue`-protected shared state — use actors for shared mutable state; annotate `@MainActor` on any type or function that must run on the main thread.
- **`AsyncSequence` / `AsyncStream` / `AsyncThrowingStream`** — landed in **Swift 5.5** (SE-0298, SE-0314) — pipeline-friendly streaming of async values without buffering full results; `AsyncStream` bridges callback-based APIs — supersedes accumulating all results in an array before processing — use `for await` to process items as they arrive.
- **`DiscardingTaskGroup` / `ThrowingDiscardingTaskGroup`** — landed in **Swift 5.9** (SE-0381) — task group that automatically releases completed child task memory rather than accumulating it; prevents unbounded memory growth in long-running server loops — supersedes regular `withTaskGroup` for fire-and-forget server accept/request loops — use for HTTP/RPC server loops that spawn a task per connection.
- **Custom actor executors** — landed in **Swift 5.9** (SE-0392) — allows specifying a custom `SerialExecutor` for an actor (e.g., to pin work to a specific thread or queue) — supersedes `@preconcurrency` workarounds for integrating actors with dispatch-queue-based subsystems.
- **`nonisolated` async functions run in caller context** — landed in **Swift 6.2** — `nonisolated async` functions no longer unconditionally hop to the global executor; they run in the caller's execution context, eliminating unnecessary thread switches — supersedes detached-task workarounds for lightweight async functions — use to reduce actor-hop overhead on frequently-called `nonisolated` async utilities.

## Concurrency — Safety & Checking

- **`-warn-concurrency` / incremental `Sendable` checking** — opt-in in **Swift 5.6** (SE-0337) — surfaces data-race warnings without breaking existing code; first step of concurrency migration.
- **`-strict-concurrency=complete`** — available in **Swift 5.10** (SE-0412 and related) — enables full data isolation checking at compile time, catching all potential data races; `nonisolated(unsafe)` keyword added to opt out per-property without wrapper types — use `-strict-concurrency=complete` in new modules; migrate existing code incrementally before enabling Swift 6 language mode.
- **Swift 6 language mode (data-race safety)** — **Swift 6.0** (2024) — opt-in per target via `swift-language-version: 6` in SwiftPM or `SWIFT_VERSION = 6` in Xcode; enforces `Sendable` and actor isolation at compile time, eliminating entire class of runtime data races — supersedes warning-only mode — use for new targets; existing targets migrate using upcoming feature flags.
- **Dynamic actor isolation checks (`@preconcurrency`)** — **Swift 6.0** (SE-0423) — runtime actor isolation checks are only emitted at boundaries where isolation cannot be statically verified, minimising overhead; checks are progressively eliminated as the ecosystem adopts Swift 6.

## Memory & Ownership

- **Noncopyable types `~Copyable` (`consuming`, `borrowing`, `consume`)** — landed in **Swift 5.9** (SE-0390); expanded to work with generics in **Swift 6.0** — noncopyable structs/enums avoid heap allocation and reference counting by enforcing unique ownership; `consuming`/`borrowing` parameter modifiers eliminate unnecessary copies and ARC traffic on hot paths — supersedes `class` for uniquely-owned resources (file descriptors, locks, hardware handles) — use when a type should not be copied and ARC overhead is measurable.
- **`Span<T>`** — landed in **Swift 6.2** — safe, bounds-checked, non-owning view into contiguous memory with zero runtime overhead; analogous to .NET `Span<T>`; prevents use-after-free without unsafe pointers — supersedes `UnsafeBufferPointer` for read-only buffer access — use for hot-path buffer processing that previously required unsafe pointers.
- **`InlineArray<N, T>`** — landed in **Swift 6.2** — fixed-size array with inline (stack or inline-in-struct) storage; no heap allocation for bounded collections — supersedes heap-allocated `Array` for small, fixed-count buffers — use for sprite lists, ring buffers, argument lists, and similar bounded hot-path buffers.
- **ARC optimizer improvements (shorter variable lifetimes)** — **Swift 5.7** — compiler automatically shortens `class`-instance lifetimes, reducing the window during which retain/release pairs must be emitted; removes the need for `withExtendedLifetime()` workarounds in many cases — automatic; no API change required.

## Observation & SwiftUI Reactivity

- **`@Observable` macro (Observation framework)** — landed in **Swift 5.9 / iOS 17 / macOS 14** — provides fine-grained, property-level SwiftUI tracking; SwiftUI only invalidates a view when a property it actually accessed changes, not on any property change — supersedes `ObservableObject` + `@Published` which trigger full-view invalidation on any `@Published` change — use `@Observable` for all new view models targeting iOS 17+; existing `ObservableObject` types can be migrated by removing `ObservableObject` conformance, `@Published` annotations, and adopting `@Observable`.
- **`@Observable` async sequence (`withObservationTracking`)** — **Swift 6.2** — synchronous state changes within a single transaction are batched, preventing redundant SwiftUI body recalculations — automatic when using `@Observable`; no extra code required.
- **`@Bindable`** — **Swift 5.9 / iOS 17** — replaces `@ObservedObject` binding pattern for `@Observable` types; requires no `@Published`; eliminates `$`-projection boxing overhead.

## SwiftData

- **SwiftData (`@Model`, `ModelContext`, `@Query`)** — landed in **Swift 5.9 / iOS 17 / macOS 14** — Swift-native persistence layer built on Core Data; `@Query` provides automatic reactive data loading in SwiftUI with no manual fetch-request boilerplate — supersedes `NSFetchedResultsController` + `NSManagedObject` for new targets on iOS 17+ — use `FetchDescriptor` with `fetchLimit` / `includePendingChanges` to control faulting and N+1 behaviour (verify against the currency brief for your version).
- **SwiftData background context** — **Swift 5.9 / iOS 17** — `ModelContext` created off the main actor (via `ModelContainer.mainContext` only on main actor; use `backgroundContext()` for writes) — supersedes Core Data `performBackgroundTask` pattern — use for batch imports and heavy writes to avoid blocking the main thread.

## Serialization & Foundation

- **swift-foundation / FoundationEssentials rewrite** — landed in **Swift 5.9 era / open-sourced 2023, shipping in production 2024** — rewrite of Foundation in Swift; `JSONDecoder`/`JSONEncoder`, `Date`, `Calendar`, `URL`, and `Locale` are significantly faster (reported 2–4× JSON decode speedups on microbenchmarks); replaces Objective-C Foundation implementations on non-Apple platforms and progressively on Apple platforms — automatic for server-side Swift on Linux; Apple platforms adopt incrementally (verify platform adoption against the currency brief for your version).

## Type System & Generics

- **`some` (opaque return types) vs `any` (existentials) clarity** — `some` landed in **Swift 5.1**; `any` keyword required for existentials in **Swift 5.7** (SE-0335) — `some` enables static dispatch and compiler optimisation of the concrete type; `any Protocol` forces heap boxing and dynamic dispatch — use `some` / generic constraints (`<T: P>`) on hot-path APIs; reserve `any` for heterogeneous collections or type-erasure boundaries.
- **Regex / `RegexBuilder`** — landed in **Swift 5.7** (SE-0350–0363) — native `Regex<Output>` type compiled at build time from regex literals (no runtime compilation cost); `RegexBuilder` DSL for composable patterns — supersedes `NSRegularExpression` (ObjC, always compiled at runtime) — use `let r = /pattern/` for literals; `NSRegularExpression` benchmarks ~10× slower for repeated use on large input.
- **Typed throws (`throws(E)`)** — landed in **Swift 6.0** — functions can declare a specific `Error` conforming type; enables the compiler to avoid existential boxing of errors on hot throwing paths — supersedes untyped `throws` for performance-sensitive code where the error type is always the same concrete type — use in tight loops or codecs where error values must not be heap-boxed.
- **Macros (`@freestanding`, `@attached`)** — landed in **Swift 5.9** — compile-time code generation replaces runtime reflection patterns; no runtime overhead for macro-expanded code — use to replace boilerplate that previously required runtime `Mirror`/reflection.

## Synchronization

- **`Synchronization` module — `Atomic<T>`, `Mutex<T>`** — landed in **Swift 6.0** — lock-free atomics (`Atomic`) and a lightweight mutex (`Mutex`) with value semantics, backed by platform primitives — supersedes `DispatchSemaphore`, `NSLock`, and `os_unfair_lock` wrappers for new code — `Atomic` for single-variable CAS patterns; `Mutex` for protecting a small critical section; both avoid the Objective-C overhead of `NSLock` (verify against the currency brief for your version).

## Embedded Swift

- **Embedded Swift** — preview in **Swift 5.9**; production-capable in **Swift 6.0** — compile mode that produces small, standalone binaries with no Swift runtime dependency via generic specialisation and dead-code stripping; targets microcontrollers and resource-constrained environments — use `-experimental-feature Embedded` (5.9) / `swiftSettings: [.enableExperimentalFeature("Embedded")]`; `InlineArray` and `Span` available in Embedded as of Swift 6.2.

## Startup & Build

- **Whole-Module Optimization (WMO)** — available since **Swift 3**; ensure enabled for release — cross-function inlining, dead-code elimination, and devirtualisation impossible with per-file compilation; material startup and throughput benefit for any non-trivial codebase — verify Xcode release config has `SWIFT_COMPILATION_MODE = wholemodule`; SwiftPM enables it by default for release builds.
- **`SWIFT_DISABLE_SAFETY_CHECKS`** — runtime bounds checks and overflow traps are on by default; disabling them in release (`-Ounchecked`) is a last resort for inner numeric loops where correctness is provably guaranteed — use only after profiling confirms bounds checks are the bottleneck; never disable globally.
