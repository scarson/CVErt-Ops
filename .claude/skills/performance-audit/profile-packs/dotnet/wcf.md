# .NET performance module: WCF (services)
> Load when `System.ServiceModel` (etc.) is detected — see the module map in `../dotnet.md`. Core lanes + Variant notes live in `../dotnet.md`; this file is the WCF (services) lens only.

## WCF (services)

> .NET Framework-only. Many enterprise 4.x apps still expose or consume WCF endpoints and the perf
> issues below are routinely missed in audits. (The modern successor is **CoreWCF** on .NET 6+, a
> separate package with the same programming model — note it as the migration target, but the
> conditions here apply to in-Framework WCF.) Cross-reference the **`.NET Framework (4.x timeline)`**
> area of the version index for the throttling-defaults and async-contract "available since" facts.

### Client: channel / proxy lifecycle
- **`ChannelFactory<T>` (or `ClientBase<T>` proxy) created per call**: constructing a channel
  factory parses endpoint config and builds the whole channel stack — expensive to repeat. Cache and
  reuse one `ChannelFactory<T>` per (contract, endpoint, binding, credentials) at AppDomain scope and
  create lightweight channels from it. Generated `ClientBase<T>` proxies cache the factory
  automatically **only** if you avoid the `Binding`-taking constructors and don't touch the public
  `ChannelFactory`/`Endpoint`/`ClientCredentials` properties before first use; otherwise caching is
  silently disabled. `ClientBase<T>.CacheSetting` (`AlwaysOn`/`Default`/`AlwaysOff`) controls this and
  is immutable once the first proxy of that type is created (verify against the currency brief for
  your version).
- **Re-doing security negotiation per call**: with message security / federation the initial
  handshake is costly; reusing the same proxy/channel amortises it. Look for new-proxy-per-request
  patterns on secured endpoints especially.
- **Abort-vs-close on faulted channels**: calling `Close()`/`Dispose()` on a channel in the
  **Faulted** state throws `CommunicationObjectFaultedException` (and `using(proxy)` hides this — the
  implicit `Dispose` can throw and mask the real exception). Look for a try/`Close`/catch→`Abort`
  pattern; raw `using` over a WCF proxy is a smell. A faulted channel must be re-created, not reused.
- **Reusing a channel across threads when not safe / leaking sessions**: datagram (sessionless)
  channels are generally callable concurrently, but sessionful channels and any per-channel state are
  not freely thread-safe — look for shared mutable proxies under concurrency, and for channels never
  closed (leaks a session/instance on the server until idle timeout).

### Server: throttling, instancing & concurrency
- **`ServiceThrottlingBehavior` on old/low defaults**: pre-4.0 defaults were very low —
  `MaxConcurrentCalls=16`, `MaxConcurrentSessions=10`, `MaxConcurrentInstances=26` (flat, not
  per-CPU) — and silently cap throughput under load (excess requests queue, then time out). 4.0
  raised them and made them per-processor (≈`16*CPU` calls / `100*CPU` sessions / `116*CPU`
  instances); 4.5 carried these higher dynamic defaults. Flag explicit low `maxConcurrentCalls`/
  `maxConcurrentSessions`/`maxConcurrentInstances` values, and self-hosted services on a framework
  target old enough to inherit the flat pre-4.0 defaults. Diagnose with the "Percent of Max
  Concurrent *" performance counters (verify the exact numbers/applicability against the currency
  brief for your version).
- **`InstanceContextMode` mismatched to workload**: `PerSession` (the default for sessionful
  bindings) holds a service instance and resources per client for the session lifetime — expensive at
  scale and a memory/leak risk for many idle clients; `PerCall` releases the instance after each call
  (best for scalability and stateless ops); `Single` shares one instance across all callers (a
  serialization bottleneck unless combined with `ConcurrencyMode.Multiple`). Flag `PerSession`/
  `Single` on high-fan-in stateless services.
- **`ConcurrencyMode` bottlenecks**: the default `Single` serialises all calls into one instance —
  a throughput wall for `Single`/`PerSession` services; `Multiple` allows concurrent calls but
  **requires the operation/shared state to be thread-safe** (look for unsynchronised shared fields);
  `Reentrant` is for callback/re-entrant patterns. Mismatched instancing+concurrency is a classic
  hidden serialisation point.
- **Sessionful bindings used where not needed**: reliable sessions / security sessions add
  per-session setup, state, and keep-alive overhead; if the contract is effectively stateless
  request/response, a sessionless binding (or `[ServiceContract(SessionMode=SessionMode.NotAllowed)]`)
  removes that cost.

### Bindings, payloads & serialization
- **Heavier binding than requirements need**: `WSHttpBinding` defaults to message-level security +
  WS-* (and supports reliable sessions) — significant per-message crypto/handshake overhead vs
  `BasicHttpBinding` (plain SOAP, transport security). For intra-org/back-end calls prefer
  `NetTcpBinding` (binary encoding, faster, connection-oriented) or `NetNamedPipeBinding`
  (same-machine, lowest overhead). Pick the lightest binding that meets the security/interop/
  transport requirement; flag `WSHttpBinding` with message security + reliable sessions used for
  simple internal traffic (verify against the currency brief for your version).
- **Default `TransferMode.Buffered` on large payloads**: buffered mode holds the **entire** message
  in memory before send/receive (LOH pressure, latency, OOM risk for large files/blobs) and is bounded
  by `maxReceivedMessageSize` (default 65,536 bytes). For large file/stream transfer use
  `TransferMode.Streamed` (or `StreamedRequest`/`StreamedResponse`) with an operation that takes/
  returns a single `Stream`; keep a sane `maxReceivedMessageSize` even when streaming (headers are
  always buffered — a DoS/OOM vector otherwise). Note streaming is unavailable on MSMQ bindings and
  disables features that need the whole message (signatures, reliable sessions). Also review
  `readerQuotas` raised blindly to `Int32.MaxValue` — that removes a memory safety bound rather than
  fixing a design (verify against the currency brief for your version).
- **`NetDataContractSerializer` in use**: it embeds full CLR type names in the wire payload and is
  slower and tightly coupled (and a known deserialization-security risk) — prefer the default
  `DataContractSerializer`. With `DataContractSerializer`, member order matters (alphabetical /
  explicit `Order=`) and a mismatch forces extra work; `[DataContract(IsReference=true)]` and large
  `[KnownType]` sets add graph-tracking and type-resolution cost — flag cyclic/large object graphs and
  long `[KnownType]`/`[ServiceKnownType]` lists serialised on hot paths. `[XmlSerializerFormat]`
  switches an operation to `XmlSerializer` (needed for precise XML/legacy schema control) but is
  slower and carries the `XmlSerializer` per-instance temp-assembly caching gotcha — see the CPU/
  serialization bullets above.

### Interface shape, async & per-call overhead
- **Chatty service interface**: fine-grained operations (a call per property/row) multiply network
  round-trips and per-call serialization/dispatch overhead; an N+1 pattern across service calls (one
  coarse call followed by a loop of per-item calls) is the service-tier analogue of EF N+1. Prefer
  coarse, DTO-returning operations that batch the data a caller needs in one round-trip.
- **Sync-over-async / blocking inside operations**: blocking on I/O (DB, downstream service, file) in
  a service operation ties up a dispatcher/thread-pool thread per concurrent call and, combined with
  throttling limits above, caps concurrency. Use `Task`-returning async operation contracts (TAP
  server-side support is **4.5+**) for I/O-bound work; avoid `.Result`/`.Wait()` inside operations
  (verify against the currency brief for your version).
- **Per-call behaviors / inspectors / metadata overhead**: custom `IDispatchMessageInspector` /
  `IParameterInspector` / message-formatter behaviors and verbose message logging run on **every**
  message — audit what each call actually executes. Leaving the MEX endpoint and
  `serviceMetadata httpGetEnabled` on in production exposes metadata and adds surface; `includeExceptionDetailInFaults`
  left enabled is a perf and information-disclosure smell. Flag heavy/duplicated behaviors in the
  dispatch path.
