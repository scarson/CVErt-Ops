# .NET performance module: Messaging & realtime (SignalR / MSMQ / queues)
> Load when `Microsoft.AspNetCore.SignalR`/`Microsoft.AspNet.SignalR`, `System.Messaging` (MSMQ), `Azure.Messaging.ServiceBus`, `RabbitMQ.Client` is detected — see the module map in `../dotnet.md`. Core lanes + Variant notes live in `../dotnet.md`; this file is the Messaging & realtime (SignalR / MSMQ / queues) lens only.

## Messaging & realtime (SignalR / MSMQ / queues)

> Spans **both** runtimes: ASP.NET Core SignalR (`Microsoft.AspNetCore.SignalR`) and legacy ASP.NET
> SignalR (`Microsoft.AspNet.SignalR`) for realtime hubs; **MSMQ** (`System.Messaging`) on Framework;
> and message brokers — **Azure Service Bus** (`Azure.Messaging.ServiceBus`) and **RabbitMQ**
> (`RabbitMQ.Client`). Bullets are *conditions to look for*. The recurring themes are connection
> reuse, batching to cut round-trips, payload sizing, and async over blocking I/O.

- **SignalR scaleout needs a backplane**: SignalR tracks connection state **per server process**, so
  in a server farm a hub on one node is unaware of connections on the others — `Clients.All` /
  group broadcasts from one node never reach clients on the others. This is a **correctness** problem
  first (messages silently lost) and a single-node bottleneck second. A multi-server deployment needs
  a backplane — the **Redis backplane** or the **Azure SignalR Service** (which also offloads the
  persistent connections off your servers); sticky sessions / session affinity are still required
  except with Azure SignalR Service (verify against the currency brief for your version).
- **Chatty hub calls / many small frequent messages**: each invoke is framed and dispatched; very
  frequent tiny messages waste framing and dispatch overhead. Batch updates where the UX allows, and
  prefer the **MessagePack hub protocol** (`Microsoft.AspNetCore.SignalR.Protocols.MessagePack`,
  added via `AddMessagePackProtocol`) over the default JSON protocol — it is a compact binary format
  producing smaller, faster-to-(de)serialize payloads (verify against the currency brief for your
  version).
- **SignalR fan-out cost**: broadcasting to very large groups or `Clients.All` multiplies one logical
  send into N transmissions; large per-connection state multiplies memory across every persistent
  connection. Scope broadcasts to the smallest necessary group, and keep per-connection state lean.
- **SignalR streaming vs buffering large results**: returning one big buffered payload blocks and
  spikes memory; prefer hub streaming (`IAsyncEnumerable<T>` / `ChannelReader<T>`) to push results
  incrementally and bound memory on big result sets (verify against the currency brief for your
  version).
- **MSMQ per-message transactions**: wrapping every `Send`/`Receive` in its own
  `MessageQueueTransaction` is expensive — batch many messages into **one** transaction to amortize
  the commit cost. Also weigh **recoverable** (disk-persisted, durable) vs **express** (in-memory)
  delivery — express trades durability for throughput — and note that large message bodies serialize
  slowly (the default `XmlMessageFormatter` is reflection-heavy; a leaner formatter or pre-serialized
  `byte[]` body is faster).
- **Broker connection / client reused, not opened per message**: for Azure Service Bus, a
  `ServiceBusClient` (and its `ServiceBusSender`/`ServiceBusReceiver`/`ServiceBusProcessor`) is
  **expensive to establish** and fully thread-safe — register it as a **singleton** / long-lived and
  reuse it; do **not** create or dispose one per message. The same holds for RabbitMQ's `IConnection`
  (share one long-lived connection, use per-thread `IModel`/channels). Opening a connection per
  message is a classic throughput killer (verify against the currency brief for your version).
- **Round-trips not cut with prefetch / batching**: receiving one message per round-trip leaves
  throughput on the table — set a sensible **prefetch** (`ServiceBusReceiver.PrefetchCount`, or
  RabbitMQ `BasicQos`) so the client pulls a batch into a local cache, and use **batch send/receive**
  (`SendMessagesAsync` with a batch, `ReceiveMessagesAsync`) to amortize network cost. Right-size
  message bodies; **sessions / ordering guarantees add per-message overhead** — only enable them when
  ordering is actually required (verify against the currency brief for your version).
- **Blocking synchronous send/receive on request paths**: synchronous broker/queue calls on a
  request thread block a thread-pool thread and invite starvation — use the async APIs
  (`SendMessageAsync`/`ReceiveMessageAsync`, processor callbacks) and don't sync-over-async with
  `.Result`/`.Wait()` (cross-reference the core **Concurrency & parallelization** lane).
