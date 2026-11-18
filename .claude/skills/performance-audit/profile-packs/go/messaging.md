# Go performance module: Messaging & streaming (Kafka / NATS / RabbitMQ / Pub/Sub)
> Load when `github.com/segmentio/kafka-go`, `github.com/IBM/sarama`, `github.com/confluentinc/confluent-kafka-go`, `github.com/nats-io/nats.go`, `github.com/rabbitmq/amqp091-go`, or `cloud.google.com/go/pubsub` is detected — see the module map in `../go.md`. Core lanes + Runtime & GC notes live in `../go.md`; this file is the Messaging & streaming lens only.

## Messaging & streaming (Kafka / NATS / RabbitMQ / Pub/Sub)

> Covers **Kafka** via `github.com/segmentio/kafka-go`, `github.com/IBM/sarama`, and
> `github.com/confluentinc/confluent-kafka-go`; **NATS** (incl. JetStream) via
> `github.com/nats-io/nats.go`; **RabbitMQ/AMQP** via `github.com/rabbitmq/amqp091-go`;
> and **Google Pub/Sub** via `cloud.google.com/go/pubsub`. Bullets are *conditions to look
> for*. The recurring themes are connection/client reuse, producer and consumer batching to
> cut round-trips, bounded concurrency on message handlers, and right-sized payloads.

- **Connection or client constructed per message or per request**: a kafka-go `Writer`/`Reader`,
  sarama `Client`, confluent `Producer`/`Consumer`, NATS `Conn`, AMQP `Connection`, or Pub/Sub
  `Client` negotiates TCP, TLS, and broker handshake on construction — each is expensive to
  establish and designed to be **long-lived and shared**. Creating one per message (or per
  inbound HTTP request) serializes connection setup and destroys throughput. For AMQP specifically,
  share one long-lived `Connection` and multiplex via per-goroutine `Channel`s — AMQP channels are
  **not goroutine-safe**, so each goroutine needs its own `Channel`, but all can share the
  underlying `Connection` (verify against the currency brief for your version).

- **Producer batching absent or disabled**: publishing one message per network round-trip (e.g.,
  kafka-go `Writer` with `BatchSize` of 1 or `BatchTimeout` at zero, sarama sync producer called
  in a tight loop without async batching, confluent producer flushed after every produce) throttles
  throughput to the round-trip latency of the broker. Configure `BatchSize` / `BatchTimeout` (or
  the equivalent `linger.ms` / `batch.size` beneath the confluent C library) so the producer
  accumulates a batch before sending. Separately, choose the `RequiredAcks` / `acks` durability
  level deliberately — `acks=all` maximises durability but adds ISR-synchronisation latency; for
  high-throughput pipelines that can tolerate potential loss, a lower acks setting may be
  appropriate (verify against the currency brief for your version).

- **Consumer fetch sizing too small**: Kafka consumers with `MinBytes` / `FetchMin` set to 1 byte
  or `MaxBytes` / `FetchMax` at a very low value issue a round-trip to the broker for each
  message rather than pulling a batch into a local buffer. Raise `MinBytes` (kafka-go) or
  `Consumer.Fetch.Min` (sarama) so the broker waits until enough data is available before
  responding, amortising round-trip cost across many messages. Similarly, an AMQP channel
  `Qos` prefetch of 1 (`ch.Qos(1, 0, false)`) forces a broker ack-and-send cycle per message —
  raise the prefetch count to match actual handler concurrency (cross-reference the core
  **Data access & I/O** lane) (verify against the currency brief for your version).

- **Synchronous publish or blocking ack on a request-serving goroutine**: calling a synchronous
  produce (sarama `SyncProducer.SendMessage`, kafka-go `Writer.WriteMessages` with no timeout
  context, NATS `Conn.Publish` followed by a blocking `Conn.Flush`) on the goroutine handling an
  inbound request blocks that goroutine for the full broker round-trip and invites pileup under
  load. Publish asynchronously — use sarama `AsyncProducer` and drain its `Errors` /
  `Successes` channels in a background goroutine, or hand messages off to a buffered worker
  channel; process consumes off the request path entirely (cross-reference the core **Concurrency
  & parallelization** lane) (verify against the currency brief for your version).

- **Unbounded per-message goroutine spawn in the consumer loop**: launching `go handle(msg)` for
  every delivered message with no concurrency cap lets a slow downstream (DB, external service)
  accumulate an unbounded number of in-flight goroutines, exhausting memory and overloading the
  downstream. Bound concurrency with a fixed worker-pool receiving from a channel, or use
  `errgroup.SetLimit(n)` (verify against the currency brief for your version) to cap concurrent
  handlers; size the limit to what the downstream can actually absorb (cross-reference the core
  **Concurrency & parallelization** lane).

- **Per-message offset commit or ack (commit strategy not batched)**: committing a Kafka offset
  (or acking a RabbitMQ delivery, or acknowledging a Pub/Sub message) synchronously after every
  individual message adds a broker round-trip per message. Batch commits — commit the highest
  processed offset periodically or after N messages; ack RabbitMQ deliveries with `multiple=true`
  (`ch.Ack(tag, true)`) to acknowledge all deliveries up to that tag in one round-trip; use
  Pub/Sub's `ReceiveSettings.MaxOutstandingMessages` to control flow rather than acking one at a
  time. The trade-off is a larger duplicate-on-crash window vs throughput — accept it deliberately
  rather than defaulting to per-message commits (verify against the currency brief for your
  version).

- **Message payload size and missing compression**: large message bodies inflate broker storage I/O,
  network transfer, and Go GC pressure (each message body is a heap allocation). Right-size
  messages — prefer normalised references or event identifiers over embedding full entity payloads.
  When messages are unavoidably large and text-heavy, enable Kafka producer compression (`Codec`
  in kafka-go, `Producer.Compression` in sarama, `compression.codec` in confluent) — snappy gives
  low CPU overhead, lz4 good throughput, zstd the best ratio for CPU cost. Avoid re-serializing the
  same payload once per partition or once per retry; marshal once and reuse the `[]byte` (cross-
  reference the `serialization` module) (verify against the currency brief for your version).

- **Partition count or key distribution bottlenecking consumer parallelism**: Kafka throughput
  scales with partition count — a topic with too few partitions caps consumer-group parallelism
  regardless of how many consumer instances are deployed (one partition can only be consumed by
  one group member at a time). Equally, a poorly chosen message key can hash the majority of
  traffic to one or a few partitions (hot-partition skew), leaving most consumer goroutines idle
  while one is overloaded. Look for partition counts set at deployment defaults that were never
  sized for the target throughput, and for key fields (user ID, tenant ID) whose cardinality or
  distribution is badly skewed (verify against the currency brief for your version).
