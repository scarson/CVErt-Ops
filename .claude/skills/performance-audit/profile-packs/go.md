# Profile Pack: Go

Go-specific performance signals for the audit lanes. Use alongside `generic-pack.md`, which covers
language-agnostic patterns; this pack sharpens each lane for Go idioms and footguns.

This is the **core** Go pack (lanes + Runtime & GC notes). Tech-specific lenses (HTTP servers,
databases, gRPC, serialization, caching, messaging) live in load-on-detection modules under
`profile-packs/go/` — see **`## Framework / sub-stack modules`** at the bottom. Load the core for
every Go project; add a module only when its signals appear in scope.

---

## Algorithmic complexity & data structures (lane `algorithmic`)
- Linear membership test inside a loop (`for _, v := range slice { if v == x }`) where the slice can grow — replace with a `map` lookup; maps have O(1) average lookup vs O(n) linear scan.
- Using `map[K]bool` (or `map[K]struct{}`) as a set when keys are dense integers or sequential IDs — a plain `[]bool` or `[]int` indexed by the key is faster and uses far less memory (maps carry ~100 bytes of overhead per entry).
- Calling `regexp.MatchString` or `regexp.Compile` inside a loop — compile the pattern once at package scope or in a `sync.Once` and reuse the `*regexp.Regexp`.
- Re-sorting a slice on every iteration when incremental insertion into a sorted structure (e.g., `sort.Search` + insert) or a heap (`container/heap`) would maintain order at lower cost.
- Recomputing derived values (hash, length, formatted string) on every iteration rather than computing once before the loop or storing alongside the source data.
- Using `map[string]map[string]T` (nested maps) when a single map with a struct key (`map[Key]T`) is clearer and cheaper — struct keys avoid two hash operations and two allocations per access.
- String built with `+=` in a loop is O(n²) in allocation and copying; use `strings.Builder` (with `Grow` to pre-size) or `bytes.Buffer` for multi-step construction.

## Memory & allocation (lane `memory`)
- Interface boxing on hot paths: passing a concrete value where an `interface` is expected forces heap escape; store the concrete type and pass the interface only at the call boundary, or restructure to avoid the interface on the critical path.
- `[]byte` ↔ `string` conversions that force a copy; in read-only contexts the `unsafe` package exposes zero-copy conversions — use only after profiling confirms the cost, and tag with `(verify against the currency brief for your version)`.
- Slice growth without preallocated capacity: `append` into a nil or empty slice causes repeated doublings; use `make([]T, 0, n)` when n is known or estimable.
- Retaining a large backing array via a small sub-slice (e.g., returning `bigSlice[2:4]` from a function) — the full array cannot be GC'd; copy the needed portion: `out := make([]T, len(sub)); copy(out, sub)`.
- Missing `sync.Pool` (verify against the currency brief for your version) for reusable short-lived buffers (e.g., `bytes.Buffer` for serialization scratch space); always call `Reset()` on retrieval — pool items are cleared by the GC without notice, so `New` must supply a valid zero-value object.
- `defer` inside a tight inner loop: each `defer` records a stack entry that runs at function return, not loop exit; restructure the loop body into a helper function or remove the defer.
- High pointer density in frequently allocated structs: the GC must trace every pointer in the live heap; prefer index-based linking (`NextIdx int`) over pointer chaining (`Next *Node`) in hot allocation paths; the GC stops scanning a struct at its last pointer field, so place non-pointer fields at the end.
- Combining small related allocations into a single struct value rather than separate `new` calls (e.g., embedding a `[16]byte` array and using `buf = arr[:0]` avoids a second allocation for the backing array).

## Data access & I/O (lane `data-access`)
- Per-row DB queries inside a loop (N+1 pattern) — prefer batch queries, `IN (...)` clauses, or multi-row inserts; N round-trips dominate latency regardless of query speed.
- Missing prepared statements for queries executed in tight loops or under concurrent load — repeated parse/plan overhead accumulates (verify against the currency brief for your version).
- Unbuffered `io.Reader`/`io.Writer` on file or network I/O: each small `Read`/`Write` becomes a syscall; wrap with `bufio.Reader`/`bufio.Writer` (default 4 KB buffer) or use `bufio.Scanner` for line-oriented input (verify against the currency brief for your version).
- Forgetting `bufio.Writer.Flush()` — buffered writes are silently dropped if the writer is not flushed before close.
- `json.Marshal`/`json.Unmarshal` on hot paths: both allocate and use reflection; for streaming HTTP responses prefer `json.NewEncoder(w).Encode(v)` (writes directly to the `ResponseWriter`); for ingest prefer `json.NewDecoder(r).Decode(&v)`; for highest throughput consider code-generated marshalers (verify against the currency brief for your version).
- Unmarshaling into `map[string]any` or `any` instead of a concrete struct — forces full reflection on every field and prevents compiler optimizations.
- Missing or misconfigured connection pool settings (`MaxOpenConns`, `MaxIdleConns`, `ConnMaxLifetime`) leading to either exhaustion under load or idle connection churn (verify against the currency brief for your version).
- `SELECT *` or reading an entire response body when only a subset of fields/bytes is needed — over-fetch inflates network I/O, deserialization work, and GC pressure.

## Concurrency & parallelization (lane `concurrency`)
- Goroutine leaks: goroutines launched without a `context.Context` cancellation path (or a `done` channel) accumulate silently — each retains at least a 2–8 KB stack that grows on demand; always `defer cancel()` when creating a context and propagate cancellation down the call chain.
- Unbounded goroutine spawn (`go f()` inside a loop with no cap) — use `errgroup.Group` with `g.SetLimit(n)` (verify against the currency brief for your version) or a fixed worker pool receiving from a channel; unbounded spawn exhausts memory under load.
- `sync.Mutex` critical sections that span I/O or computation: hold the lock only around the shared-state read/write, not around the work that produced the value; consider `sync.RWMutex` for read-heavy workloads.
- Single shared channel used as a global bottleneck — the channel serializes all senders/receivers; consider sharding across N channels or switching to a worker-pool pattern when profiling shows channel contention.
- Shared mutable buffers accessed by multiple goroutines (e.g., a package-level `[N]byte` used as a scratch buffer in concurrent `ReadFrom` calls) — give each goroutine its own buffer or use `sync.Pool`.
- Independent sub-tasks executed serially that could be fanned out — use `errgroup.WithContext` so the first error cancels remaining work; verify tasks have no shared mutable state and no ordering dependency before parallelizing.
- Goroutines in `syscall` state consume OS threads (M in the scheduler); goroutines blocked on Go channels do not — distinguish blocking profiles (`runtime.SetBlockProfileRate`) from `GODEBUG=schedtrace` output to identify the correct fix.
- `time.After(d)` inside a long-lived `for { select {...} }` loop: each iteration allocates a `*time.Timer` that (on older runtimes) is not reclaimed until `d` fires, so a hot loop where another case keeps firing leaks timers for the whole duration — prefer one reusable `time.NewTimer`/`time.NewTicker` with `Reset`, or a `context` deadline; the leak is reduced on newer runtimes but the reusable-timer idiom is still the durable fix (verify against the currency brief for your version).

## Framework-idiom currency (lane `idiom-currency`)
- Consult the currency brief/index for the framework in use (stdlib `net/http`, gRPC, Gin, Echo, etc.). Flag superseded middleware patterns, changed default timeouts or buffer sizes, and fast-path APIs the code bypasses (verify against the currency brief for your version).
- Offline (no brief): note candidate idiom concerns at LOW confidence, flagged for manual currency check.

## Payload / startup / build (lane `payload-startup`)
- Heavy work in `init()` functions (file I/O, network calls, large allocations, regexp compilation) runs before `main` and inflates cold-start time; prefer lazy initialization via `sync.Once` or explicit setup calls.
- Large numbers of `init()` registrations or eagerly constructed global singletons add latency on every cold start in serverless or container environments — sequence matters; profile with `GODEBUG=inittrace=1` (verify against the currency brief for your version).
- Eager construction of rarely-used subsystems at startup (opening DB connections, loading remote config) instead of on first use — use `sync.Once`-guarded lazy init.
- `runtime.SetFinalizer` on hot-path objects: finalized objects survive their first GC cycle and delay reclamation; chains of finalized objects require N GC cycles to free; prefer explicit `Close()` methods or `runtime.AddCleanup` (verify against the currency brief for your version).
- Shipping debug symbols or enabling CGo dependencies that are not needed bloats binary size and cold-start time; verify build flags strip appropriately (`-ldflags="-s -w"`) (verify against the currency brief for your version).

---

## Runtime & GC notes (load for every Go project)

Go has no legacy-vs-modern runtime split the way some ecosystems do — every Go program shares one
runtime whose garbage collector, scheduler, and build pipeline expose durable tuning levers. These
cut across all the lanes above (and every module below); treat them as the Go analog of a "variant
notes" section. They are *how the runtime is configured and measured*, not code-pattern signals.

- **`GOMAXPROCS` unaware of the container CPU limit**: the runtime historically sets `GOMAXPROCS` to
  the number of host logical CPUs, which in a CPU-limited container (Kubernetes `limits.cpu`, cgroup
  quota) over-provisions the scheduler — too many runnable Ps cause CPU throttling, scheduling
  latency, and GC-assist contention. Look for the absence of `go.uber.org/automaxprocs` (or an
  explicit `runtime.GOMAXPROCS` set from the cgroup quota) in containerized services; newer Go
  runtimes are becoming cgroup-aware, so confirm the behavior for the toolchain in use (verify
  against the currency brief for your version).
- **GC tuning levers left at defaults for the workload**: `GOGC` (default 100 — collect when the
  heap doubles) trades GC CPU for memory; raising it reduces GC frequency for throughput-bound,
  memory-rich services, lowering it caps memory at higher GC cost. `GOMEMLIMIT` is a *soft* heap
  ceiling the GC respects even with `GOGC=off` — essential for memory-capped containers to avoid OOM
  kills; leave 5–10% headroom below the container limit and pair with a higher `GOGC` (verify against
  the currency brief for your version). Flag services that fight OOM kills or GC-thrash with neither
  knob set.
- **cgo on a hot path**: every `cgo` call crosses a boundary that pins the calling goroutine to its
  OS thread for the call, cannot be inlined, blocks escape analysis across the boundary, and adds
  fixed per-call overhead; a `cgo` call in a tight loop or per-request path is a recurring footgun.
  Prefer a pure-Go implementation where one exists; batch work across the boundary when cgo is
  unavoidable; check whether `CGO_ENABLED=0` is viable (also smaller, faster-starting static
  binaries) (verify against the currency brief for your version).
- **Optimizing without a profile, or shipping without PGO**: Go ships first-class profiling — flag
  changes justified by intuition rather than `pprof` (CPU/heap/block/mutex) or
  `go test -bench -benchmem`. For CPU-bound services, **Profile-Guided Optimization** (commit a
  representative `default.pgo` next to `main`) lets the compiler inline and devirtualize hot calls
  for a few percent throughput at no code cost — its absence on a hot service is a missed lever
  (verify against the currency brief for your version).
- **Avoidable heap escapes the compiler will show you**: `go build -gcflags='-m'` reports which
  values escape to the heap (returned pointers, values stored behind an interface, closures captured
  by reference, slices whose size the compiler can't bound). Escapes on hot paths drive GC work;
  the escape report and inlining decisions (`-m -m`) are the durable way to confirm a suspected
  allocation rather than guessing (cross-reference the **Memory & allocation** lane above).

## Framework / sub-stack modules (load on detection)

Load the core lanes + **Runtime & GC notes** above for *every* Go project. Additionally load the
matching module when its technology is detected in the audit scope, and include it as ecosystem
context in the relevant lane prompts. (These tech-specific lenses are split out so a run pastes only
what's relevant — see the version index `../version-indexes/go.md` for version-specific facts.)

| Detected (signals) | Load module |
|---|---|
| **HTTP servers & web frameworks** — `net/http` servers, `github.com/gin-gonic/gin`, `github.com/labstack/echo`, `github.com/gofiber/fiber`, `github.com/go-chi/chi` | [`go/net-http-servers.md`](go/net-http-servers.md) |
| **Database access** — `database/sql`, `github.com/jackc/pgx`, `gorm.io/gorm`, `github.com/jmoiron/sqlx`, `sqlc`, `github.com/lib/pq` | [`go/database-sql.md`](go/database-sql.md) |
| **gRPC** — `google.golang.org/grpc`, `google.golang.org/protobuf` (`.proto` / `*.pb.go`) | [`go/grpc.md`](go/grpc.md) |
| **Serialization** — `encoding/json`, `google.golang.org/protobuf`, `github.com/json-iterator/go`, `github.com/mailru/easyjson`, `github.com/goccy/go-json`, `github.com/vmihailenco/msgpack` | [`go/serialization.md`](go/serialization.md) |
| **Caching** — `github.com/dgraph-io/ristretto`, `github.com/allegro/bigcache`, `github.com/coocood/freecache`, `github.com/patrickmn/go-cache`, `github.com/redis/go-redis`, `golang.org/x/sync/singleflight` | [`go/caching.md`](go/caching.md) |
| **Messaging & streaming** — `github.com/segmentio/kafka-go`, `github.com/IBM/sarama`, `github.com/confluentinc/confluent-kafka-go`, `github.com/nats-io/nats.go`, `github.com/rabbitmq/amqp091-go`, `cloud.google.com/go/pubsub` | [`go/messaging.md`](go/messaging.md) |

---

## Sources

Durable signals in this pack are grounded in these authoritative sources (version-specific facts and
their per-entry citations live in `../version-indexes/go.md`):

- go.dev — blog/pprof, wiki/Performance, blog/slices-intro, blog/strings, doc/effective_go, doc/gc-guide
- pkg.go.dev — `sync.Pool`, `strings.Builder`, `bufio`, `encoding/json`, `golang.org/x/sync/errgroup`
- **Runtime & GC** — go.dev/doc/gc-guide (`GOGC`/`GOMEMLIMIT`), go.dev/blog/pgo, `runtime.GOMAXPROCS` docs, cgo command docs, `go build -gcflags=-m` (escape analysis), `go.uber.org/automaxprocs`.

**Sub-stack modules** carry their own grounding; key sources per module:

- **HTTP servers** (`go/net-http-servers.md`) — `net/http` `Server`/`Transport` docs, gin/echo/chi
  routing docs, gofiber/fasthttp context-reuse caveats.
- **Database access** (`go/database-sql.md`) — `database/sql` (`SetMaxOpenConns` etc., `Rows`),
  pgx/`pgxpool` (`Batch`, `CopyFrom`), GORM performance docs (`Preload`/`Joins`/`Select`).
- **gRPC** (`go/grpc.md`) — grpc-go docs (`ClientConn`, `MaxRecvMsgSize`, `keepalive`,
  load-balancing/resolver), protobuf Go API.
- **Serialization** (`go/serialization.md`) — `encoding/json` (`Encoder`/`Decoder`, `RawMessage`,
  `UseNumber`), protobuf Go API, easyjson/goccy-go-json/jsoniter/msgpack READMEs.
- **Caching** (`go/caching.md`) — `golang.org/x/sync/singleflight`, ristretto/bigcache/freecache
  READMEs, `sync.Map` docs, redis/go-redis (pooling, `Pipelined`).
- **Messaging** (`go/messaging.md`) — segmentio/kafka-go, IBM/sarama, confluent-kafka-go, nats.go
  (JetStream), rabbitmq/amqp091-go (`Qos`/`Channel` thread-safety), cloud.google.com/go/pubsub.
