# Go performance module: Serialization (encoding/json / protobuf / msgpack)
> Load when `encoding/json`, `google.golang.org/protobuf`, `github.com/json-iterator/go`,
> `github.com/mailru/easyjson`, `github.com/goccy/go-json`, or
> `github.com/vmihailenco/msgpack` is detected — see the module map in `../go.md`. Core
> lanes + Runtime & GC notes live in `../go.md`; this file is the Serialization lens only.

## Serialization (encoding/json / protobuf / msgpack)

> Scope: stdlib `encoding/json` (reflection-based `Marshal`/`Unmarshal`), the emerging
> `encoding/json/v2` direction (verify the milestone in the currency brief / version index),
> code-generated `easyjson`, drop-in faster replacements
> (`goccy/go-json`, `jsoniter`), protobuf (`google.golang.org/protobuf`), msgpack, plus
> `encoding/gob` and `encoding/xml`. The recurring theme is reflection and allocation cost
> on hot paths, streaming vs whole-buffer trade-offs, decoding into concrete types rather
> than dynamic maps, and matching the wire format to the interop need.

- **Reflection cost of `json.Marshal`/`json.Unmarshal` on hot paths**: the stdlib encodes
  and decodes via reflection on every call — it caches per-type field metadata, but the
  reflective walk and per-call allocations remain; look for calls inside request handlers,
  tight loops, or per-message processing that accumulates under load. For the hottest paths
  consider a code-generated marshaler (`github.com/mailru/easyjson`) or a faster drop-in
  replacement (`github.com/goccy/go-json`, `github.com/json-iterator/go`) that retains
  the stdlib API surface (verify against the currency brief for your version).

- **Whole-buffer vs streaming encode/decode**: `json.Marshal(v)` builds the complete
  `[]byte` in memory before returning; `json.NewEncoder(w).Encode(v)` writes directly to
  an `io.Writer` — for large payloads or HTTP response bodies this avoids the intermediate
  allocation and reduces time-to-first-byte. Conversely, `json.NewDecoder(r).Decode(&v)`
  streams from an `io.Reader` rather than requiring `io.ReadAll` first. Know the semantics
  differences: `Encoder.Encode` appends a trailing newline; a `Decoder` over a connection
  may leave unconsumed bytes if the stream contains multiple values (cross-reference the
  **HTTP servers & web frameworks** module in `net-http-servers.md` and the **Data access
  & I/O** lane in `../go.md`).

- **Decoding into `map[string]any` or `any` instead of a concrete struct**: unmarshaling
  into a dynamic map or bare `interface{}` forces full per-field reflection, boxes every
  value into an `interface{}`, and allocates for every key string and value; it also blocks
  any compiler analysis of field access. Decode into a typed struct instead. Where only a
  sub-tree is needed, decode the surrounding message into a struct that holds a
  `json.RawMessage` field and decode the sub-tree lazily or not at all.

- **Struct shape and tag hygiene inflating payload or work**: exported fields with no
  `json:"-"` tag that the consumer never reads are marshaled on every call — adding `"-"`
  eliminates the work; missing `omitempty` on optional fields sends zero-value noise over
  the wire and through the decoder on the other side; very deep or wide nested structs
  multiply the reflective walk proportionally. Audit the struct against the actual wire
  contract, not just the Go representation.

- **`[]byte` fields encoded as base64 and buffer allocation on hot serialize paths**: the
  JSON encoder represents `[]byte` as base64, which is both larger and costlier than the
  raw binary; large blob fields are particularly expensive. Repeated `[]byte(s)` /
  `string(b)` conversions on hot paths each copy the backing array. Reuse encode buffers
  via a `sync.Pool` of `*bytes.Buffer` (call `Reset()` on retrieval) rather than
  allocating a fresh buffer per call — this is the canonical intersection with the
  **Memory & allocation** lane in `../go.md` (cross-reference the `sync.Pool` bullet there).

- **Protobuf allocation and repeated re-marshaling**: protobuf is binary, smaller, and
  faster to marshal/unmarshal than JSON for service-to-service traffic, but
  `proto.Marshal` still allocates; reuse message structs (reset with `proto.Reset`) where
  the struct is not shared, and avoid re-marshaling the same logical payload more than once
  per hop (cross-reference the **gRPC** module when detected). Don't use
  `proto.MarshalOptions{}.Marshal` in a per-request hot path without checking whether a
  pooled approach fits the message lifecycle (verify against the currency brief for your
  version).

- **`Decoder.UseNumber()` and custom `MarshalJSON`/`UnmarshalJSON` methods as hidden
  costs**: by default the JSON decoder represents all numbers as `float64`, which loses
  precision for large integers — `Decoder.UseNumber()` defers parsing so the caller can
  call `.Int64()` or `.Float64()` explicitly. Separately, any type that implements
  `json.Marshaler` or `json.Unmarshaler` has its method called per value during traversal;
  if such a method allocates (building a formatted string, calling `fmt.Sprintf`, making
  an intermediate map) that cost multiplies across every element in a collection — look for
  custom JSON methods on high-cardinality types in hot serialization paths (verify against
  the currency brief for your version).

- **Choosing the wrong wire format for the interop need**: `encoding/gob` is Go-only,
  stateful (receiver must pre-register concrete types behind interfaces), and unsuitable
  for cross-language or cross-version interop; `encoding/xml` is heavier than JSON in
  both parse cost and wire size; msgpack (`github.com/vmihailenco/msgpack`) is a compact
  binary middle ground that crosses language boundaries without a schema — match the
  format to the actual interop requirement, payload volume, and versioning story rather
  than defaulting to JSON for all traffic (verify against the currency brief for your
  version).
