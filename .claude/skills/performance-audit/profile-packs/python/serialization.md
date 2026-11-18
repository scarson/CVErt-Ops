# Python performance module: Serialization & validation (json / orjson / pydantic / msgpack / pickle)
> Load when stdlib `json`, `orjson`/`ujson`/`msgspec`, `pydantic`, `marshmallow`, `pickle`, or `msgpack` is detected — see the module map in `../python.md`. Core lanes + Runtime & interpreter notes live in `../python.md`; this file is the Serialization & validation lens only.

## Serialization & validation (json / orjson / pydantic / msgpack / pickle)

> Scope: stdlib `json` (pure-Python decoder, CPython C-accelerated encoder), drop-in faster encoders
> (`orjson`, `ujson`, `msgspec`), `pydantic` (v1 pure-Python vs v2 Rust-core), `marshmallow`,
> `dataclasses`/`attrs`, `pickle`, and `msgpack`. The recurring themes are: validation and encoding
> cost multiplied over every API request; pydantic v2's compiled Rust core (`pydantic-core`) as a
> step-change in throughput; avoiding redundant validation passes on already-trusted data; and choosing
> a wire format matched to the actual interop boundary rather than defaulting to JSON everywhere.

- **Pydantic v1 vs v2 on a hot validation path**: pydantic v2 moved all validation and serialization
  into a compiled Rust core (`pydantic-core`), making it roughly an order of magnitude faster than
  pure-Python v1 for the same model. A codebase still on v1 — or using v1-era patterns such as
  `.dict()` instead of v2's `.model_dump()`, or mixing `orm_mode = True` config instead of
  `model_config = ConfigDict(from_attributes=True)` — is leaving very large gains on the table on any
  request-scoped validation path. v2 is a deliberate migration with some behavior changes, so frame
  findings as an upgrade to evaluate, not a drop-in swap (verify against the currency brief for your
  version).

- **Redundant or repeated validation of the same data**: validating the same payload more than once
  — e.g., a pydantic model in the framework layer (FastAPI request body) plus a second
  `MyModel(**data)` call in business logic, or re-parsing JSON that was already deserialized — pays
  the validation cost twice. For data that is already trusted (read back from your own DB, produced
  internally), use `Model.model_construct(**data)` to skip validation entirely, or `TypeAdapter` to
  validate a bare list or dict once rather than per-element in a loop (verify against the currency
  brief for your version; cross-reference the **Web frameworks** module in `web-frameworks.md` for
  FastAPI `response_model` re-validation).

- **stdlib `json` on large or frequent payloads**: `json.loads`/`json.dumps` is backed by a C
  extension for encoding but remains relatively slow on large payloads compared to Rust-backed
  alternatives; `json.loads` is a pure-C parser but `orjson` and `msgspec` still outpace it
  materially at scale. `orjson` (Rust) serializes `dataclasses`, `datetime`, `UUID`, and `numpy`
  arrays natively without a `default=` callback; `msgspec` offers similar speed with built-in schema
  validation. Key API differences: `orjson.dumps` returns `bytes` (not `str`), is stricter about
  non-serializable types, and does not support all stdlib `json` kwargs. Switch the hot path
  carefully — do not assume the API is a drop-in (verify against the currency brief for your version).

- **pickle on a hot path or across a trust boundary**: `pickle` is slow for large object graphs
  (it reflects on every attribute via `__reduce__`/`__getstate__`), is Python-version-coupled (a
  pickle from one CPython version may break on another), and is **a remote-code-execution vector
  on untrusted input** — any cache, message queue, or RPC channel that deserializes pickle from an
  external or user-controlled source is a critical security issue. Prefer a schema'd binary format
  (`msgpack`, `msgspec`, protobuf) for inter-service or cache payloads, or `orjson`/`json` for
  human-readable wire formats. Annotate hotspots where the pickle protocol version is left at
  default — higher protocol numbers are faster (verify against the currency brief for your version).

- **Schema or model object construction at request time**: building a pydantic `TypeAdapter`, a
  `marshmallow` schema instance, or a dynamic pydantic model class inside a request handler or in a
  tight loop pays the reflection/compilation cost on every invocation. `marshmallow` schemas carry
  significant construction overhead (field introspection, validator wiring); pydantic `TypeAdapter`
  compiles a Rust validation core the first time it is constructed. Both should be instantiated once
  at module scope or in a startup lifespan hook and reused. Dynamic model creation via
  `pydantic.create_model(...)` in a request path is a strong signal of this anti-pattern (verify
  against the currency brief for your version).

- **`marshmallow` on large collections**: `marshmallow` is pure-Python and reflection-heavy; on
  result sets of hundreds of objects, `Schema.dump(many=True)` iterates the list at Python speed,
  calling each field's serialization method via attribute lookup per row. For these hot list
  endpoints consider pydantic v2 (Rust-serialized), `msgspec.Struct`, or `orjson` with typed
  objects instead. `SerializerMethodField`-equivalent (`marshmallow.fields.Method`) callables that
  trigger additional lookups per row compound this cost (cross-reference the **Web frameworks**
  module in `web-frameworks.md` for DRF `ModelSerializer` on list endpoints).

- **Custom `datetime`, `Decimal`, and `UUID` encoding in stdlib `json`**: `json.dumps(obj,
  default=my_handler)` calls `my_handler` for every non-serializable value, once per instance in
  the payload — on a response containing hundreds of `datetime` or `Decimal` values this is a
  per-value Python function call overhead. `datetime.isoformat()` and `str(Decimal(...))` are
  also non-trivial when called at scale. `orjson` and `msgspec` have native fast paths for
  `datetime`, `UUID`, and (for orjson) `numpy` scalars/arrays, eliminating the `default=` dispatch
  entirely (verify against the currency brief for your version).

- **Wire format mismatched to the interop boundary**: JSON is the right default for human-readable,
  cross-language APIs, but service-to-service payloads and cache values where size and throughput
  matter should use a binary format. `msgpack` is compact, schema-less, and crosses language
  boundaries without a compiler step; `msgspec` combines fast binary encoding with Python schema
  validation; protobuf/gRPC adds a schema contract with generated code. Over-large JSON payloads
  that transmit fields the consumer never reads should be paginated or projected before serialization
  rather than serialized whole (cross-reference the **Data access & I/O** lane in `../python.md`).
