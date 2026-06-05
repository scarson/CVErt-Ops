# Rust performance module: Serialization (serde / serde_json / bincode / prost)
> Load when serde-based serialization is detected — `serde`, `serde_json`, `bincode`, `postcard`, `rmp-serde`, `prost`, `simd-json` — see the module map in `../rust.md`. Core lanes + Runtime & build notes live in `../rust.md`; this file is the Serialization lens only.

## Serialization (serde / serde_json / bincode / prost)

> Scope: `serde` derive machinery, `serde_json` (text), `bincode`/`postcard` (compact binary,
> Rust-to-Rust), `rmp-serde` / MessagePack (cross-language binary), `prost` / protobuf
> (schema'd, cross-language), and `simd-json`/`sonic-rs` (SIMD-accelerated JSON). The recurring
> theme is: borrow don't allocate (zero-copy where the lifetime fits), stream or reuse buffers
> rather than allocating per call, avoid structural choices (`flatten`/`untagged`/`Value`) that
> force a second parse pass, and match the wire format to the actual boundary — not every path
> needs JSON.

- **`#[serde(borrow)]` with `&'de str`/`&'de [u8]` for per-field zero-copy**: the core pack
  flags "borrowed `Deserialize<'de>`" as a win — the mechanism is `#[serde(borrow)]` on a
  field typed `&'de str` or `&'de [u8]`, which causes serde to point directly into the input
  buffer instead of allocating a new `String`/`Vec<u8>` per field. The trade-off is lifetime
  coupling: the deserialized value cannot outlive the buffer. When ownership is only
  *sometimes* needed, `Cow<'de, str>` avoids the unconditional clone while still permitting
  owned construction — measure whether the allocation is measurable before adding the lifetime
  complexity (verify against the currency brief for your version).

- **`serde_json::from_reader` over an unbuffered source**: `from_reader` issues many small
  reads against whatever `io::Read` it receives — over an unbuffered `File` or `TcpStream`
  (both syscall-per-read by default) this multiplies syscall overhead; wrap in `BufReader`
  first. Conversely, when the bytes are already in memory, `from_slice`/`from_str` avoids
  the reader machinery entirely and is consistently faster than routing in-memory bytes
  through `from_reader`. For output, `to_writer` streams into a `Write` target while
  `to_string`/`to_vec` build the complete payload in a fresh allocation; the right choice
  depends on whether the bytes need to exist as a whole before the next step
  (verify against the currency brief for your version).

- **`#[serde(flatten)]` and `untagged` enums force a buffered second pass**: `#[serde(flatten)]`
  causes the deserializer to collect all fields into an intermediate representation (a content
  map) and re-parse, defeating zero-copy and inserting an allocation + second traversal on
  every call. `#[serde(tag = "...", content = "...")]` (adjacently-tagged) and `untagged`
  enums have the same intermediate-buffer cost; externally- and internally-tagged enums avoid
  it. Presence of `flatten` or `untagged` on a type used in a hot path is the signal — not
  their presence in general (verify against the currency brief for your version).

- **`serde_json::Value` and `arbitrary_precision` as allocation multipliers**: deserializing
  into `Value` (a dynamic tree) allocates a heap node per JSON value; on large payloads or in
  tight loops this accumulates quickly. If only a subtree is needed, decode the outer message
  into a concrete struct with a `serde_json::RawValue` field and decode the inner part lazily
  or not at all. Separately, enabling the `arbitrary_precision` feature changes number
  handling and is slower than the default; number fields that flow into `f64` don't need it
  (verify against the currency brief for your version).

- **Allocating a fresh buffer on every serialize call**: calling `serde_json::to_vec` or
  `to_string` in a per-request or per-message hot path allocates a new `Vec<u8>`/`String`
  each time. Reuse a buffer: hold a `Vec<u8>` across calls, `buf.clear()` before each use,
  and pass `&mut buf` via `serde_json::to_writer`; `with_capacity` pre-sizes on the first
  call if a representative payload size is estimable. Cross-reference the **Memory** lane in
  `../rust.md` (loop-body allocation / `clear()`-to-preserve-capacity pattern).

- **`#[derive(Serialize, Deserialize)]` monomorphization on hot generic paths**: derive
  generates a full implementation per concrete type; a generic function or struct
  instantiated over many types produces one copy per instantiation — for serialization this
  means separate codegen for each concrete `T`. This is usually the right trade-off, but a
  hot generic deserializer fanned out over a large type set is a compile-time and binary-size
  source worth profiling with `cargo bloat` or `twiggy`. Cross-reference the Runtime & build
  notes in `../rust.md` (LTO, `codegen-units`) for the build-side levers.

- **JSON vs a binary format for the actual boundary**: `serde_json` is human-readable, but
  text parsing, UTF-8 validation, and base64 encoding of binary fields make it materially
  slower and larger than the alternatives for non-human-facing boundaries. `bincode`/`postcard`
  are compact and fast for Rust-to-Rust paths (no cross-language schema needed); `rmp-serde`
  (MessagePack) is a compact cross-language option without a schema; `prost`/protobuf is
  schema'd and well-suited for versioned cross-language contracts. Using `serde_json` for
  internal cache payloads or service-to-service calls is the common footgun — verify the
  format is matched to the boundary before optimizing within it
  (verify against the currency brief for your version).

- **`simd-json` / `sonic-rs` on measured JSON hot paths**: `simd-json` rewrites JSON parsing
  using SIMD intrinsics and can be multiple times faster than `serde_json` on large payloads;
  it requires a mutable, owned input buffer (it mutates the slice in place), which changes
  call-site ownership. `sonic-rs` offers a similar gain with a somewhat different API surface.
  Both add a non-trivial dependency and the benefit is payload-size-dependent — the signal
  for reaching for either is a profiler trace showing JSON parsing as a top contributor, not
  a parse anywhere in the call graph (verify against the currency brief for your version).
