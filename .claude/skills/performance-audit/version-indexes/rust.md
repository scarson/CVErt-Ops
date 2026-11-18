---
index_schema_version: 1
ecosystem: rust
covered_through: "Rust 1.96"
built_on: 2026-06-04
sources:
  - https://nnethercote.github.io/perf-book/build-configuration.html
  - https://raw.githubusercontent.com/rust-lang/rust/master/RELEASES.md
  - https://blog.rust-lang.org/2022/12/15/Rust-1.66.0/
  - https://blog.rust-lang.org/2023/06/01/Rust-1.70.0/
  - https://blog.rust-lang.org/2023/12/28/Rust-1.75.0/
  - https://blog.rust-lang.org/2024/03/21/Rust-1.77.0/
  - https://blog.rust-lang.org/2024/07/25/Rust-1.80.0/
  - https://blog.rust-lang.org/2024/09/05/Rust-1.81.0/
  - https://blog.rust-lang.org/2024/10/17/Rust-1.82.0/
  - https://blog.rust-lang.org/2025/02/20/Rust-1.85.0/
  - https://docs.rs/rustfft/latest/rustfft/            # numeric/DSP library fast paths
  - https://docs.rs/realfft/latest/realfft/
  - https://docs.rs/ndarray/latest/ndarray/
---
# Rust performance version index
> Build-once lookup. The idiom-currency lane consults this first; live research only extends past
> `covered_through`.
>
> Note: Rust's per-version *language/stdlib* hot-path API churn is low — the majority of those wins are
> **build-config** (codegen flags, linker, PGO/LTO). That part of the index is intentionally lean.
> **Library-API fast paths** (numeric/DSP crates below) are a different matter and ARE worth carrying:
> they are the durable idioms that ground an idiom-currency pass on a numeric/audio/DSP stack.

## Build & Codegen

- **`lto = "thin"` / `lto = "fat"` in `[profile.release]`** — durable build-config, no version requirement — thin LTO crosses crate boundaries and yields ~10–20% runtime gain over the default thin-local LTO; fat LTO is more aggressive but rarely worth the extra link time — supersedes `lto = false` (default thin-local only) — set in `Cargo.toml` `[profile.release]`; prefer `thin` as the first upgrade, `fat` only if benchmarks justify it.

- **`codegen-units = 1` in `[profile.release]`** — durable build-config, no version requirement — disables the compiler's parallel codegen sharding, letting LLVM see the full crate for inlining/optimisation; reduces binary size and improves runtime speed at the cost of longer compile times — supersedes the default (`16` in release) — pair with `lto = "thin"` for maximum effect.

- **`-C target-cpu=native` (RUSTFLAGS)** — durable build-config, no version requirement — unlocks AVX/AVX2/AVX-512 and other CPU-specific instructions, enabling auto-vectorisation of SIMD-amenable loops; can yield large wins on numeric/string workloads — not set by default (portable binary assumption) — use for binaries that run only on the build machine or a known CPU class; do not use for distributed crates.

- **PGO via `cargo-pgo` (tooling)** — tooling, version-independent — profile-guided optimisation: instrument → run on representative workload → recompile with profile data; typically 10%+ runtime improvement — `cargo-pgo build`, `cargo-pgo optimize` wraps `rustc`'s `-C profile-generate`/`-C profile-use` flags — not supported for crates distributed via `cargo install`; use `cargo-wizard` to discover and apply these config knobs interactively.

- **BOLT via `cargo-pgo` (tooling)** — tooling, version-independent — post-link binary layout optimisation (improves instruction-cache locality); complementary to PGO, not a replacement — `cargo-pgo bolt` subcommand; Linux-only, requires `llvm-bolt` in PATH.

- **`panic = "abort"` in `[profile.release]`** — durable build-config, no version requirement — removes stack-unwinding machinery; slightly reduces binary size and eliminates unwinding overhead on panic paths — supersedes default `panic = "unwind"` when FFI callers or test harnesses do not require unwind propagation.

- **`strip = "symbols"` / `strip = "debuginfo"` in `[profile.release]`** — durable; named `strip` values stable since **Rust 1.77** (numeric `0`/`1`/`2` existed earlier) — reduces binary and distribution size; `"debuginfo"` is now the **default** for release profiles since **Rust 1.77** (std debuginfo stripped automatically) — before 1.77, release binaries silently included std debuginfo; upgrade to 1.77+ to get the default; use `"symbols"` for maximum size reduction (impairs profiling).

- **`debug = "line-tables-only"` in `[profile.dev]`** — durable build-config — reduces dev-build debuginfo to line numbers only; saves ~20–40% compile time vs full `debug = true` while keeping `file:line` in backtraces — supersedes `debug = 2` for typical dev workflows where you don't need variable inspection in a debugger.

- **Frame pointers in std (`-Cforce-frame-pointers=yes`)** — **Rust 1.79** — standard library is now compiled with frame pointers enabled by default; downstream binaries can be profiled with Linux `perf` without per-frame unwinding tables — no action required; use `-Cforce-frame-pointers=yes` in RUSTFLAGS for your own crates to match.

- **Compiler self-optimisation (BOLT + LTO on Linux rustc)** — **Rust 1.66** — the distributed `x86_64-unknown-linux-gnu` rustc itself is built with LTO (frontend) and BOLT (LLVM backend); users get a faster compiler automatically on Linux without any config change.

- **Sort algorithm improvements** — **Rust 1.81** — both stable (`slice::sort`) and unstable (`slice::sort_unstable`) sort implementations were rewritten with improved algorithms, delivering better runtime performance and compile time for the sort itself — no API change; upgrade to 1.81+ to get automatically.

## Linker

- **`lld` default linker on Linux** — **Rust 1.90** (x86_64-unknown-linux-gnu) — `lld` is now the default linker on x86_64 Linux, significantly reducing link times vs GNU `ld`; no configuration needed on 1.90+ — if on an older toolchain, set `RUSTFLAGS="-C link-arg=-fuse-ld=lld"` or add `[target.x86_64-unknown-linux-gnu] linker = "clang" rustflags = ["-C", "link-arg=-fuse-ld=lld"]` in `.cargo/config.toml`.

- **`mold` linker (tooling)** — tooling, version-independent — faster than `lld` for incremental dev builds; set via `RUSTFLAGS="-C link-arg=-fuse-ld=mold"` or `.cargo/config.toml` — use for dev profiles where link speed is the bottleneck; no runtime perf change, build-time only.

- **`wild` linker (tooling, experimental)** — tooling, version-independent — Linux-only; may be faster than `mold` but less mature — use experimentally; verify correctness of output binaries before adopting in CI.

## Stdlib & Language

- **`OnceLock` / `OnceCell` stabilisation** — **Rust 1.70** — thread-safe (`OnceLock`) and single-threaded (`OnceCell`) one-time initialisation in std; supersedes `lazy_static` and `once_cell` crate dependencies for global/static initialisation — use `OnceLock<T>` for `static` values initialised at first access.

- **`LazyLock` / `LazyCell` stabilisation** — **Rust 1.80** — lazy-initialised statics with closure-based initialisation syntax; supersedes `OnceLock::get_or_init` pattern for `static` globals — `static FOO: LazyLock<ExpensiveType> = LazyLock::new(|| init());`; `LazyCell` for non-`Sync` thread-local use.

- **`std::hint::black_box` stabilisation** — **Rust 1.66** — prevents the compiler from optimising away expressions in microbenchmarks; required for correct `criterion`/`std::hint::black_box` benchmarking — supersedes the `test::black_box` unstable API — use in benchmark loops to prevent dead-code elimination of the measured computation.

- **`core::hint::cold_path` stabilisation** — **Rust 1.95** — marks a code branch as cold (unlikely), guiding the compiler to optimise the hot path at the expense of the cold branch; replaces the `#[cold]` function attribute pattern for inline branch hints — use in error/rare-case branches within hot functions.

- **Inline `const { }` expressions** — **Rust 1.79** — allows arbitrary const evaluation inline in expression position without a named `const` item; enables constant-folding of derived values (e.g., `[const { None }; N]`) with type inference — reduces runtime cost of initialisation that can be computed at compile time.

- **Cargo sparse registry protocol default** — **Rust 1.70** (stabilised in **Rust 1.68**) — Cargo now uses the HTTP sparse protocol for crates.io by default; fetches only metadata for crates you use instead of cloning the full index git repo — significant `cargo update`/`cargo fetch` speed improvement; automatic on 1.70+, no config needed.

- **`str::contains` NEON acceleration (aarch64)** — **Rust 1.95** — `str::contains` uses ARM NEON SIMD on aarch64 targets with `neon` feature enabled by default; improves substring search throughput on Apple Silicon and similar — no API change; automatic on 1.95+ on aarch64.

- **`Box/Rc/Arc::new_uninit` / `assume_init` stabilisation** — **Rust 1.82** — enables allocation of heap memory without initialising it, then writing directly; avoids a redundant zeroing pass for types where you will immediately write all fields — supersedes `Box::new(MaybeUninit::uninit())` boilerplate — use for large heap-allocated types where initialisation cost is measurable.

- **`#[target_feature]` on safe functions** — **Rust 1.86** — `#[target_feature(enable = "avx2")]` can now be applied to safe (non-`unsafe`) functions; reduces unsafe surface when writing SIMD-specialised hot paths — previously required `unsafe fn`; now safe fn with a target-feature guard is ergonomically viable.

- **`std::arch` SIMD intrinsics callable in safe code** — **Rust 1.87** — SIMD intrinsics from `std::arch` are safe to call when the required target features are enabled (either via `-C target-feature` or `#[target_feature]`); reduces `unsafe` boilerplate in performance-critical SIMD loops.

## Numeric & DSP libraries (version-independent)
> Library-API fast paths for numeric / signal-processing crates — durable idioms (not tied to a Rust
> release). Carried here so the idiom-currency lane can ground a DSP/audio/numeric audit instead of
> falling back to model knowledge. Verify the exact API against the crate version in `Cargo.lock`.

- **`rustfft` — build ONE `FftPlanner`, cache the planned `Arc<dyn Fft<T>>`** — version-independent — planning computes twiddle factors and selects an algorithm, which is expensive relative to the transform itself. Build the planner once and reuse the returned `Arc<dyn Fft>` for every transform of a given size; constructing a planner (or calling `plan_fft_*`) per buffer/symbol/call defeats the internal plan cache and re-allocates twiddles each time — supersedes per-call `FftPlanner::new()` + `plan_fft_forward(n)` — the single most common DSP hot-path footgun (a real OFDM audit found a planner rebuilt per symbol).

- **`rustfft` — `process_with_scratch` / `process_outofplace_with_scratch` with a reused scratch buffer** — version-independent — plain `process()` allocates internal scratch on every call; size a scratch `Vec` once via `Fft::get_inplace_scratch_len()` (or `get_outofplace_scratch_len()`) and pass it, eliminating per-transform allocation on the hot path — supersedes `fft.process(&mut buf)` called in a loop — use whenever the transform runs per frame/symbol/message.

- **`realfft` for real-valued input** — version-independent — built on rustfft, it exploits real-input symmetry to do ~half the work and yield N/2+1 complex bins; for audio/DSP where the input is real this beats running a full complex FFT and discarding the redundant half — supersedes zero-filling an imaginary part into a full `Complex` FFT — use for real signal inputs (audio capture, sensor streams).

- **`num-complex::Complex<f32>` / `Complex<f64>`** — version-independent — use the crate type over hand-rolled `(re, im)` tuples: it is `#[repr(C)]` (FFI / `bytemuck` zero-copy buffer reinterpretation), interops with rustfft/ndarray, and its arithmetic lowers to efficient code — reserve manual re/im math for proven hot spots where you deliberately bypass bounds/branches.

- **`ndarray` — `.dot()` with the `blas` feature for matrix/vector products** — version-independent — `.dot()` dispatches to an optimized BLAS (OpenBLAS/Accelerate/MKL) when the `blas` feature + a `blas-src` backend are enabled, vastly outperforming a hand-written triple loop on large operands — supersedes naïve nested-loop GEMM/GEMV — enable for numeric-heavy code; without a backend `.dot()` still beats a manual loop but leaves BLAS speedups on the table.

- **`ndarray` — operate on views (`ArrayView`) + `Zip`/`azip!`; avoid `.to_owned()` in loops** — version-independent — slicing returns views (no copy); `Zip::from(a).and(b).for_each(...)` (or `azip!`) builds fused, allocation-free element-wise kernels, and `.as_slice()` exposes contiguous data for SIMD; `.to_owned()`/`.to_vec()` inside a hot loop copies the whole array each iteration — supersedes per-iteration owned-array allocation — keep large arrays borrowed and mutate in place.

## Tooling (version-independent)

- **`tikv-jemallocator` (jemalloc) global allocator** — tooling, version-independent — replaces the system allocator (glibc malloc) with jemalloc; reduces fragmentation and can yield large runtime speed and memory reductions on allocation-heavy workloads — add `tikv-jemallocator = "0.5"` (renamed from `jemallocator` in 0.5) and `#[global_allocator] static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;` in `main.rs`; enable THP with `MALLOC_CONF="thp:always,metadata_thp:always"` on Linux.

- **`mimalloc` global allocator** — tooling, version-independent — Microsoft's allocator; good general-purpose alternative to jemalloc with lower overhead on some workloads — add `mimalloc = "0.1"` and `#[global_allocator] static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;` — benchmark against jemalloc for your specific workload.

- **`cargo-wizard`** — tooling, version-independent — interactive CLI that encapsulates Rust build-config knowledge (LTO, codegen-units, PGO, BOLT, strip, panic mode) and writes the correct `Cargo.toml` / `.cargo/config.toml` entries — use as a first step when optimising a release build without hand-editing flags.

- **`nohash-hasher` crate** — tooling, version-independent — provides a no-op hasher for `HashMap`/`HashSet` when keys are already well-distributed integers (e.g., numeric IDs); eliminates hashing overhead entirely — supersedes `FxHashMap` for integer-keyed maps where identity hashing is correct — use only when key distribution guarantees no collisions from the no-op hash.

- **`cargo build-dir` config stabilisation** — **Rust 1.91** — `build.build-dir` in `.cargo/config.toml` lets you redirect intermediate build artifacts to a custom directory; enables placing build artefacts on a fast local NVMe separate from the source tree (useful in CI and shared-storage environments) — set `build.build-dir = "/fast/disk/target"` in config; artefact layout inside is an implementation detail.
