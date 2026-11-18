# Version checks use ecosystem-native comparison

## What was built

- `PLAN.md` §9.2 no longer mandates `github.com/Masterminds/semver/v3`. Any version comparison must use the rules native to the advisory's ecosystem, and anything that cannot be evaluated must report "cannot evaluate", never "not affected".
- Pitfall ARCH-8 in `dev/implementation-pitfalls.md` now states the same rule and records three data traps: `introduced: "0"`, stored ranges with no upper bound, and OSV `GIT` ranges.

## Key decisions

- Semver is correct only for ecosystems that follow it, and gives wrong answers for dpkg, PEP 440 and Maven.
- Archival copies keep the old wording: `dev/implementation-pitfalls-original.md`, `dev/pitfall-meta-reviews/` and `dev/plans/`. The audit summary row in `dev/implementation-pitfalls.md` that lists item 5.12 as "semver — not implemented yet" is a dated snapshot and also stays.
- `AGENTS.md` and `CLAUDE.md` never stated the old mandate, so they had nothing to remove.

## Dependency check: `github.com/google/osv-scalibr/semantic` v0.5.3, checked 2026-11-06

Verdict: approved, on condition that `internal/version` validates syntax itself.

| Check | Result | Notes |
|---|---|---|
| Repository status | OK | Not archived. The README says the code may change as SCALIBR merges with OSV-Scanner, which is planned consolidation, not deprecation |
| Last commit | OK | Repository pushed 2026-11-06; `semantic/` changed 2026-10-26 |
| Last release | OK | v0.5.3, 2026-09-22; pre-1.0, so the API can change |
| Open issues and PRs | OK | 357 open, with active development |
| Known vulnerabilities | OK | OSV lists none for v0.5.3. CVE-2025-5981 (container unpacking, fixed 0.2.1) and CVE-2025-13425 (directory iteration, fixed 0.3.4) are older and in packages `semantic` does not use |
| Canonical location | OK | `github.com/google/osv-scalibr`; OSV-Scanner v2 moved its lockfile code here |
| License | OK | Apache-2.0 |
| Transitive dependencies | Warning | `semantic` imports only the standard library, but requiring its module raises nine shared requirements through version selection (below) |
| Go module status | OK | 26 versions on the Go proxy. The go directive stays where it is |

Requirements raised by adopting the module:

| Module | From | To | In production binary |
|---|---|---|---|
| `go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp` | v0.61.0 | v0.68.0 | Yes |
| `go.yaml.in/yaml/v2` | v2.4.2 | v2.4.4 | Yes |
| `github.com/tidwall/match` | v1.1.1 | v1.2.0 | Yes |
| `github.com/tidwall/pretty` | v1.2.0 | v1.2.1 | Yes |
| `github.com/moby/moby/client` | v0.4.0 | v0.5.0 | No, tests only |
| `github.com/moby/moby/api` | v1.54.1 | v1.55.0 | No, tests only |
| `github.com/containerd/platforms` | v0.2.1 | v1.0.0-rc.1 | No, tests only |
| `github.com/docker/go-connections` | v0.6.0 | v0.7.0 | No, tests only |
| `github.com/go-ole/go-ole` | v1.2.6 | v1.3.0 | No, tests only |

OSV lists no advisories for any of the raised versions. The production package list changes only inside otelhttp, which swaps its internal `otel/semconv` versions; adopting `semantic` itself adds that one package.

Alternatives considered: separate per-format libraries, which means several dependencies to vet and no shared interface; and `deps.dev/util/semver`, also from Google, which `osv-scalibr` already requires and which is not a stable release. Neither was better.

## Gotchas

- A scratch module cannot show the raised requirements, because it has no shared dependencies. `go get` in the real module is the only way to see them.
- `semantic.Parse` returned no error for 16 malformed strings in 15 ecosystem spellings, apart from `:` and `a:1.0` in the Debian family. It sorts them above or below every real version, so "parses" says nothing about validity.
- `internal/testutil` failed with `reaper: new reaper ... No such container`, which looked like a result of raising moby. The unmodified `go.mod` failed the same way. It is Ryuk on a shared Docker daemon, and the tests pass with `TESTCONTAINERS_RYUK_DISABLED=true`, the setting CI uses.

## Quality checks

- Documentation only; no tests apply. The dependency checks above ran against the versions listed.
- `go test ./internal/testutil/... ./internal/feed/generic/...` passes on the raised requirements, the former with `TESTCONTAINERS_RYUK_DISABLED=true`.
- `govulncheck ./...` reports GO-2026-6865 (`klauspost/compress`), GO-2026-4887 and GO-2026-4883 (`docker/docker`). All three are in modules this change does not move.
