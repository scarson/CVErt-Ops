# Ecosystem vocabulary at the API edge

## What was built

- DSL conditions, watchlist items and `GET /cves?ecosystem=` accept OSV's ecosystem names only, and reject old names such as `pypi` or `cargo` with a 422 listing the canonical names.
- A value matches a stored ecosystem that equals it or starts with it followed by a colon, so a bare `Debian` covers every release and `Ubuntu:Pro` covers every Ubuntu Pro release.
- Watchlist and search comparisons fold package names (lower case, and PEP 503 separators for PyPI) through `ecosystem.FoldedNameSQL`. Stored names keep their upstream spelling.
- The web watchlist dialog offers canonical names.

## Decisions and gotchas

- There is no compatibility for old names, by Sam's decision: there are no existing installs, so no stored rule or item is rewritten.
- The DSL's `affected.package` substring match does not fold separators.
- A release picker in the dialog is out of scope; naming one release is available through the API.

## Quality checks

Targeted tests for `internal/alert`, `internal/api` and `internal/store` passed with `golangci-lint` clean, and the web dialog test, lint and type check pass. The full suite is run before this branch merges.
