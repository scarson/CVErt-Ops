# GHSA token variable

## What was built

- The GHSA adapter reads its token from `GITHUB_GHSA_TOKEN`, not `GITHUB_TOKEN`. The production compose file, its render test, `.env.example`, the getting-started settings table and `dev/research-findings/ghsa.md` use the same name.
- `.env.example` says how to get the token: a fine-grained personal access token with public repositories read-only and no permissions. GitHub's global advisories endpoint (`GET /advisories`) needs no permission.

## Decisions and gotchas

- `GITHUB_TOKEN` is set by GitHub Actions and the gh CLI for other purposes. Under the old name the adapter would send whatever token those set to the advisories endpoint. `TestNewReadsGHSATokenOnly` sets both variables and checks that only `GITHUB_GHSA_TOKEN` is read.
- No compatibility with the old name: there are no existing installs.
- Historical plans and implementation logs still say `GITHUB_TOKEN`, because they record what was true when written.

## Quality checks

- `TestNewReadsGHSATokenOnly` failed before the change and passes after it.
- `go test ./internal/feed/ghsa/ ./docker/ -count=1` passes. `golangci-lint run` on both packages: 0 issues.
