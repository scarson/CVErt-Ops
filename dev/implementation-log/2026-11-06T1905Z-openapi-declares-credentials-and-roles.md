# OpenAPI declares credentials and roles for every operation

## What was built

- `bearerAuth` (http bearer) and `cookieAuth` (`apiKey` in the `access_token` cookie) in both served documents.
- `operationAccess` in `internal/api/openapi_security.go`: one table of method and path to access, for all 137 operations, applied after the spec merge.
- `x-min-role` on role-gated operations (`viewer`, `member`, `admin`, `owner`, `site-admin`), and `x-own-credential` on operations authenticated by their own cookie.
- `TestOpenAPISecurity_MatchesEnforcement` reads the served spec and calls every operation on a real server: no credentials, an API key one role too low, a key at the minimum role, an owner's session, and a site admin's session.
- PLAN §16 now says API keys are declared only as `http bearer`, the browser session as a cookie scheme, and never a credential in a query parameter. Sam approved this on 2026-11-06.

## Key decisions

- One table rather than a field on each `huma.Operation`: chi routes and their spec-only declarations live apart, so per-operation fields would add a third place to keep in step. A missing entry panics in `Handler`, and every test that builds a handler catches it.
- Roles go in `x-min-role`, not the security requirement's list. OpenAPI 3.0 requires that list to be empty for these schemes, 3.0 is the document `oapi-codegen` reads, and a list there means "all of these", not "this role or higher".
- Refresh, logout, MFA challenge and verify, and MFA confirm are authenticated by dedicated cookies that huma already documents as parameters, so they carry `x-own-credential` instead of a scheme.

## Gotchas

- huma validates the body before a handler checks its cookie, so session-only operations need a valid body or they answer 400 or 422 for the wrong reason. The test holds those bodies.
- The conformance run sends hundreds of requests in seconds, past even the enterprise rate limit. A 429 fails the test outright, because it answers before the check under test.

## Quality checks

- `go test ./internal/api/` passes. Four deliberate table errors were each caught: a role declared too high, one too low, an admin route opened to keys, and an authenticated route declared public.
- `vue-tsc --build` passes against the regenerated types.
- Not tested: a Go client from `oapi-codegen`, which auto mode refused to run. A typed `openapi-typescript` client did call the real stack with a key.
