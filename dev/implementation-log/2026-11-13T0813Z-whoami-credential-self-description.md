# GET /whoami: a credential describes itself

## What was done

`GET /api/v1/whoami` answers "who am I and what may I do" in one call, so a script given only a base URL and a key can find its org and limits (requirement AUTH-5 of the private homelab integration requirements).

- **API-key caller:** `principal: "api_key"`, the creator's `user_id`, `api_key` (ID, name, the key's own role cap, `expires_at` or null) and `org` (ID, name, the role the key acts with, tier, and `rate_limit`). The role is the key's role lowered to the creator's current org role, exactly as `RequireOrgRole` computes it.
- **Browser session:** `principal: "session"`, `user_id`, and `orgs`: each org where the membership is active, with the same role, tier and rate-limit fields. Deactivated memberships and deleted orgs are left out. Sessions are answered because it costs one loop over the memberships and gives the SPA and a logged-in user the tier and limit per org, which `/auth/me` does not.
- `rate_limit` is `{scope: "org", requests_per_minute, burst}`: the token bucket `orgRateLimitMiddleware` enforces. `scope` says the bucket is shared by every caller in the org; a per-key bucket (AUTH-7) would add another scope.
- A key whose creator is no longer an active member gets 403, as on every org route. A key's call to `/whoami` spends a token from its org's bucket, so it cannot be used to poll past the org's limit. Session calls are not rate limited, like `/auth/me`.
- Spec: the `whoami` operation in `openapi_spec.go`, `"GET /whoami": anyCredentialOp()` in the security table; `openapi.json` and `web/src/lib/api/schema.d.ts` regenerated.

## Decisions and gotchas

- **No `scopes` field.** Key scopes (AUTH-3) do not exist yet; the field is added with them rather than shipped as an always-empty list a client might read as "no access".
- **Shared helpers instead of copies.** `orgTierResolver` (tier cache, then store), `orgRateLimitFor` / `orgRateLimitFromPerMinute` (burst is a sixth of the per-minute rate, at least 1) and `allowOrgRequest` are now used by both the middleware and `/whoami`, so the reported limit cannot drift from the enforced one. `capToKeyRole` and `Role.String` replace the inline cap in `RequireOrgRole`.
- The route is outside `/orgs/{org_id}`, so it does not get `ctxOrgID`, `tierMiddleware` or `orgRateLimitMiddleware`; the handler does the membership, tier and bucket steps itself for the key's org.

## Quality checks

- `internal/api/whoami_test.go`: key caller (acceptance: one call gives key, org, capped role, tier, 60/min burst 10), never-expiring key with a tier override (pro tier, override 120/min, burst 20), session with one active and one deactivated membership, unauthenticated and bad key (401), deactivated key creator (403), and the 11th call in a burst of a free-tier key (429). All six failed with 404 before the route existed.
- `go test ./internal/api/ -run 'TestWhoami|TestOpenAPI|TestRequireOrgRole|TestTier|TestOrgRateLimit|RateLimit'`: pass after two fixes. The response schema was first named `WhoamiResponse`, the name oapi-codegen gives the operation's own response type, which `TestOpenAPISpec_SchemaNamesFitGeneratedClients` rejects; the types are now `CallerIdentity`, `CallerAPIKey`, `CallerOrg` and `CallerRateLimit`. `TestOpenAPISecurity_MatchesEnforcement` calls `/whoami` with every key role and a session.
- golangci-lint v2.15.0 (the CI pin, via `go run`; the `~/go/bin` build is too old for Go 1.27.4) on `./internal/api/...`: 0 issues.
- `security-review` checklist on the diff: no failures. The membership, org and tier reads use bypass transactions, as `RequireOrgRole` and `tierMiddleware` do, with IDs taken from the authenticated key or the user's own memberships, never from the request.
