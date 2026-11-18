# Round 2 review: alternatives and rationale

Document: `dev/plans/2026-11-13-api-client-cli-and-mcp-server-design.md` (worktree `cli-mcp-design-5a3740`, HEAD `b493321`).
Lens: alternatives & rationale. Findings are ranked most severe first.

## R1 · alternatives & rationale · §5.2 Commands / §11 Acceptance

**Anchor:** §5.2, `watchlists items replace` row: "`--cves` reads one CVE ID per line, the shape `jq -r` produces from a scanner report." §11: "replace a watchlist's CVE items from a scanner report".

**Claim:** The chosen mechanism for scanner-driven CVE lists (a whole-list `PUT` built only from `--cves`) does not do what the acceptance criterion says. It replaces every item on the watchlist, so any package or CPE item on the same watchlist is deleted. The design does not weigh the alternative of a client-side merge (read the current items, keep the non-CVE items, send the merged list) or a diff (add missing CVEs, remove stale CVEs one by one).

**Evidence:** §2 says watchlists are "replaced as a whole list (`PUT`, at most 10,000 items)". The server's replace response documents removal of everything not in the request: `internal/api/watchlists.go` line 93, `Removed int ... "Items that were on the watchlist, not in the request, and were removed"`. Nothing in §5.2 restricts `--cves` to CVE-only watchlists or warns that other item types are dropped. §11 says "replace a watchlist's CVE items", which is a narrower operation than the one designed.

**Axes:** Objective (the PUT semantics and the acceptance wording disagree). Remedy is a choice: client-side merge, a documented "CVE-only watchlist" precondition with a refusal when other types exist, or rewording the acceptance.

## R2 · alternatives & rationale · §5.4 Exit codes

**Anchor:** "| 3 | No results | A search or list returned no items; `cves get` or `cves sources` got 404. |" and "| 0 | Success | ... for a search or list, returned at least one item. |"

**Claim:** Treating an empty list as a non-zero exit is a significant decision with no recorded rationale and no recorded alternative (exit 0 with an empty `items` array, leaving emptiness to `jq -e`). It conflicts with the design's primary use case, a timer script polling alert events: `events list --after <cursor>` with no new events is the normal steady state and would exit 3.

**Evidence:** §1 names "scripts on a timer" and "poll alert events" as the first use. §10 states the poller stores and resumes from a cursor, so an empty page is expected on most runs. A script under `set -e`, or a systemd timer unit, treats exit 3 as a failure every quiet interval. The design gives the opposite reasoning for `check` in §5.4 ("`jq -e` expresses each choice in one line") and does not explain why the same argument does not apply to lists. Decision 6 in §12 lists the exit codes but gives no reason for code 3.

**Axes:** Contestable (grep-style "no match" exit codes are a known convention). Remedy is a choice: record the rationale, exempt `events list --after`, or make empty a success.

## R3 · alternatives & rationale · §2 Findings (DSL row) / §7.3 Descriptions

**Anchor:** §2: "The MCP server cannot import it to build its DSL reference without linking store code; a test keeps a hand-written reference in step instead (section 7.3)."

**Claim:** The stated reason for a hand-written DSL reference does not survive scrutiny, and the obvious alternative is unmentioned. Only `accessor.go` imports the store; the field catalog and an export function for it are store-free and already consumed by another feature. Moving the catalog to a leaf package would let `internal/mcpserver` build the `validate_rule` description from the canonical source. The drift test proposed instead checks only field names, so operators and enum values in the hand-written text can drift undetected.

**Evidence:**
- `grep -n "cvert-ops/internal" internal/alert/dsl/*.go` (non-test): `accessor.go` imports `internal/store/generated`; `field.go`, `compiler.go` and `validator.go` import only `internal/ecosystem`.
- `go list -deps ./internal/ecosystem` lists no other `cvert-ops` package.
- `internal/alert/dsl/field.go` lines 58-68 define `FieldDescription{Name, TypeDesc, ValidOps, EnumValues, Nullable}` and `ExportFieldDescriptions()`, which `internal/ai/schema.go` line 38 already uses to describe the DSL to an LLM.
- §7.3 test: "one fails when a DSL field name in `internal/alert/dsl` is missing from the `validate_rule` description" (names only; no operator or enum check).

**Axes:** Objective that the alternative exists and that the stated obstacle is narrower than claimed. Remedy is a choice (extract the catalog to a store-free package; or keep hand-written text and widen the test to operators and enums), and extraction touches server code outside this design's scope.

## R4 · alternatives & rationale · §3 Decision: a separate `cvert` binary

**Anchor:** "The deciding facts are `go install` and the size of what an agent host has to run. Whether `go install` from the proxy works for this module ... is untested; the plan's first task verifies it against a pushed branch."

**Claim:** One of the two deciding facts is unverified and no fallback is recorded if it fails. The comparison also omits an obvious distribution alternative: prebuilt release binaries. `go install` requires a Go 1.27.4 toolchain on every agent host and workstation; release binaries need none and would also make the server binary installable without Node, which removes the install-path argument for either option. The repository has no release workflow, so this is a real gap, not a duplicate of existing practice.

**Evidence:** `.github/workflows/` contains only `ci.yml`. `go.mod` declares `go 1.27.4`, which `go install` will require or fetch. The §3 table's "Install" row compares only `go install` with "a source checkout with Node and `npm run build`, or the container image". `go.mod` has no `replace` or `exclude` directives (checked), so the most common cause of `go install pkg@version` failure is absent; the case mismatch (`github.com/scarson/cvert-ops` versus remote `github.com/scarson/CVErt-Ops.git`) remains the open question the design names.

**Axes:** Contestable (release automation is extra work). Remedy is a choice: record the fallback if `go install` fails, and either weigh release binaries or state why they are out of scope.

## R5 · alternatives & rationale · §8.2 Build and image

**Anchor:** "Version and commit set by the same ldflags as the server; `cvert --version` prints them, and the MCP server reports them in its implementation info."

**Claim:** The chosen mechanism does not work on the design's primary install path, and the alternative is unmentioned. `go install` cannot set `-X` ldflags, and no existing build sets them for the server either, so `cvert --version`, the `User-Agent: cvert/<version>` of §5.1 and the MCP implementation info would all report the default. `runtime/debug.ReadBuildInfo` reports the module version for `go install pkg@vX` builds and the VCS revision for local builds, with no build flags.

**Evidence:** `cmd/cvert-ops/main.go` lines 60-62 document `-X main.version=... -X main.commit=...`, but `docker/Dockerfile` builds with `-ldflags="-s -w"` only, and `.github/workflows/ci.yml` contains no `ldflags`. §5.6 relies on version identity ("built and tested against the spec of its own commit") while stating nothing detects skew; an unset version removes even manual diagnosis.

**Axes:** Objective (no build sets the flags; `go install` cannot). Remedy is a choice (`ReadBuildInfo`, or add ldflags to every build and accept that `go install` builds report no version).

## R6 · alternatives & rationale · §5.1 Configuration / §12 decision 7

**Anchor:** "`http://` is refused unless the host is a loopback address, because the key would cross the network in clear text. No flag overrides this."

**Claim:** The rationale is stated, but no alternative is recorded, and two deployment cases in this repository are not weighed. (a) The repository's default Caddy configuration issues certificates from Caddy's local CA, so a client on another host needs a way to trust that CA; the design has no CA setting and does not say that the `SSL_CERT_FILE` environment variable is the answer (Go honours it on Linux, not on Windows or macOS, where the platform verifier is used). (b) §3 offers `docker run --entrypoint /cvert` from the server's own image; on the compose network the app is `http://app:8080`, which this rule refuses, so that path must go through Caddy's external hostname. An explicit opt-in (for example an environment variable naming the allowed plain-HTTP host) and a CA-file setting are the obvious alternatives.

**Evidence:** `docker/Caddyfile`: "`localhost` (default dev) ... Uses Caddy's built-in local CA to issue a self-signed certificate"; `reverse_proxy app:8080`. `docker/compose.prod.yml` line 18: "Only Caddy publishes host ports". §5.1 has no TLS trust setting.

**Axes:** Contestable (refusing plain HTTP with no override is a defensible security stance). Remedy is a choice: record the rejected override with its reason, and decide how a private CA is trusted.

## R7 · alternatives & rationale · §4.2 API client: hand-written, not generated

**Anchor:** "Keeping in sync" row: "The 3.0 document is served but not checked in. CI would have to write it, run the generator and fail on a diff" versus "A test (no database) checks every operation the client calls against the checked-in `openapi.json`".

**Claim:** Two problems. (a) The sync row compares unequal guarantees as if they were equal cost: generation gives compile-time types for every field; the hand-written test checks names only (§9.1 lists "method, path template, query parameters, body field names, and the response field names"), so a type, nullability or enum change passes. The cost difference named (writing the 3.0 file) is small, since `internal/api/openapi_test.go` already writes `openapi.json` under `GENERATE_OPENAPI=1` and `openapi_security_test.go` already fetches `/api/v1/openapi-3.0.json` in process. The decisive reasons are the runtime dependency and the generated volume; the sync row does not distinguish the options. (b) An obvious third option is unmentioned: move the exported request and response structs the client needs into a store-free package that both server and client import, giving compile-time agreement with no generator and no new dependency. The check types, which §6.3's merge must reproduce exactly, are already exported.

**Evidence:** `openapi.json` line 5880: `"openapi": "3.1.0"` (the checked-in file is 3.1; the generator needs 3.0). `internal/api/check.go` lines 43-89 export `CheckRequest`, `CheckItem`, `CheckResults`, `CheckFeedStatus`, `CheckItemResult`, `CheckComponent`, in a package that imports the store (forbidden to the client by §7.1's `depguard` rule).

**Axes:** (a) contestable; (b) objective that the option exists and is unweighed. Remedy is a choice; (b) touches server code.

## R8 · alternatives & rationale · §5.2 `watchlists items add`

**Anchor:** "an item already on the list fails with 409 (exit 8). A caller that needs a repeatable operation uses `replace`."

**Claim:** The rationale does not distinguish the options. `replace` is not a repeatable add: it removes every item not in the request (see R1). A script or agent that wants to ensure one item is watched, without touching the rest, has no idempotent path. The alternative of treating 409 "item already exists" as success (or a `--ignore-existing` flag) is not recorded. The same applies to the MCP `add_watchlist_item` tool, where an agent retrying after a lost response gets a tool error for an add that succeeded.

**Evidence:** `internal/api/watchlists.go` line 614 returns 409 "item already exists in watchlist"; line 93 documents replace's removals.

**Axes:** Contestable. Remedy is a choice.

## R9 · alternatives & rationale · §6.1 Input

**Anchor:** "| `trivy` | A Trivy JSON report. | One item per distinct package (below). |"

**Claim:** The scanner input is tied to one tool's native report format, with no recorded reason over a scanner-neutral format such as CycloneDX JSON, which Trivy (`--format cyclonedx`), Syft and others emit and which carries `components[].purl` directly. The design itself notes the Trivy field names "come from Trivy's report type, not from a captured report" and need a golden fixture to confirm, which is a maintenance cost a standard format may reduce. The source-package substitution of §6.1 would still need tool-specific properties in a CycloneDX document, so the choice may be right; it is just not argued. (The private requirement may name Trivy; this reviewer could not read it, and the design does not say so.)

**Evidence:** §6.1 and §6.1 "Trivy reports" paragraph; no mention of CycloneDX, SPDX or other scanners anywhere in the document.

**Axes:** Contestable. Remedy is a choice (record the reason, or add a neutral format).

## R10 · alternatives & rationale · §5.4 Exit codes / §12 decision 6

**Anchor:** "| 8 | Request rejected | 400, 404 on a path other than a lookup, 409, 413, 422; and `rules validate` when the server answers `valid: false`. |"

**Claim:** Mapping "the rule is invalid" to the same code as transport-level rejections (malformed request, unknown watchlist ID, payload too large) is unexplained, and a script cannot tell "fix your rule" from "your request or IDs are wrong" without parsing stderr. Neither a dedicated code nor the `check` approach (exit 0, let `jq -e '.valid'` decide, as §5.4 argues for `check`) is recorded as considered.

**Evidence:** §2 says only "`rules validate` maps `valid: false` to an exit code"; §5.4's reasoning for `check` points the other way and is not reconciled.

**Axes:** Contestable. Remedy is a choice.

## R11 · alternatives & rationale · §4.1 MCP SDK

**Anchor:** "No advantage over the official SDK for a server that this project would maintain for years." and "Both SDKs below depend on it, so no SDK avoids it."

**Claim:** The rejection of `mcp-go` does not engage the design's own evidence: the official SDK had four high-severity advisories in 2026, two of them in JSON parsing that a stdio server uses (field case matching, NUL handling), against one for `mcp-go`, in an OAuth client this design would not use. The stated reason (long-term maintenance by the official project) may still decide it, but the advisory comparison is left unaddressed. Separately, "Both SDKs below" refers to two SDKs while only one SDK alternative is listed, so either an alternative was dropped from the record or the sentence is wrong; the claim "no SDK avoids it" rests on that list.

**Evidence:** §4.1 vulnerability row and the alternatives list.

**Axes:** Contestable (official-project backing is a legitimate tiebreaker). Remedy is determinate for the dangling "Both SDKs" reference; a choice for the rationale.

---

Per-lens line — alternatives & rationale: R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11.
