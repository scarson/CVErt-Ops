# Round 2 wave read: integration defects in the edit wave

Document: `dev/plans/2026-11-13-api-client-cli-and-mcp-server-design.md`. Wave: the working-tree diff against `b493321`. Read on 2026-11-13. Ranked most severe first.

## D1. Section 12 says the design text follows each recommendation; in several places it follows the other option

- **Section 12, preamble:** "The design text follows the recommendation where it has to say something, and marks the span as pending."
- **What is wrong:** several spans follow the option that section 12 does not recommend, and some are not marked as pending.
  - Exit codes. Recommendation 7 is exit 0 for an empty list and a new code 10 for an invalid rule. Section 5.4 still has 3 ("A search or list returned no items") and 8 ("`rules validate` when the server answers `valid: false`"), and its table has no code 10. Section 9.2 tests "(3, or 0 if Sam decides empty lists exit 0)" and "(8, subject to the same decision)". These spans are marked as proposals, but they show the option that is not recommended.
  - Write switch. Recommendation 6 is "with named tools" (`--enable-write-tool NAME`). Sections 7.2, 9.3, 11 and 13 ("the write flag") all use the single `--enable-writes` flag. Section 7.1 ("plus the set of write tools to offer") fits the named-tools option instead, so sections 7.1 and 7.2 describe different switches.
  - Request pacing. Recommendation 13 is that the clients pace their own requests to half the org rate. Section 5.5 and the section 2 rate-limit row ("they retry 429 only within a time budget") describe no pacing and do not mark the span as pending.
- **Evidence:** section 5.4 table; section 7.1 paragraph 2; section 7.2 paragraph 1; section 9.2 bullet 4; section 9.3 bullet 3; section 11 bullets 2 and 3; section 13 item 2; section 12 items 6, 7 and 13.

## D2. Exit 9 is defined two ways

- **Section 5.4, code 9:** "the only items it could not answer were ones the server could not answer even alone".
- **Section 6.2, step 4:** "A half that hits the time limit again is not split further: all of its items are unanswered."
- **What is wrong:** step 4 makes items unanswered without ever sending them alone, so the section 5.4 definition excludes them. Step 6 ("If every failure was of that kind, … exits 9") does not settle it. "That kind" can mean step 5's single-item failures, which would match section 5.4, or every unanswered item, which would include step 4's halves. Under the first reading, a run whose only failure is a half that timed out twice has no exit code, because step 7 covers only "any other failure".
- **Evidence:** sections 5.4 and 6.2, steps 4 to 7.

## D3. The worst case for the 503 split is wrong once the two split rules interleave

- **Section 6.2:** "A batch that came from a 422 split can be split again on a timeout, and the reverse; … The worst case of step 4 is three time-limited requests for one batch, about 90 seconds."
- **What is wrong:** suppose an input batch gets a 422 and is split, and each half then times out, is split, and both of its quarters time out again. That is six time-limited requests (about 180 s) for one input batch, and recursive 422 splits allow more. With "and the reverse", it is also unclear whether a piece that came from a 422 split of a timeout half may be split again on a timeout. "Not split further" applies only to "a half that hits the time limit again".
- **Evidence:** section 6.2, step 4 and the paragraph after the steps.

## D4. The server's version is relied on, but no build sets it; the cited facts are partly wrong

- **Section 5.1:** "No build in the repository sets the server's version flags today (the Dockerfile and CI pass `-s -w` only), so nothing relies on them."
- **Section 5.6:** "`cvert whoami` prints the client's version beside the server's (section 10)". **Section 10:** whoami returns "the server's version".
- **What is wrong:**
  1. The wave now relies on the server's version (sections 5.6 and 10), which contradicts "nothing relies on them". In every build the server reports `version = "dev"`, so the comparison in section 5.6 shows nothing.
  2. CI passes no linker flags, not `-s -w`.
  3. The `/cvert` in the image (section 8.2) gets no VCS revision. `.dockerignore` excludes `.git`, so `ReadBuildInfo` reports `(devel)`. Section 5.1 says only "the VCS revision Go records in local builds", which hides this.
- **Evidence:**
  - `cmd/cvert-ops/main.go` lines 60–67: `version = "dev"`, `commit = "unknown"`, settable only by `-X` linker flags.
  - `docker/Dockerfile` lines 38 and 46: `-ldflags="-s -w"`.
  - `.github/workflows/ci.yml` line 222: `run: go build ./cmd/cvert-ops`, with no flags.
  - `.dockerignore`: `.git` is excluded.

## D5. `cvert whoami` both prints the server body unchanged and adds the client's version

- **Section 5.6 (new):** "`cvert whoami` prints the client's version beside the server's".
- **Section 5.3 (unchanged):** "A single-resource command prints the server's response body unchanged".
- **What is wrong:** `whoami` is a single-resource command (section 5.2, `GET /whoami`). It cannot both print the body unchanged and add a field. Section 5.3 lists `events list` as its only exception.

## D6. "Every list command takes `--cursor`" does not hold for `events list`

- **Section 5.2:** "Every list command takes `--cursor`, to continue from a `next_cursor` it printed, and `--all`."
- **What is wrong:** the `events list` row is `events list [--after CURSOR] … [--all]`, with no `--cursor`. Section 5.3 says the cursor `events list` prints is meant for `--after`. The sentence contradicts the table, or it adds a second cursor flag to `events list` that nothing defines.

## D7. Section 8.1 says the CLI and the MCP server cannot disagree on retries, but section 7.5 now makes them differ

- **Section 8.1 (unchanged):** "The CLI and the MCP server share batching, retries and error mapping in `internal/apiclient`, so the two cannot disagree on them." The same section says `internal/mcpserver/` is "Built from an `*apiclient.Client`."
- **What is wrong:**
  - Section 7.5 now gives the MCP server its own policy: it returns a 429 at once instead of waiting within a budget, it does not split on the time-limit 503, and it applies a 60-second deadline per call. Section 6.2 requires the CLI to do the opposite on the first two. Section 8.1's claim that the two cannot disagree is no longer true, and it does not say where the different policy lives.
  - Section 7.1 now builds the MCP package from the client "plus the set of write tools to offer and the client's version". The "Built from an `*apiclient.Client`" line in section 8.1 is out of date.

## D8. Section 12.8 says the production stack's Caddy uses a local CA, but the repository's Caddyfile does not support that

- **Section 12, item 8:** "The default production stack's Caddy issues certificates from its own local CA, so a client on another host needs to trust it".
- **What is wrong:** the Caddyfile uses the local CA only when `CADDY_HOST` is left at its default, `localhost`, which it documents as "default dev". For a production hostname it documents Let's Encrypt. In the `localhost` setup the site matches only the host name `localhost`, so the case "a client on another host" that this item describes does not arise in that setup. A private CA may still be needed for internal names. But the stated reason, that the default production stack uses Caddy's local CA, is not what the repository's configuration says.
- **Evidence:** `docker/Caddyfile` lines 3–20 ("localhost (default dev) … Uses Caddy's built-in local CA"; "cvert.example.com (production) … Auto-provisions a trusted certificate via Let's Encrypt") and line 25 (`{$CADDY_HOST:localhost} {`).

## D9. The `go install` command given for the plan's first task is invalid, and the table says the install already works

- **Section 3:** "An end-to-end `go install ./cmd/cvert@<branch>` is the plan's first task".
- **What is wrong:**
  - Go refuses a relative path with a version suffix. The command has to be `go install github.com/scarson/cvert-ops/cmd/cvert@<branch>`, the form the table above it uses.
  - The table cell says the install "works", while this paragraph says it is unverified until that task runs.
- **Evidence:** `go help install` (Go 1.27.4): "Arguments must be package paths or package patterns … They must not be … relative or absolute file paths." For context, `go list -m -json github.com/scarson/cvert-ops@latest` does return a pseudo-version (`v0.0.0-20260510080726-74ab7227a4d8`, dated 2026-05-10). So `@latest` resolves to a six-month-old commit, which supports the text's advice to name a commit or a branch.

## D10. The stop rule's list of exit codes leaves out 8

- **Section 6.2, step 7:** "Any other failure (401, 403, 5xx, a network error, or the retry budget running out on 429 or a busy slot) stops the run … exits with that failure's code (4, 5, 7, 1 or 6)".
- **What is wrong:** steps 3 to 7 do not cover a 400, a 413, or a 422 with a problem type other than the candidate limit. Section 5.4 maps those to exit 8, but step 7's list of codes does not include 8, so it is unclear whether such a failure stops the run, and with which code.

## D11. The section 12.7 recommendation contradicts the requirement as section 1 now summarises it

- **Section 1 (new):** "The requirement asks … for exit codes that tell no results, authentication failure, rate limiting and server errors apart."
- **Section 12, item 7(a):** "Recommendation: exit 0 for empty lists".
- **What is wrong:** under that recommendation, an empty search or list exits 0, so "no results" has its own exit code only for a 404 from a single-resource lookup. Item 7 does not say that it departs from the requirement that section 1 now states.

## D12. Section 12.13's example of `--all` contradicts the `--all` limit

- **Section 12, item 13:** "`watchlists items list --all` over 10,000 items takes 200 requests, so it exits 6 after holding the bucket empty".
- **What is wrong:** section 5.2 makes `--all` stop "above 10,000 items with exit 2". A list "over 10,000 items" would therefore exit 2 if the walk got that far. A whole-list replace also caps a watchlist at 10,000 items (section 2). The arithmetic holds for a list of exactly 10,000: 200 pages of 50. So "over" should be "of", or the item should state which limit is reached first.
- **Evidence:** `internal/api/watchlists.go` line 717: `const limit = 50`.

## D13. Rebuttals bolted onto design sentences

Each of these clauses reads as an answer to a reviewer's objection rather than as design text:

- **Section 5.2:** "requests were sent by then, which exit 2's description allows." This justifies the edit against the exit-code table instead of stating the behaviour.
- **Section 4.1, `mcp-go`:** "Its smaller advisory count is not evidence of a safer parser: it has its own JSON handling, which nobody has audited the way the official SDK's was in 2026". The audit claim is not supported anywhere in the document.
- **Section 2, check row:** "the clients cannot change that, and the server's single slot stays as the version check design set it." The consequence column now argues against changing the server instead of stating a consequence for this design.
- **Section 9.2:** "an invalid rule in `rules validate` (8, subject to the same decision)". "The same decision" refers back to the empty-list decision, 7(a), but the invalid-rule decision is 7(b) and has three options. The recommended one, code 10, is not mentioned.

## D14. Small factual slips introduced by the wave

- **Section 7.1, item 2:** "`internal/alert/dsl` and `internal/ai` both reach `internal/store/generated` indirectly." `internal/alert/dsl` imports it directly, in `internal/alert/dsl/accessor.go`. Only `internal/ai` reaches it indirectly, through `internal/ai/schema.go`, which imports `internal/alert/dsl`.
- **Section 2, score filters row:** "`internal/api/cves.go` lines 262–267". The four fields are at lines 265–268; `EPSSMax` is at line 268. The raw query string is read in `Resolve`, at lines 304–307 (`parseFloat("cvss_min", …)`).
- **Section 8.2:** "`.golangci.yml`: the `depguard` rule of section 7.1, and the `go list -deps` test beside it." A Go test cannot live in `.golangci.yml`, so the line reads as if it does. Neither this line nor section 9.1 names the package that holds the test.
- **Section 7.5:** "One MCP session costs one request at startup (`whoami`) and one request per tool call, plus the requests of any 422 split." This leaves out busy-slot retries (section 7.5, "Retries") and the `whoami` retry on the first tool call after a failed startup (section 7.1).

## Claims checked and found correct

These claims, introduced by the wave, match the repository:

- **Audit calls:** `auditLog` is called at lines 256, 307, 515, 559 and 691 of `internal/api/watchlists.go`, for create (including the tier-limit refusal), update, delete and replace. There is none for adding or deleting a single item.
- **DSL catalog:** `field.go` imports only `internal/ecosystem`. `FieldDescription` has `ValidOps` and `EnumValues`, and `internal/ai/schema.go` calls `dsl.ExportFieldDescriptions()`.
- **Score filters:** none of the four appears in `openapi.json`.
- **Unexported handler types:** `alertEventEntry`, `watchlistItemEntry` and `alertRuleEntry` are unexported and served by chi routes.
- **Check endpoint:**
  - The `id` limit is 128 (`maxIDLen`).
  - `rpm` gives `unsupported_purl_type` (`internal/ecosystem/purl.go`).
  - `epss_score` and `in_cisa_kev` on a check advisory can be null.
  - `warnings` and `error.code` are enumerated in the spec.
  - Problem `title` is `http.StatusText` (`internal/api/contract.go` line 34).
- **CVE detail:** it returns `range_type`, `introduced` and `fixed`, but no `last_affected` (`internal/api/cves.go` lines 100–102).
- **Alert events:** `first_fired_at DEFAULT now()` and `id … DEFAULT gen_random_uuid()` (migration 000016). Implementation pitfalls NOTIFY-20 and ARCH-13 exist and say what the design attributes to them.
- **Test server dependencies:**
  - `ServerDeps{}` is used in `internal/api/smoke_test.go`.
  - Without an evaluator, dry-run answers 503 ("dry-run not available").
  - `audit.Writer` writes asynchronously and has `Flush()`.
- **Membership check:** `RequireOrgRole` returns 403 when an API key's user is no longer a member or is deactivated.
- **Server and spec:**
  - The server has no TLS listener.
  - Compose names the service `app` on port 8080.
  - The spec tests fetch `/api/v1/openapi-3.0.json` in process.
