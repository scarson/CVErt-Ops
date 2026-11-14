# encoding/json/v2 Migration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (or superpowers:executing-plans) to implement this plan phase by phase.

**Goal:** Move the JSON paths where `encoding/json/v2` makes CVErt-Ops more correct or more secure, and record, with reasons, which paths stay on v1 `encoding/json`.

**Architecture:** v2 is adopted per call site, never by a global switch. Caller-supplied JSON is decoded with v2's strict defaults (case-sensitive names, duplicate names refused, invalid UTF-8 refused, trailing data refused) plus `RejectUnknownMembers` where the project defines every key. A value that is validated in one place and consumed in another is decoded by one shared function, so the two cannot read it differently. Byte-stable outputs (hash inputs, stored formats, outbound payloads) and upstream feed parsing stay on v1, which Go 1.27 keeps and implements on top of v2 with v1's behaviour.

**Tech Stack:** Go 1.27.4 (`encoding/json`, `encoding/json/v2`, `encoding/json/jsontext`), huma v2.37.3, chi, PostgreSQL 18 (JSONB), testcontainers-go, Vue 3 SPA with `openapi-typescript`.

**Pitfall documents (read before any task):** `dev/implementation-pitfalls.md` (API-2: `omitempty` on PATCH structs; FEED-1, FEED-4, FEED-20: feed wire-format assumptions and decoder draining) and `dev/testing-pitfalls.md` (§7: seed CVE data with `testutil.SeedCorpus` or store methods, never raw SQL).

**Related work:**
- scarson/CVErt-Ops#250, merged into `dev` at `1f32430` — `decodeJSON` in `internal/api/contract.go` decodes every chi request body with v2 and `RejectUnknownMembers`, answering 422 with a huma-style location such as `body.items[1].x`.
- Branch `claude/strict-dsl-conditions` (worktree `.claude/worktrees/objective-grothendieck-b9ac93`), not yet committed on 2026-11-14 — makes `dsl.Parse` (`internal/alert/dsl/parser.go`) decode with v2 and `RejectUnknownMembers`, returning `*dsl.UnknownKeyError`. Because alert-rule create/PATCH/validate, saved-search create/PATCH/execute and the AI query endpoint all call `dsl.Parse`, that branch covers them. Phase 5 depends on it.

---

## Living Document Contract

This plan is a living document. Every executing agent MUST update it as
execution progresses, not only at completion.

Where this project has no git repository, every reference below to a SHA,
a branch, or a PR means the nearest durable equivalent the project does
offer (a dated revision, a build identifier, a release tag), and where
none exists the banner states that plainly. An invented SHA is worse than
an absent one: it reads as an anchor and sends the next agent looking for
a commit that never existed.

- **Before any phase claim:** no phase may be claimed while the
  **Plan review** line in Execution Status reads ⬜ NOT RUN. An unreviewed
  plan is not executable. Run the review (`plan-review-cycle`) and let its
  completion flip the line, or — if this plan was legitimately exempted by
  the user — record that at the line as ⏭ SKIPPED with the date, so the
  exemption is visible instead of indistinguishable from an omission.
- **On phase claim:** before flipping your own banner, check the preceding
  phase's banner against git reality — a ✅ SHIPPED banner's recorded SHA
  reachable on `dev`, a 🚧 banner live per observable signals (an open PR,
  recent branch commits). If a banner does not match reality, correct it
  first. Then flip your own banner to 🚧 IN PROGRESS with a claim timestamp
  (ISO 8601 UTC) and the branch name. Do not write an expected-completion
  estimate.
- **On phase ship:** record the shipped commit SHA(s), date, and PR link in
  the Execution Status table. The banner ships in its own commit, after the
  work: commit the work with a pathspec that excludes this plan, read the
  SHA back from git, then commit the table update on top. Do not amend.
- **On phase defer:** set ⏸ with a prose unblock condition and a link to
  the artifact whose own status will signal the unblock.
- **On PR merge:** record the merge SHA in the table.
- **On deviation from the written plan:** document it inline in the
  affected task AND add a one-line summary to "Deviations" below the table.
- **On discovery** (pre-existing defects, drift): add a one-line entry with
  file:line pointers to "Discoveries" below the table.

**Layout invariant.** Only the two one-line headers — **Plan review** and
**Overall** — sit above the status table. Deviations and Discoveries are
subsections below it; each entry is one line plus a pointer.

Why this matters here: the phases ship as separate PRs over several sessions, two of them wait on other work (the strict-DSL branch, and Sam's decisions below), and the next session must be able to tell from this file alone what has landed.

---

## Execution Status
<!-- Plan review and Overall are the only lines above the table. New content goes
     in the Deviations / Discoveries subsections below it — never above the table. -->

**Plan review:** ✅ 2026-11-14 — 5 rounds (2 self, 2 independent cold reads with go1.27.4 probes, 1 self pass on round-4 fixes): 11, 17, 0, 9, 0 findings; all fixed in place
**Overall:** ⬜ Not started

| Phase | Status | Ship SHA(s) | PR | Notes |
|---|---|---|---|---|
| 0 — Precondition: strict DSL parsing on `dev` | ⬜ | | | Owned by branch `claude/strict-dsl-conditions` |
| 1 — Notification channel config: one strict decoder for API and delivery | ⬜ | | | Starts after Sam answers decision 1 |
| 2 — SCIM request bodies | ⬜ | | | |
| 3 — huma-registered request bodies and `clearableField` | ⬜ | | | |
| 4 — Opaque pagination cursors | ⬜ | | | After Phase 3 (same file) |
| 5 — Stored alert-rule conditions fail closed | ⬜ | | | After Phase 0 |
| 6 — API response encoding | ⬜ | | | After Phase 3; waits on Sam's decision 3 |
| 7 — Replace the JCS dependency with `jsontext.Value.Canonicalize` | ⬜ | | | Waits on Sam's decision 2 |
| 8 — Pitfall entries, PLAN.md, final full suite | ⬜ | | | Last |

### Deviations
(none yet)

### Discoveries
(none yet)

---

## Decisions for Sam

Decision 1 gates Phase 1, decision 2 gates Phase 7, decision 3 gates Phase 6. Phases 2–5 need none of them. Recommendations first.

1. **Refuse channel config keys that delivery does not read.** Recommended: yes. Today the API accepts and stores any config key, masks the ones delivery does not read, and `TestChannelConfig_UnrecognisedFieldsMaskedAndKeptOnRoundTrip` (`internal/api/channels_redaction_test.go:~381`) pins that as intended behaviour. Refusing them makes "what the API validated" equal "what delivery reads" and removes a class of stored values nobody can see. Changing it means rewriting that test (it becomes a refusal test, and the masking of such keys in already-stored rows moves to a store-seeded test); the test is not deleted. If Sam declines, Phase 1 still ships case-sensitive matching and typed header values, and both parsers omit `RejectUnknownMembers` (Task 1.1 says where).
2. **Replace `github.com/cyberphone/json-canonicalization` with the standard library's RFC 8785 canonicalizer** (`jsontext.Value.Canonicalize`, Go 1.27). Recommended: yes, as Phase 7. It removes a third-party dependency (pseudo-version `v0.0.0-20241213102144-19d51d7fe467`, no tagged release) from the `material_hash` path. The golden hash pins (`internal/merge/testdata/golden_material_hashes.json`) must not move; if any pin moves, the phase stops.
3. **Encode API responses with v2.** Recommended: yes, last (Phase 6). The gain: a nil slice or map is written as `[]` or `{}`, which is what the published OpenAPI schemas (non-nullable arrays and objects) and the generated TypeScript types already promise; v1 writes `null`. The cost: every `omitempty` on a bool, number, pointer, interface, or `json.RawMessage` field of a response type needs `omitzero` to keep its current output, and HTML characters are no longer escaped (harmless for `application/json` with `X-Content-Type-Options: nosniff`). Phase 6 has a measurement step that lists every field whose output would change before anything is switched.

---

## Background: what v2 changes (verified on go1.27.4, 2026-11-14)

The list below comes from `go doc encoding/json` ("Migrating to v2") and from probe programs run against the local toolchain. Statements marked *probed* were observed, not only read.

| Behaviour | v1 (`encoding/json`) | v2 default | Relevance |
|---|---|---|---|
| Object name matching | case-insensitive | case-sensitive (*probed*: `{"URL":"b"}` does not fill `json:"url"`) | Validation reading one key and delivery reading another |
| Duplicate names | allowed, last wins (*probed*) | error, including two spellings of one field under `MatchCaseInsensitiveNames` (*probed*: `userName` + `USERNAME` → "duplicate object member name") | Parser differentials |
| Case-insensitive matching when asked for | — | `MatchCaseInsensitiveNames(true)` and the `case:ignore` tag also ignore `_` and `-` (`user_name` fills `userName`); v1's `json.MatchCaseSensitiveDelimiter(true)` turns that off | SCIM (Phase 2) |
| Unknown members | ignored | ignored unless `RejectUnknownMembers(true)`; a case variant of a known name counts as unknown under case-sensitive matching | Silently dropped input |
| Struct field `format` tag option | — | not in Go 1.27's stable v2 (tag options: `omitzero`, `omitempty`, `string`, `case`, `embed`) | Phase 6 |
| Trailing data | `Decoder.Decode` stops after the first value (*probed*) | `Unmarshal`/`UnmarshalRead` refuse it (*probed*) | Smuggled second value |
| Invalid UTF-8 | replaced with U+FFFD on decode and encode (*probed*) | error on decode and encode (*probed*: marshal fails mid-output); `jsontext.AllowInvalidUTF8(true)` restores replacement (*probed*) | A response that echoes bad bytes becomes a marshal error |
| Strictness inside a v1-style `UnmarshalJSON([]byte)` method | — | **not propagated** (*probed*: unknown member and case-variant accepted inside such a method under `RejectUnknownMembers`) | `clearableField` |
| Strictness inside an `UnmarshalJSONFrom(*jsontext.Decoder)` method that calls `UnmarshalDecode` | — | propagated (*probed*) | `clearableField` fix |
| Strictness inside a `json.RawMessage` member | — | syntax, duplicate names and UTF-8 are checked; names are not (*probed*) | Channel `config`, DSL condition `value` |
| Map key order on marshal | sorted | unordered (*probed*: varies across runs); `Deterministic(true)` gives v1's order (*probed*) | Any hash or byte comparison |
| nil slice / nil map / nil `[]byte` | `null` | `[]` / `{}` / `""` (*probed*) | API responses, stored formats |
| `omitempty` | omits false, 0, nil pointer, nil interface, empty slice/map/string | omits a field that *encodes* as `null`, `""`, `{}` or `[]` (*probed*: `false`/`0` now written; a non-nil pointer to an empty struct and a `*string` pointing at `""` now omitted) | Response shapes |
| `omitzero` | supported | supported, same meaning (*probed*) | The portable replacement |
| `string` tag option | strings, bools, numbers | numbers only | No use in this repository (grep for `,string"` finds none) |
| `time.Duration` | integer nanoseconds | runtime error without a format option (*probed*) | No tagged `time.Duration` field found |
| HTML escaping | `<`, `>`, `&` escaped | not escaped (*probed*) | Response bytes |
| JSON `null` into a non-pointer | usually leaves the value | zeroes it (*probed*) | `decodeScalar` already refuses `null` |
| Error types | `*json.SyntaxError`, `*json.UnmarshalTypeError` | `*jsontext.SyntacticError`, `*jsonv2.SemanticError` (*probed*) | NVD and KEV adapters branch on the v1 types |

Two facts from the Go 1.27 documentation frame the scope: the v1 API is not deprecated, and v1 is now implemented as v2 plus `DefaultOptionsV1`. Staying on v1 therefore carries no maintenance cost once `GOEXPERIMENT=nojsonv2` is removed; the reason to move a call site is a behaviour it gains, not v1 going away. Also, `json.RawMessage` is now an alias of `jsontext.Value`, and `json.Marshaler`/`json.Unmarshaler` are aliases of the v2 interfaces, so types declared with them need no change when a call site moves.

A JSONB column cannot hold duplicate keys (Postgres keeps the last), trailing data, or invalid UTF-8. v2's duplicate, trailing-data and UTF-8 checks therefore add nothing on reads from JSONB; on stored reads only name case and unknown members can differ.

---

## Inventory (2026-11-14, `dev` at `9fd15f7`)

`grep -rl '"encoding/json"$' --include=*.go .` lists 91 non-test files and 137 test files. One non-test file, `internal/api/contract.go`, also imports v2.

| Category | Files importing v1 (non-test) | Verdict |
|---|---|---|
| 1. Untrusted request input | `internal/api/` 18 files hold the call sites below; `internal/alert/dsl/` 5 | Migrate the sites in Phases 1–4; DSL value decoders stay (see below) |
| 2. Stored-data reads | `internal/store/` 14 hand-written, `internal/alert/evaluator.go`, `internal/notify/` 4, `internal/check/` 3, `internal/ingest/` 3, `cmd/cvert-ops/main.go`, `internal/worker/job.go` | Migrate two readers (Phase 1 channel config, Phase 5 rule conditions); the rest stay |
| 3. API responses | `writeJSON` family in `internal/api/contract.go`, `readyz.go`, `server.go`; huma's `DefaultJSONFormat` | Phase 6, subject to decision 3 |
| 4. Feed adapters | `internal/feed/` 14 | **Stay on v1** |
| 5. sqlc-generated code | `internal/store/generated/` 12 | **Stay on v1** (nothing to change) |
| 6. Tests and fixtures | 137 test files | **No bulk migration**; rules below |
| Other: hash and dedup inputs | `internal/merge/hash.go`, `match_inputs.go`, `resolve.go`, `internal/check/names.go` | **Stay on v1 marshal**; Phase 7 swaps only the canonicalizer |
| Other: formats this app writes and reads back | `internal/merge/pipeline.go` (`normalized_json`), `internal/audit/writer.go`, `internal/store/security_events.go`, `internal/store/notification_delivery.go`, `internal/notify/digest.go`, `dispatcher.go`, `worker.go:268`, feed and evaluator cursors, job payloads | **Stay on v1** |
| Other: outbound and third-party | `internal/secure/syslog.go` (syslog), `internal/notify/` webhook payloads, `internal/api/oauth_github.go` (GitHub API responses), `internal/ai/gemini.go` | **Stay on v1** (Gemini output is parsed strictly later by `dsl.Parse`) |
| Other: tools | `dev/cmd/` 3, `internal/testutil/` 2, `.claude/skills/performance-audit/test-fixtures/go-sample/service.go` | **Stay on v1** |

### Category 1 — untrusted request input: every remaining parser of caller-supplied JSON

| Site | Today | Phase |
|---|---|---|
| `internal/api/contract.go:110` `decodeJSON` (every chi body) | v2 strict | done (PR #250) |
| `internal/alert/dsl/parser.go` `Parse` (alert rules, saved searches incl. `query_json`, AI query) | v1 | strict-DSL branch (Phase 0) |
| `internal/api/channels.go:122,304` webhook `config` → `map[string]any`; `:729` `validateEmailConfig`; delivery reads at `internal/notify/webhook.go:40`, `internal/notify/worker.go:292` | v1, case-insensitive struct decode at delivery vs case-sensitive map lookup and redaction at the API | 1 |
| `internal/api/scim_users.go:90,594,756`, `internal/api/scim_groups_handler.go:39,220,347` (`json.NewDecoder(r.Body).Decode`) | v1: duplicate names (last wins), trailing data accepted | 2 |
| huma-registered operations with bodies: `internal/api/auth.go:1124-1240` (register, login, refresh, change-password, accept-invitation, forgot/reset-password, verify-email, resend-verification), `internal/api/auth_mfa.go:1436-1520` (MFA) | huma `DefaultJSONFormat.Unmarshal` = v1; huma's schema validation already refuses unknown names | 3 |
| `internal/api/contract.go:195` `clearableField.UnmarshalJSON` (nested v1 decode) | strictness of the outer v2 decode does not reach `T` | 3 |
| `internal/api/contract.go:247` `decodePageCursor` (14 callers), `internal/api/cves.go:183` `decodeCursor`, `internal/store/dsl_executor.go:97` `decodeDSLCursor` | v1 | 4 |
| `internal/alert/dsl/validator.go:135,216,240,263,299,573`, `compiler.go:289,357`, `sets.go:596` (condition `value` into string, number, `[]string`) | v1 | **stay**: the bytes are a `json.RawMessage` that the outer v2 decode (Parse, or Phase 5 for stored rules) has already checked for syntax, duplicates and UTF-8, and for scalar and `[]string` targets v1 and v2 agree on everything else (`decodeScalar` refuses `null` explicitly) |
| `internal/api/scim_groups_handler.go:570-590` `extractMemberValues` (PATCH member `value` into `SCIMGroupMember`), `internal/api/scim_users.go:896-903` (pathless replace `value` into `map[string]json.RawMessage`, matched with `strings.ToLower`) | v1: `[{"value":"A","VALUE":"B"}]` resolves to `B`; `{"active":false,"Active":true}` resolves in map iteration order | 2 (Task 2.2): the outer decode checks exact duplicates only, not case-variant ones |
| `internal/api/scim_users.go:847-879`, `scim_groups_handler.go:394`, `scim_types.go:108-120` (PATCH `value` into a string or bool) | v1 into scalars | **stay**: scalar targets have no member names; bytes already checked by the Phase 2 outer decode |
| `internal/api/ingest.go:49` `raw_payload` | `json.RawMessage` inside a `decodeJSON` body | done (checked by the outer v2 decode; stored as JSONB) |

### Category 2 — stored reads: policy

A stored row was written through a validated path, so a stricter read can only change outcomes for rows written before the validation existed or by a path that skipped it. Fail-closed matters where the stored value decides what the system does on someone's behalf: which CVEs an alert rule matches, and where a notification is sent and what is shown about it. For those two, the read uses the same strict decoder as the write and a refused row fails visibly (rule → `status='error'`; delivery → permanent failure recorded on the delivery). Every other stored reader decodes values this application marshaled itself with v1 (cursors, job payloads, `normalized_json`, CNA versions, digest lists, AI cache, tier overrides, watchlist matches); strictness there adds no protection and would turn a format slip into an outage of a background worker, so they stay on v1.

### Category 4 — feed adapters stay on v1

Feeds must tolerate upstream drift (FEED-1, FEED-4). Under v2 defaults, one upstream record with a duplicate key or a stray invalid byte would abort a whole page instead of being decoded the way it is today, and invalid UTF-8 that v1 turns into U+FFFD would become a hard error that also changes what reaches `material_hash`. The NVD and KEV skip-bad-record logic branches on `*json.SyntaxError` and `*json.UnmarshalTypeError` (`internal/feed/nvd/adapter.go:446-455`, `internal/feed/kev/adapter.go:226-236`). Using v2 with options that restore all of that (`MatchCaseInsensitiveNames`, `jsontext.AllowDuplicateNames`, `jsontext.AllowInvalidUTF8`, `FormatNilSliceAsNull`, ...) is v1 under another name. The only gain would be decoder speed, which is not this plan's goal. If a future change does move a streaming loop, the CLAUDE.md rule maps as follows: `json.Decoder.Token()` → `jsontext.Decoder.ReadToken()`, `Decoder.More()` → `dec.PeekKind() != ']'` (or `'}'`), skipping a value → `dec.SkipValue()`, decoding one element → `jsonv2.UnmarshalDecode(dec, &elem)`; `jsonv2.UnmarshalRead(r, &slice)` is forbidden for large feeds exactly as `Decode(&slice)` is.

### Category 5 — sqlc-generated code stays on v1

`internal/store/generated` imports `encoding/json` only for the `json.RawMessage` type of JSONB columns (`sqlc.yaml` does not set `emit_json_tags`). `json.RawMessage` is now an alias of `jsontext.Value`, so the generated code already works with either package. The code is regenerated by `sqlc generate` and must not be edited.

### Category 6 — tests and fixtures: rules, no bulk migration

- Do not convert the 137 test files. A test that decodes a response with v1 is lenient about unknown fields, which keeps tests from breaking when a field is added; that is acceptable.
- A test that asserts a strictness behaviour (a phase in this plan) decodes or sends JSON exactly as the production path does.
- A test that compares JSON **bytes** must use v1 or `jsonv2.Deterministic(true)`; v2 map order varies between runs.
- `TestOpenAPISpec` (`internal/api/openapi_test.go:207`) writes `openapi.json` with v1 `json.MarshalIndent` and compares parsed values. Keep v1 there: sorted keys keep the committed file diffable.
- Golden fixtures: feed golden files (`internal/feed/*/testdata/golden`) are upstream bytes and do not change. `internal/merge/testdata/golden_material_hashes.json` pins `material_hash` for the golden corpus (`internal/merge/material_hash_golden_test.go`); no phase except Phase 7 touches hashing, and Phase 7 must leave every pin unchanged. `internal/alert/dsl/where_golden_test.go` pins SQL text and is unaffected.

---

## Setup (every phase)

1. Work in a new worktree branched from local `dev` (CLAUDE.md "Worktree base branch"):
   ```bash
   git worktree add ".claude/worktrees/json-v2-phase-N" -b "claude/json-v2-phase-N" dev
   ```
2. Copy the SPA build, or `go build ./...` fails with `pattern all:dist: no matching files found`:
   ```bash
   cp -r ../../../web/dist web/dist
   ```
   (run from the worktree root; if the main checkout has no `web/dist`, run `cd web && npm run build` there first).
3. Docker Desktop must be running: `internal/api`, `internal/alert`, `internal/store` and `internal/notify` integration tests start Postgres through testcontainers. If Docker is down, stop and tell Sam (CLAUDE.md: a hard blocker; do not fall back to compile-only checks).
4. Run only the tests named in each task while working. Before opening the phase's PR, run the full suite once and record the result in the PR body:
   ```bash
   go test ./... -count=1 -timeout=600s 2>&1 | tee test-run.log
   ```
5. Lint with `golangci-lint run --allow-parallel-runners`.
5a. Test-writing rules that apply to every phase (`dev/testing-pitfalls.md` §16 and §7): every cookie-authenticated POST/PUT/PATCH/DELETE test request through the HTTP stack sets `X-Requested-By: CVErt-Ops` (the CSRF check applies only to requests carrying the auth cookie, so a login request without cookies, such as `doLogin` in `auth_test.go:66-76` sends, needs none); never discard a setup error with `_ =`; a test that calls `testutil.SeedCorpus` must not call `t.Parallel()` (SeedCorpus calls `t.Setenv`); assert on decoded problem JSON (`status`, `errors[i].location`, `errors[i].message`), not on substrings of the body.
6. After each commit, add an implementation-log entry in `dev/implementation-log/` (naming rules in `dev/implementation-log/README.md`).
7. Each phase ships as its own PR to `dev`.

Every task below uses these two blocks; they are not repeated in full.

```
BEFORE starting work:
1. Invoke /superpowers:test-driven-development
2. Read dev/testing-pitfalls.md
Follow TDD: write failing test → implement → verify green.
```

```
BEFORE marking this task complete:
1. Review tests against dev/testing-pitfalls.md
2. Verify test coverage (error paths? edge cases?)
3. Run tests and confirm green
```

And after each phase:

```
After completing this phase:
Review the phase from multiple perspectives (correctness, security, test
quality). Minimum 3 review rounds. If round 3 still finds issues, keep going
until clean.
```

---

## Phase 0 — Precondition: strict DSL parsing on `dev`

Not executed by this plan. Phase 5 starts only after the strict-DSL work (branch `claude/strict-dsl-conditions`) is merged into `dev`. Check with:

```bash
git log --oneline dev -- internal/alert/dsl/parser.go
```

and confirm that `internal/alert/dsl/parser.go` on `dev` calls `jsonv2.Unmarshal(..., jsonv2.RejectUnknownMembers(true))`. Record the merge SHA in the table. If the branch's final design differs from what Phase 5 assumes (a shared options value, the name `UnknownKeyError`), adapt Phase 5 and record a deviation.

---

## Phase 1 — Notification channel config: one strict decoder for API and delivery

**Why.** The API checks a webhook `url` by looking up `cfg["url"]` in a `map[string]any` (case-sensitive) and masks config for responses and audit records by exact key (`internal/audit/redact.go:27-46`, except header keys, which it matches with `strings.EqualFold`). Delivery decodes the same stored bytes into a struct with v1, which matches names case-insensitively (`internal/notify/webhook.go:36-40`, `internal/notify/worker.go:289-292`). So an email channel stored with `{"Recipients":["x@example.com"]}` passes `validateEmailConfig` (v1, case-insensitive), is shown to admins and in the audit log as `"Recipients":"[REDACTED]"` (not an address list under the key `recipients`), and is delivered to `x@example.com`. A webhook `custom_headers` value that is not a string (`{"X-A":1}`) passes the API (it decodes into `map[string]any`). At delivery, v1 finishes the decode and then reports a type error, which `ChannelWebhookConfig` discards, so the delivery goes out with header `X-A` set to an empty value: the stored config and what is sent differ without any error.

**Behaviour after the phase.** Rows marked *(decision 1)* depend on `RejectUnknownMembers`; the "If declined" column gives the outcome when Sam declines decision 1 (v2 then ignores unknown and case-variant names silently).

| Input (create or PATCH `config`) | Today | After | If declined |
|---|---|---|---|
| webhook `{"URL":"https://h.example/x"}` *(decision 1)* | 422 "must include a non-empty url" (map lookup misses) | 422, `body.config.URL`, "unexpected property" | 422, `body.config.url`, "webhook config must include a non-empty url"; key stored only if a `url` is also sent |
| email `{"Recipients":["a@example.com"]}` *(decision 1)* | 201, delivered, shown masked | 422, `body.config.Recipients`, "unexpected property" | 422, "email config must include at least one recipient" |
| webhook `custom_headers` `{"X-A":1}` | 201, delivered with `X-A` empty | 422, `body.config.custom_headers.X-A`, "custom_headers values must be strings" | same as After |
| webhook `{"url":"...","note":"x"}` *(decision 1)* | 201, `note` stored and masked | 422 `body.config.note`, "unexpected property" | 201 as today |
| webhook `{"url":1}` | 422, `body.config.url`, "webhook config must include a non-empty url" | unchanged | unchanged |
| `null`, `[]` or `"x"` as `config` | 422 (webhook `null` at `body.config.url`, since `null` decodes into the map without error; others at `body.config` or `body.config.recipients`) | 422 at `body.config` with the type's existing message | same as After |
| duplicate key inside `config` | 400 (already refused by `decodeJSON`'s v2 decode) | unchanged | unchanged |
| stored row (written before this phase) that the parser refuses, at delivery | delivered per v1 reading | permanent delivery failure, reason recorded | same, for the rows the declined parser still refuses |
| stored row with unknown keys *(decision 1)*: GET | keys shown masked | unchanged (masking code untouched) | unchanged |
| stored row with unknown keys *(decision 1)*: PATCH sending back the config read from GET | 200 | 422 at `body.config.<first unknown key>`; row unchanged | 200 |

### Task 1.1 — Typed channel config parsers in `internal/notify`

**Files:**
- Create: `internal/notify/channel_config.go`
- Create: `internal/notify/channel_config_test.go`
- Modify: `internal/notify/webhook.go:23-47` (`ChannelWebhookConfig`)
- Modify: `internal/notify/worker.go:252-259` (`deliverWebhook`), `internal/notify/worker.go:285-298` (`deliverEmail`)
- Modify: `internal/api/channels.go:544-572` (`testWebhookChannel`, caller of `ChannelWebhookConfig`)

**Step 1 — failing unit tests** (`channel_config_test.go`, table-driven, no Docker):

| Case | Input | Expected |
|---|---|---|
| webhook minimal | `{"url":"https://h.example/x"}` | URL set, headers nil, no error |
| webhook with headers | `{"url":"https://h.example/x","custom_headers":{"X-Team":"secops"}}` | headers map has one entry |
| webhook case variant *(decision 1)* | `{"URL":"https://h.example/x"}` | error; `errors.AsType[*jsonv2.SemanticError]` true, `errors.Is(semErr.Err, jsonv2.ErrUnknownName)` true, pointer `/URL`. If declined: no error, empty URL |
| webhook unknown key *(decision 1)* | `{"url":"https://h.example/x","note":"x"}` | unknown-name error at `/note`. If declined: no error |
| header value not a string | `{"url":"https://h.example/x","custom_headers":{"X-A":1}}` | `*jsonv2.SemanticError`, not unknown-name, pointer `/custom_headers/X-A` |
| not an object | `[]`, `"x"`, `null` | error (v2 decodes `null` into a struct without error, so the parser checks the kind first) |
| email minimal | `{"recipients":["a@example.com"]}` | one recipient |
| email case variant *(decision 1)* | `{"Recipients":["a@example.com"]}` | unknown-name error at `/Recipients`. If declined: no error, no recipients |
| email recipients wrong type | `{"recipients":"a@example.com"}` | `*jsonv2.SemanticError`, pointer `/recipients` |

**Step 2 — run, expect FAIL** (undefined functions):
```bash
go test ./internal/notify/ -run 'TestParse(Webhook|Email)Settings' -count=1
```

**Step 3 — implement** `channel_config.go`:

```go
// ABOUTME: Typed notification channel config and the one decoder that API validation and delivery share.
// ABOUTME: Names match case-sensitively and keys delivery does not read are refused, so what is validated is what is used.
package notify

// WebhookSettings is the config JSON stored for a webhook channel.
// WebhookConfig (webhook.go) is the delivery-time view built from it plus the
// channel's signing secrets.
type WebhookSettings struct {
	URL           string            `json:"url"`
	CustomHeaders map[string]string `json:"custom_headers,omitzero"`
}

// EmailSettings is the config JSON stored for an email channel.
type EmailSettings struct {
	Recipients []string `json:"recipients"`
}

// channelConfigOptions: v2 defaults (case-sensitive names, no duplicates,
// valid UTF-8) plus refusal of keys this type does not define.
var channelConfigOptions = jsonv2.RejectUnknownMembers(true)

// errConfigNotObject reports a config that is not a JSON object.
var errConfigNotObject = errors.New("config must be a JSON object")

func ParseWebhookSettings(raw []byte) (WebhookSettings, error) {
	// if jsontext.Value(raw).Kind() != '{' { return WebhookSettings{}, errConfigNotObject }
	// jsonv2.Unmarshal(raw, &cfg, channelConfigOptions), error wrapped with %w
}
func ParseEmailSettings(raw []byte) (EmailSettings, error) { /* same shape */ }
```

Return the `jsonv2` error wrapped with `%w` so callers can read the `*jsonv2.SemanticError` and its `JSONPointer`. If Sam declines decision 1, `channelConfigOptions` is `jsonv2.DefaultOptionsV2()`, the type comment and the file's ABOUTME drop "keys ... are refused", and the *(decision 1)* test rows take their "If declined" expectations; record a deviation.

Change `ChannelWebhookConfig` to `func ChannelWebhookConfig(ch *store.NotificationChannelForDeliveryRow) (WebhookConfig, error)`, built from `ParseWebhookSettings`. Callers:
- `deliverWebhook` (`internal/notify/worker.go:252`): on error return `&permanentDeliveryError{err: fmt.Errorf("parse webhook config: %w", err)}`, the type `deliverEmail` already uses because config does not change between retries. Today bad config yields an empty URL and the delivery is retried until exhausted; delete the comment at `worker.go:257` that describes that.
- `testWebhookChannel` (`internal/api/channels.go:544`): on error return an error the endpoint reports as a failed test; do not include the stored config in the message.
- Test callers: `grep -rn 'ChannelWebhookConfig(' --include=*_test.go internal` and update each to the two-value form. One needs more than that: the `withOtherKey` case in `internal/notify/webhook_test.go:~359-362` builds config with a `headers` key and asserts that `Send` fails with 401. With decision 1, `ChannelWebhookConfig` now returns an unknown-name error at `/headers`; rewrite the case to assert that error (do not delete it). If declined, the case is unchanged.
- `deliverEmail`: replace the inline struct and `json.Unmarshal` with `ParseEmailSettings`; keep the `permanentDeliveryError` wrapping and the "no recipients" check.

Do NOT change `audit.RedactChannelConfig`, `channelResponseConfig`, `channelAuditState` or `resolveMaskedChannelConfig`: they handle arbitrary stored maps for display and must keep masking keys in rows written before this phase.

**Step 4 — run unit tests, expect PASS; then the package:**
```bash
go test ./internal/notify/ -count=1
```

**Step 5 — delivery tests.** In `internal/notify/worker_test.go` (Docker), insert channel rows with `store.CreateNotificationChannel(ctx, orgID, name, chanType, config)` (`internal/store/notification_channel.go:58`; it stores config as given, bypassing API validation on purpose) and add: an email row with config `{"Recipients":["a@example.com"]}` → delivery ends as a permanent failure and no SMTP send is attempted (decision 1 only; if declined, the delivery fails permanently with "no recipients", which is also a valid assertion). A webhook row with `custom_headers` `{"X-A":1}` → permanent failure whose recorded reason contains `parse webhook config`, and no HTTP request reaches the test server. Existing webhook and email delivery tests stay green.

**Step 6 — commit:** `fix(notify): decode channel config with one strict parser shared with the API`

### Task 1.2 — API create and PATCH validate config with the shared parsers

**Files:**
- Modify: `internal/api/contract.go:152-169` (`bodyLocation`)
- Modify: `internal/api/channels.go:110-160` (create), `:295-330` (PATCH), `:729-757` (`validateEmailConfig`; also called by `testEmailChannel` at `:574-579` with the stored config, so the test endpoint and delivery read email config with the same parser)
- Modify tests: `internal/api/channels_test.go`, `internal/api/channels_redaction_test.go`, `internal/api/contract_test.go`

**Step 1 — generalize the location helper.** Replace `bodyLocation(ptr)` with `jsonLocation(root string, ptr jsontext.Pointer) string`, and keep `bodyLocation(ptr)` as `jsonLocation("body", ptr)` so `decodeJSON` is unchanged. Add a `contract_test.go` case: `jsonLocation("body.config", "/custom_headers/X-A")` → `body.config.custom_headers.X-A`.

**Step 2 — failing API tests** (`channels_test.go`, Docker), each for create and for PATCH, asserting status, `errors[0].location` and `errors[0].message`:
Each row of the Phase 1 behaviour table that concerns create or PATCH becomes a test case, with the exact status, location and message the table gives, including:
- webhook `{"URL":...}` *(decision 1)* → 422, `body.config.URL`, `validation.MsgUnexpectedProperty`.
- email `{"Recipients":[...]}` *(decision 1)* → 422, `body.config.Recipients`, `validation.MsgUnexpectedProperty`.
- webhook `custom_headers` `{"X-A":1}` → 422, `body.config.custom_headers.X-A`, "custom_headers values must be strings".
- webhook with an unknown key *(decision 1)* → 422 at `body.config.<key>`.
- Regression: existing masked round-trip tests (`channels_redaction_test.go` round trips with `[REDACTED]` values) still pass.
Before writing these, grep `channels_test.go` for existing assertions on `body.config.recipients` and `body.config` locations; Step 3 keeps those locations for the errors they cover, and any assertion that changes is listed in the commit message.

**Step 3 — implement.** In create and PATCH, after `resolveMaskedChannelConfig` and before the `url` and SSRF checks: for `webhook` call `notify.ParseWebhookSettings`; for `email`, change `validateEmailConfig` to `func validateEmailConfig(config json.RawMessage) ([]string, *huma.ErrorDetail)`, which calls `notify.ParseEmailSettings` first and returns the detail (location and message) to write. Today both email callers hard-code `Location: "body.config.recipients"` (`channels.go:~139`, `:~321`); make them write the returned detail instead, keeping `body.config.recipients` as the location of the recipient-count, RFC 5322 and duplicate errors. `testEmailChannel` (`channels.go:574`) uses only the detail's `Message`. Map parse errors to 422 responses:

| Parse error | Location | Message |
|---|---|---|
| unknown-name `*jsonv2.SemanticError` | `jsonLocation("body.config", semErr.JSONPointer)` | `validation.MsgUnexpectedProperty` |
| other `*jsonv2.SemanticError` with pointer `/url` (webhook) | `body.config.url` | "webhook config must include a non-empty url" (today's response) |
| other `*jsonv2.SemanticError` with pointer under `/custom_headers/` | `jsonLocation("body.config", ptr)` | "custom_headers values must be strings" |
| other `*jsonv2.SemanticError` with pointer `/custom_headers` | `body.config.custom_headers` | "custom_headers must be an object of header names to strings" |
| other `*jsonv2.SemanticError` with pointer `/recipients` or under it (email) | `body.config.recipients` | "email config must include a recipients array" |
| anything else (not an object, syntax) | `body.config` | webhook: "webhook config must be valid JSON with a url field"; email: "email config must include a recipients array" |

Then run the existing checks on the typed value: non-empty `url` (location `body.config.url`), `validateWebhookURL`, and in `validateEmailConfig` the recipient count, RFC 5322 and duplicate checks, now reading `EmailSettings.Recipients`. Remove the `map[string]any` decodes at `channels.go:121-123` and `:303-305`. Do NOT change the masking helpers named in Task 1.1.

**Step 4 — the existing intended-behaviour test (decision 1 only).** `TestChannelConfig_UnrecognisedFieldsMaskedAndKeptOnRoundTrip` creates a channel through the API with keys delivery does not read. Do not delete it. Change it into two tests: (a) the API refuses that body with 422 at `body.config.account` — `resolveMaskedChannelConfig` re-encodes the config with v1 `json.Marshal`, which sorts keys, and v2 reports the first unknown member it meets, so `account` comes before `auth`, `extra` and `nested`; and (b) for a row with those keys inserted through `store.CreateNotificationChannel` (a legacy row): GET returns the keys masked exactly as the original test asserts; a PATCH that changes only `name` succeeds and its audit record's old and new state show the keys masked (assert with the original test's `assertNoCredential` helper); and a PATCH that sends back the config read from GET returns 422 at `body.config.account`, with the stored row unchanged. `TestChannelAuditState_MasksUnrecognisedFields` calls `channelAuditState` directly and is unchanged.

**Step 5 — run:**
```bash
go test ./internal/api/ -run 'TestChannel|TestCreateChannel|TestPatchChannel|TestBodyLocation|TestJSONLocation' -count=1
```

**Step 6 — doc text.** Update the `Config` `doc:` strings at `internal/api/channels.go:34-50` so they state the keys each type takes (`url`, `custom_headers` for webhook; `recipients` for email) and, with decision 1, that other keys are refused. This changes `openapi.json` descriptions: regenerate (`GENERATE_OPENAPI=1 go test -run '^TestOpenAPISpec$' ./internal/api/`, then `cd web && npm run generate-api`) and commit both.

**Step 7 — commit:** `fix(api): validate channel config with the parser delivery uses`

### Task 1.3 — Pre-deploy check of stored channels

Before this phase's PR merges, run against every database that holds channels (dev databases; the kept full-ingest database `cvert-check-ingest-pgdata` holds CVE data and is read only — check it, do not modify it):

```sql
-- Channels the strict parsers refuse. The first branch applies only with decision 1.
SELECT c.id, c.org_id, c.type, 'unknown key: ' || k.key AS problem
FROM notification_channels c
CROSS JOIN LATERAL jsonb_object_keys(CASE WHEN jsonb_typeof(c.config) = 'object' THEN c.config ELSE '{}'::jsonb END) AS k(key)
WHERE c.deleted_at IS NULL
  AND ((c.type = 'webhook' AND k.key NOT IN ('url', 'custom_headers'))
    OR (c.type = 'email'   AND k.key <> 'recipients'))
UNION ALL
SELECT c.id, c.org_id, c.type, 'config is not an object'
FROM notification_channels c
WHERE c.deleted_at IS NULL AND jsonb_typeof(c.config) <> 'object'
UNION ALL
SELECT c.id, c.org_id, c.type, 'url is not a string'
FROM notification_channels c
WHERE c.deleted_at IS NULL AND c.type = 'webhook' AND jsonb_typeof(c.config) = 'object'
  AND jsonb_typeof(c.config->'url') IS DISTINCT FROM 'string'
UNION ALL
SELECT c.id, c.org_id, c.type, 'custom_headers is not an object of strings'
FROM notification_channels c
WHERE c.deleted_at IS NULL AND c.type = 'webhook' AND jsonb_typeof(c.config) = 'object'
  AND jsonb_typeof(c.config->'custom_headers') NOT IN ('object', 'null')
UNION ALL
SELECT c.id, c.org_id, c.type, 'custom_headers has a value that is not a string'
FROM notification_channels c
CROSS JOIN LATERAL jsonb_each(CASE WHEN jsonb_typeof(c.config->'custom_headers') = 'object' THEN c.config->'custom_headers' ELSE '{}'::jsonb END) AS h(name, value)
WHERE c.deleted_at IS NULL AND c.type = 'webhook' AND jsonb_typeof(h.value) <> 'string'
UNION ALL
SELECT c.id, c.org_id, c.type, 'recipients is not an array'
FROM notification_channels c
WHERE c.deleted_at IS NULL AND c.type = 'email' AND jsonb_typeof(c.config) = 'object'
  AND jsonb_typeof(c.config->'recipients') IS DISTINCT FROM 'array'
UNION ALL
SELECT c.id, c.org_id, c.type, 'recipients has an element that is not a string'
FROM notification_channels c
CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(c.config->'recipients') = 'array' THEN c.config->'recipients' ELSE '[]'::jsonb END) AS e(value)
WHERE c.deleted_at IS NULL AND c.type = 'email' AND jsonb_typeof(e.value) <> 'string';
```

(`jsonb_typeof` of a missing member is SQL NULL, hence `IS DISTINCT FROM`; a missing `url` or `recipients` already fails today's checks and is listed for completeness. A `custom_headers` of JSON `null` decodes to a nil map and is accepted. Set-returning functions read their input only through `CASE` guards, because Postgres does not promise the order in which `OR`/`AND` operands are evaluated.)

Both `notification_channels` and `alert_rules` have `FORCE ROW LEVEL SECURITY`, which applies to the table owner too, so running as the owner sees no rows and reports a false clean result. Run the check with `psql` in a transaction that sets the bypass the workers use, and prove the rows are visible first:

```sql
BEGIN;
SET LOCAL app.bypass_rls = 'on';
SELECT count(*) FROM notification_channels;   -- must equal the table's real row count, not 0
-- the check query above
COMMIT;
```

(or connect as a superuser, which RLS never applies to). Record both counts in the PR body. This is a one-off check, not a migration. Rows found fail delivery after the deploy; on dev databases, fix or delete them by hand.

---

## Phase 2 — SCIM request bodies

**Why.** SCIM bodies come from an external identity provider. `json.NewDecoder(r.Body).Decode` accepts duplicate names with the last one winning, two spellings of one attribute (RFC 7643 §2.1 makes SCIM attribute names case-insensitive, so `userName` and `USERNAME` are the same attribute) with the last one winning, and a second JSON value after the first. Where the IdP and CVErt-Ops would resolve such a body differently, the provisioned identity differs from what the IdP shows.

**Behaviour after the phase.** Bodies decode with v2, `MatchCaseInsensitiveNames(true)` (required by SCIM) together with v1's `json.MatchCaseSensitiveDelimiter(true)` (without it, v2's case-insensitive matching also ignores `_` and `-`, so an IdP attribute `user_name` or `external_id` would fill `userName` or `externalId`; RFC 7643 asks only for case-insensitivity; the option lives in package `encoding/json` and v2 calls accept it), without `RejectUnknownMembers` (IdPs send extension schemas and attributes this server ignores; RFC 7644 lets a service provider ignore them). Duplicate names, two spellings of one attribute, trailing data and invalid UTF-8 → 400 with the SCIM error each handler writes today: the three user handlers (`scim_users.go:91,595,757`) write `scimType` `""`, the three group handlers (`scim_groups_handler.go:40,221,348`) write `scimType` `"invalidValue"`, all with detail `"invalid JSON body"`. Keep both as they are.

### Task 2.1 — `decodeSCIMBody` and its six callers

**Files:**
- Modify: `internal/api/scim_types.go` (add `decodeSCIMBody`)
- Modify: `internal/api/scim_users.go:90,594,756`, `internal/api/scim_groups_handler.go:39,220,347`
- Test: `internal/api/scim_types_test.go` (unit), `internal/api/scim_users_test.go`, `internal/api/scim_groups_handler_test.go` (Docker)

**Step 1 — failing tests.** Unit (`scim_types_test.go`) for `decodeSCIMBody` into `scimUserRequest`:
- `{"userName":"a","USERNAME":"b"}` → false, 400 written.
- `{"userName":"a","userName":"b"}` → false.
- `{"userName":"a"} {"userName":"b"}` → false.
- body with byte `0xff` inside a string → false.
- `{"UserName":"a","externalId":"x"}` → true, `UserName == "a"` (case-insensitive match still works).
- `{"userName":"a","user_name":"b","external_id":"x"}` → true, `UserName == "a"`, `ExternalID == ""` (delimiters are not folded; `user_name` and `external_id` are unknown attributes and ignored).
- body with `"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"x"}` → true (unknown attributes ignored).
Handler tests (Docker): one create-user and one group PATCH with a duplicate attribute → 400 and no row written.

**Step 2 — run, expect FAIL:**
```bash
go test ./internal/api/ -run 'TestDecodeSCIMBody' -count=1
```

**Step 3 — implement:**

```go
// scimJSONOptions decode SCIM JSON: attribute names match case-insensitively
// (RFC 7643 section 2.1) but '_' and '-' are not ignored, and encoding/json/v2's
// defaults refuse duplicate names, trailing data and invalid UTF-8.
var scimJSONOptions = jsonv2.JoinOptions(jsonv2.MatchCaseInsensitiveNames(true), json.MatchCaseSensitiveDelimiter(true))

// decodeSCIMBody decodes a SCIM request body into dst. Attribute names match
// case-insensitively, as RFC 7643 section 2.1 requires; attributes dst does not
// define are ignored. Duplicate attributes (in any spelling), trailing data and
// invalid UTF-8 are refused with a 400 SCIM error, which has been written when it
// returns false. scimType is the SCIM error type the caller reports.
func decodeSCIMBody(w http.ResponseWriter, r *http.Request, dst any, scimType string) bool {
	if err := jsonv2.UnmarshalRead(r.Body, dst, scimJSONOptions); err != nil {
		writeSCIMError(w, http.StatusBadRequest, scimType, "invalid JSON body")
		return false
	}
	return true
}
```

Replace the six `json.NewDecoder(r.Body).Decode(&x)` blocks with `if !decodeSCIMBody(w, r, &x, <scimType>) { return }`, passing `""` in `scim_users.go` and `"invalidValue"` in `scim_groups_handler.go`. Do NOT touch the scalar PATCH `value` decoders listed under Category 1 as "stay", and do not change any `scimType` value.

**Step 4 — run SCIM tests:**
```bash
go test ./internal/api/ -run 'TestSCIM|TestDecodeSCIMBody|TestScim' -count=1
```

**Step 5 — commit:** `fix(api): refuse ambiguous SCIM request bodies`

### Task 2.2 — SCIM PATCH values with member names

**Files:** Modify `internal/api/scim_groups_handler.go:570-590` (`extractMemberValues`), `internal/api/scim_users.go:896-903` (pathless replace); tests in `internal/api/scim_groups_handler_test.go`, `internal/api/scim_users_test.go`.

**Step 1 — failing handler tests** (Docker):
- Group PATCH `add` members with `value` `[{"value":"<uuid A>","VALUE":"<uuid B>"}]` → 400 and membership unchanged. Today B is added.
- User PATCH pathless replace with `value` `{"active":false,"Active":true}` → 400 `invalidValue` and the user's state unchanged. Today the outcome depends on map iteration order.
- Controls: `[{"value":"<uuid A>"}]` adds A; `{"Active":false}` deactivates (case-insensitive name still accepted).
- Unchanged no-ops: an `add` on path `members` with no `value`, and a `remove` on path `members` with `"value":null`, still change nothing and do not return 400 (today both are no-ops).
Each test body holds a single operation: a multi-operation PATCH applies earlier operations before a later one fails, so "membership unchanged" holds only for single-op bodies.

**Step 2 — implement.**
- `extractMemberValues` (today: tries an array decode, falls back to a single-object decode, and returns nil when both fail, so a refused array would silently become "no members"): an empty `raw` or JSON `null` returns `nil, nil` (no members, as today); otherwise choose the shape by `jsontext.Value(raw).Kind()` — `'['` decodes `[]SCIMGroupMember`, `'{'` decodes one `SCIMGroupMember`, anything else is an error — each with `jsonv2.Unmarshal(raw, &x, scimJSONOptions)`. Change the signature to `([]uuid.UUID, error)`. Callers: the `add` path at `scim_groups_handler.go:371` writes `writeSCIMError(w, http.StatusBadRequest, "invalidValue", "invalid members value")` on error and returns; the helper at `:611` (`extractRemoveTargets`, which has no `http.ResponseWriter`) gains an error return, and its caller in the `remove` path (`:~382`) writes the same error. Keep skipping entries whose `value` is not a UUID, as today; that behaviour is outside this plan.
- Pathless replace: after decoding `valMap`, refuse the operation with `writeSCIMError(w, http.StatusBadRequest, "invalidValue", "pathless operation value has duplicate attributes")` when two keys are equal under `strings.EqualFold`. Keep the `map[string]json.RawMessage` decode and the `strings.ToLower` switch.

**Step 3 — run:** `go test ./internal/api/ -run 'TestSCIM|TestScim' -count=1`

**Step 4 — commit:** `fix(api): refuse SCIM PATCH values that name one attribute twice`

---

## Phase 3 — huma-registered request bodies and `clearableField`

**Why.** The auth and MFA operations are registered with huma (`internal/api/auth.go:1124-1240`, `internal/api/auth_mfa.go:1436-1520`), which decodes bodies with `huma.DefaultJSONFormat.Unmarshal` = v1 (`huma@v2.37.3/defaults.go:16-23`). huma's schema validation refuses unknown and case-variant names (`additionalProperties: false`), but duplicate names (last wins), invalid UTF-8 (replaced) are accepted, unlike every chi body since PR #250. Separately, `clearableField[T].UnmarshalJSON` (`internal/api/contract.go:195-207`) decodes `T` with v1; v2 options do not reach a `[]byte` method, so a struct `T` would accept unknown and case-variant members even inside a strict `decodeJSON` body (probed). Today `T` is `uuid.UUID` (`scim_admin.go:63`) or `string` (`watchlists.go:52`), so nothing is exposed yet.

### Task 3.1 — huma decodes request bodies with v2

**Files:**
- Modify: `internal/api/openapi_spec.go:30-37` (`newHumaConfig`)
- Test: `internal/api/auth_test.go` (login handler tests; the operation is `POST /api/v1/auth/login`, registered at `auth.go:1133`)

**Step 1 — failing tests** (Docker). Register a user first (the test file's existing helpers do this). Build each body from raw bytes and send it with `http.NewRequestWithContext`; do not use `doLogin`, which formats the body with `%q` and would turn a `0xff` byte into the escape `\xff`, which v1 already refuses as invalid JSON.
- Duplicate name: `{"email":"other@example.com","email":"<registered email>","password":"<correct password>"}`. Today v1 keeps the last `email` and the login succeeds (200 with auth cookies), so this is red. After: exactly 400, decoded problem `errors[0].location == "body"`, and no `Set-Cookie`.
- Invalid UTF-8: the registered email, and a password string containing the raw byte `0xff` (in Go: `[]byte("{\"email\":\"...\",\"password\":\"pw\xff\"}")`). Today v1 replaces the byte and the login fails on the password (401). After: exactly 400 with `errors[0].location == "body"`.
- Control: a valid login still returns 200.

**Step 2 — run, expect FAIL** (today: 200 for the duplicate-name body and 401, not 400, for the invalid-UTF-8 body).

**Step 3 — implement** in `newHumaConfig`, after `huma.DefaultConfig(...)`:

```go
// Request bodies decode with encoding/json/v2's defaults, as chi bodies do in
// decodeJSON: duplicate names and invalid UTF-8 are refused and names match
// case-sensitively. Unknown members are left to huma's schema validation, which
// reports them with huma's locations. Responses keep huma's encoder.
requestJSON := huma.Format{
	Marshal:   huma.DefaultJSONFormat.Marshal,
	Unmarshal: func(data []byte, v any) error { return jsonv2.Unmarshal(data, v) },
}
cfg.Formats = map[string]huma.Format{"application/json": requestJSON, "json": requestJSON}
```

`newHumaConfig` also configures the spec-only API; formats do not affect schemas, so `openapi.json` must not change. Verify:
```bash
go test ./internal/api/ -run '^TestOpenAPISpec' -count=1
```

**Step 4 — run auth and MFA tests:**
```bash
go test ./internal/api/ -run 'TestLogin|TestRegister|TestMFA|TestAuth|TestPassword|TestInvitation|TestVerify' -count=1
```
Error texts in huma responses for malformed bodies may change; update only assertions on the error text, never on status codes, and record each in the commit message.

Note for the tests: on an unmarshal error huma puts the whole request body in `errors[0].value` (`huma@v2.37.3/huma.go:2068-2072`), so the 400 for a duplicate-key login echoes the password to the caller who sent it. This already happens for malformed JSON today and is not changed by this task; record it under Discoveries for Sam. In tests, do not log response bodies of login or password requests (`t.Log`, failure messages): assert on decoded `status` and `errors[i].location` instead.

**Step 5 — commit:** `fix(api): decode huma request bodies with encoding/json/v2`

### Task 3.2 — `clearableField` decodes `T` with the caller's options

**Files:** Modify `internal/api/contract.go:184-214`; test in `internal/api/contract_test.go`.

**Step 1 — failing test:** a test-only `struct{ A string \`json:"a"\` }` as `T`, inside a body struct, decoded through `decodeJSON` (use `httptest`): `{"f":{"a":"x","zz":1}}` → 422 at `body.f.zz`; `{"f":{"A":"x"}}` → 422 at `body.f.A` (verify-first: the 422 is the requirement; if the `JSONPointer` v2 reports from inside `UnmarshalJSONFrom` does not give these locations, record the observed location as a deviation instead of changing `bodyLocation`); `{"f":null}` → `Sent` true, `Value` nil; key absent → `Sent` false. Also keep the two real uses green: `go test ./internal/api/ -run 'TestWatchlist|TestSCIMAdmin|TestPatch' -count=1`.

**Step 2 — implement:** replace `UnmarshalJSON([]byte)` with

```go
// UnmarshalJSONFrom records that the key was sent and decodes its value with the
// decoder's options, so a strict request decode stays strict inside the field.
// encoding/json/v2 calls it only for keys present in the input, including null.
func (f *clearableField[T]) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	f.Sent = true
	if dec.PeekKind() == 'n' {
		_, err := dec.ReadToken()
		f.Value = nil
		return err
	}
	var v T
	if err := jsonv2.UnmarshalDecode(dec, &v); err != nil {
		return err
	}
	f.Value = &v
	return nil
}
```

Update the type's doc comment (it says encoding/json decodes both an omitted key and null to nil; keep that explanation of why the type exists). Check that every request struct holding a `clearableField` is decoded through `decodeJSON` (v2); v1 `json.Unmarshal` also calls `UnmarshalJSONFrom` (probed), so a v1 caller keeps working.

**Step 3 — commit:** `fix(api): keep request strictness inside clearable PATCH fields`

---

## Phase 4 — Opaque pagination cursors

**Why.** Cursors are base64 JSON that the server issues and the caller sends back; a caller can edit them. v1 accepts a case-variant name (`{"D":...}` fills `json:"d"`), duplicates and unknown members. Each cursor value is used as a bound SQL parameter, so the risk is a confusing partial cursor, not injection; the change is small and makes all caller-supplied JSON follow one rule.

**Files:**
- Modify: `internal/api/contract.go:247-260` (`decodePageCursor`), `internal/api/cves.go:183-198` (`decodeCursor`), `internal/store/dsl_executor.go:95-110` (`decodeDSLCursor`)
- Test: `internal/api/contract_test.go` (existing cursor tests at `:363-430`), `internal/api/cves_test.go` (`TestCursorRoundTrip`), `internal/api/alert_events_test.go` (`TestAlertEvents_MalformedCursor`, for the handler-level case), `internal/store/dsl_executor_test.go`

**Step 1 — failing tests** for each decoder: an encoded cursor with an extra member → error; with a case-variant name → error; with a duplicate name → error; a cursor produced by the matching encoder round-trips. Through one list handler (e.g. alert events), an edited cursor → 400.

**Step 2 — implement:** `jsonv2.Unmarshal(raw, dst, jsonv2.RejectUnknownMembers(true))` in all three. Keep the encoders on v1 `json.Marshal`: the encoded structs have no maps or nil slices, so the bytes would not change, and leaving them avoids touching 14 call sites.

Before writing, run `grep -rn 'base64\.\(Raw\)\?URLEncoding\.DecodeString' --include=*.go internal | grep -v _test` and confirm no other cursor decoder exists; if one does, include it and record a deviation.

**Existing test this breaks:** `TestExecuteDSLQuery_CraftedCursor` (`internal/store/dsl_executor_test.go:395-425`) builds its cursor with key `"s"`, but `dslCursor` defines `d` and `c` (`dsl_executor.go:82-85`). Under v1 the key is ignored, so the test has been running with a zero date, not the far-future date it intends. Fix the test to use key `"d"` with an RFC 3339 time (so it tests what its comment says), record this under Discoveries, and add a separate case with an unknown member that expects the error. The file is `package store_test`, so `decodeDSLCursor` is reached only through `ExecuteDSLQuery` (Docker); test it that way.

**Step 3 — run:**
```bash
go test ./internal/api/ -run 'Cursor' -count=1
go test ./internal/store/ -run 'DSLCursor|ExecuteDSL' -count=1
```

**Step 4 — commit:** `fix(api): refuse edited pagination cursors`

---

## Phase 5 — Stored alert-rule conditions fail closed

**Precondition:** Phase 0.

**Why.** `loadAndCompileRule` (`internal/alert/evaluator.go:716-733`) decodes stored `conditions` with v1. A stored condition with a key the DSL does not define (for example `"negate": true`, which the author meant to invert the condition) or a case variant (`"Field"`) is read with the key ignored or case-folded, so the rule matches something other than what its author wrote, silently. After Phase 0 the write path refuses such keys, so only rows written before it (dev data) can carry them, but the evaluator is the place where a wrong reading has effect: the existing fail-closed path (`failUncompilableRule`, `evaluator.go:705-711`, sets `status='error'` visibly; PLAN.md §10.5) is the right outcome.

**Behaviour after the phase.** A stored rule whose conditions hold an unknown or case-variant key → compile error → `status='error'`, logged with the rule ID; no alert events. Valid stored rules are unaffected. Saved-search execution already reaches the stored `query_json` through `dsl.Parse` (`internal/api/saved_searches.go:425`) and answers 422 "saved search has invalid query" once Phase 0 lands; no change needed there.

### Task 5.1 — `dsl.ParseConditions`

**Files:** Modify `internal/alert/dsl/parser.go`; test `internal/alert/dsl/dsl_test.go` (or the parser test file Phase 0 created).

**Step 1 — failing unit tests:** `ParseConditions([]byte(...))`:
- `[{"field":"severity","operator":"in","value":["critical"]}]` → one condition.
- `[{"field":"severity","operator":"in","value":["critical"],"negate":true}]` → `*UnknownKeyError{Index: 0, Key: "negate"}`.
- `[{"Field":"severity","operator":"in","value":["critical"]}]` → `*UnknownKeyError{Index: 0, Key: "Field"}`.
- `{}` and `"x"` → error.
- `null` and `[]` → error (v2 decodes `null` into a nil slice without error, and `Compile` builds no predicate from zero conditions; a stored rule passed the non-empty check when it was written, so an empty stored array is refused).
Use whatever error type Phase 0 defined; if it is not `*UnknownKeyError`, use it and record a deviation.

**Step 2 — implement.** Define one options value in `parser.go` used by both `Parse` and `ParseConditions`, so the two cannot drift:

```go
// decodeOptions are the options every DSL decode uses: encoding/json/v2's
// defaults plus refusal of keys the DSL does not define.
var decodeOptions = jsonv2.RejectUnknownMembers(true)

// ParseConditions decodes a stored conditions array with the same rules as
// Parse and refuses an empty or null array, which Parse also refuses. Logic is
// stored in its own column, which a CHECK constraint limits to "and" and "or".
func ParseConditions(data []byte) ([]Condition, error)
```

Map an unknown-name error to the Phase 0 error type, with the condition index taken from the JSON Pointer (`/0/negate` → index 0). Reuse Phase 0's pointer-mapping helper rather than writing a second one; if its shape does not fit (it expects `/conditions/<i>/key`), generalize it with a prefix parameter and keep `Parse`'s behaviour identical (its tests must stay green).

**Step 3 — run:** `go test ./internal/alert/dsl/ -count=1`

**Step 4 — commit:** `feat(dsl): parse stored conditions with the rules Parse uses`

### Task 5.2 — The evaluator uses `ParseConditions`

**Files:** Modify `internal/alert/evaluator.go:716-733`; test: new `internal/alert/stored_conditions_test.go` (Docker; the package's `main_test.go` already has `TestMain` with `testutil.Run`).

**Step 1 — failing integration test.** Create an org and an active rule through the store method that inserts alert rules (find it with `grep -n 'func (s \*Store) CreateAlertRule' internal/store/alert_rule.go`), passing conditions JSON directly (this bypasses API validation on purpose). Seed CVEs with `testutil.SeedCorpus` (no `t.Parallel()`). For each of: an unknown key (`"negate":true`), a case-variant key (`"Field"`): run `Evaluator.EvaluateBatch` (`evaluator.go:137`), constructing the evaluator the way `evaluator_test.go` does, then assert the rule's status is `error` and it has no `alert_events`. Control: the same rule without the extra key produces the alert events it produces today.

**Step 2 — implement:** replace `json.Unmarshal(rule.Conditions, &conditions)` with `dsl.ParseConditions(rule.Conditions)`; keep the wrapping message `parse conditions for rule %s: %w`.

**Step 3 — verify-first: other writers of stored conditions.** Run `go test ./internal/alert/ -count=1`. If an existing test inserts a rule whose conditions the strict decode refuses (for example a hand-written fixture with an extra key), fix the fixture, not the decoder, and record each in a deviation. Then grep non-test code for every `INSERT INTO alert_rules` and every caller of the store's create/update rule methods; each must take conditions that passed `dsl.Parse`. List any that do not under Discoveries.

**Step 4 — pre-deploy check.** Run inside the same `BEGIN; SET LOCAL app.bypass_rls = 'on'; ... COMMIT;` wrapper as Task 1.3, with `SELECT count(*) FROM alert_rules;` first to prove the rows are visible (`alert_rules` has `FORCE ROW LEVEL SECURITY`):

```sql
SELECT r.id, r.org_id, r.status, 'unknown key: ' || k.key AS problem
FROM alert_rules r
CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(r.conditions) = 'array' THEN r.conditions ELSE '[]'::jsonb END) AS c(elem)
CROSS JOIN LATERAL jsonb_object_keys(CASE WHEN jsonb_typeof(c.elem) = 'object' THEN c.elem ELSE '{}'::jsonb END) AS k(key)
WHERE r.deleted_at IS NULL
  AND k.key NOT IN ('field', 'operator', 'value')
UNION ALL
SELECT r.id, r.org_id, r.status, 'conditions is not a non-empty array'
FROM alert_rules r
WHERE r.deleted_at IS NULL
  AND (jsonb_typeof(r.conditions) <> 'array'
    OR jsonb_array_length(CASE WHEN jsonb_typeof(r.conditions) = 'array' THEN r.conditions ELSE '[]'::jsonb END) = 0)
UNION ALL
SELECT r.id, r.org_id, r.status, 'condition is not an object'
FROM alert_rules r
CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(r.conditions) = 'array' THEN r.conditions ELSE '[]'::jsonb END) AS c(elem)
WHERE r.deleted_at IS NULL AND jsonb_typeof(c.elem) <> 'object';
```

Record both counts in the PR body. Such rules go to `error` on their next evaluation; their owners re-save them through the API, which now reports the offending key.

**Step 5 — commit:** `fix(alert): fail closed on stored conditions with keys the DSL does not define`

---

## Phase 6 — API response encoding

**Precondition:** Phase 3 merged (same function, `newHumaConfig`); Sam's decision 3.

**Why.** Response schemas generated by huma declare slices as `type: array` and maps as `type: object`, not nullable, and `web/src/lib/api/schema.d.ts` types them as `T[]` and `Record<...>`. With v1, a nil slice or map in a response is written as `null`, which neither the schema nor the TypeScript types allow. `writeList` guards its `Items` (`contract.go:224-227`); other response fields have no guard. v2 writes `[]` and `{}`.

**What must not change.** Field presence. huma marks both `omitempty` and `omitzero` fields as optional (`huma@v2.37.3/schema.go:882-894`), so swapping one for the other leaves `openapi.json` and `schema.d.ts` unchanged; the CI step "generated API types match openapi.json" proves it.

### Task 6.1 — Measure: every response field whose output would change

**Files:** Create `internal/api/response_encoding_test.go`.

**Step 1 — write the test.** Two registries are needed, and the production one alone is not enough: `mapRegistry.TypeFromRef` reads the registry's own type map (`huma@v2.37.3/registry.go:166`), `mergeSpecPaths` copies only schemas into the production registry (`openapi_spec.go:101-114`), and the spec-only API is a local variable inside `Handler` (`server.go:~258`). So in the test, build the server as `newOpenAPITestHandler` (`openapi_test.go:22-34`) does — `NewServer(nil, cfg, ServerDeps{})` with the same config, then call `srv.Handler()`, which sets `srv.humaAPI` (`server.go:252`) — and read the production registry from `srv.humaAPI.OpenAPI().Components.Schemas`. Separately build `specOnly := newSpecOnlyAPI(); registerAllSpecOps(specOnly)` and use its registry. Collect the response schemas: walk every operation's `Responses` in both specs, take each content schema's `$ref`, and follow `$ref`s inside those schemas (properties, items, additionalProperties, allOf/oneOf/anyOf) to collect every component reachable from a response. Request-only components are excluded: decoding ignores `omitempty`/`omitzero`, and PATCH bodies keep their pointer fields (API-2). Resolve each collected name with `TypeFromRef("#/components/schemas/<name>")` on the production registry, then on the spec-only registry. Fail the test for a name neither resolves, unless it is on an explicit allowlist in the test with a comment saying why (for example a schema huma builds without a Go type). Assert that at least as many types resolved as the first run recorded (write the number into the test as a constant), so a later change that silently resolves nothing fails. Then `grep -n 'writeJSON(' internal/api/*.go` and add to the test any response value type the schemas do not cover (`map[string]any`, anonymous structs, `testChannelResult` and similar), listing each in the test. For each type build two values: one in which every pointer field (to depth 3) points at a zero value and every slice, map, interface and `json.RawMessage` is nil; and one in which, in addition, every interface field holds a zero value of a basic type (`""`), because v1 writes a non-nil interface holding `""` under `omitempty` and v2 omits it (probed; huma's `ErrorDetail.Value` is `any` with `omitempty`). Encode it with v1 `json.Marshal` and with the options Task 6.3 will use (`responseJSONOptions`, defined there; in this task define it locally in the test: `jsonv2.JoinOptions(jsonv2.Deterministic(true), jsontext.AllowInvalidUTF8(true))`). Decode both outputs into `map[string]any` and walk them together. Classify each path that differs:
- *expected*: v1 `null` → v2 `[]` or `{}`.
- *presence*: a key present in one output and absent in the other.
- *error*: v2 marshal failed (for example a `time.Duration` field).
- *other*: any other difference in a value (for example a nil `[]byte` written as `null` by v1 and `""` by v2, a `[N]byte` array written as numbers by v1 and base64 by v2, or a pointer-receiver `MarshalJSON` that v1 skips for a non-addressable value and v2 calls).
The test fails while any *presence*, *error* or *other* entry exists that is not on the test's allowlist, and logs every entry as `Schema.path: v1=<..> v2=<..>`. The allowlist starts with one known entry: `ErrorModel.status` (huma's `Status int` with `omitempty`, `huma@v2.37.3/error.go:81`, cannot be retagged; v2 writes `"status":0` for a zero status, and every writer in this code base sets a non-zero status, which a comment in the allowlist states). Any further allowlist entry needs the same kind of written reason and is recorded under Deviations.

**Step 2 — run, record the list** in this plan under Discoveries (counts per class, and the full list in the commit message):
```bash
go test ./internal/api/ -run TestResponseEncoding -count=1 -v
```

**Step 3 — stop condition.** If the *expected* class is empty (no response can carry a nil slice or map), Phase 6 has no correctness gain: set the banner to ⏸, report to Sam, and do not do Tasks 6.2–6.5. Keep the test only if Sam asks.

**Step 4 — commit** (the failing test is committed together with Task 6.2, not alone, so `dev` never holds a red test).

### Task 6.2 — `omitempty` → `omitzero` where v1 output must be kept

For every *presence* entry: change the field's tag from `omitempty` to `omitzero` when the field's type is a bool, number, pointer, interface, or `json.RawMessage`. For a slice, map or string `omitempty` behaves the same in both versions; such a field cannot be a *presence* entry unless the type has a custom marshaler, which the executor must then examine and record. A struct-typed (non-pointer) field with `omitempty` would also differ (v1 never omits a struct; v2 omits one that encodes as `{}`), and the fix there is not obvious, because removing `omitempty` makes huma list the field as required and changes `openapi.json`. No response type has such a field on 2026-11-14 (only request-side `clearableField`s); if one appears, stop and report it. Do not add `omitzero` to request-only types (PATCH bodies keep pointer fields with `omitempty`, see API-2; decoding ignores both options). Go 1.27's stable v2 has no per-field `format` tag option (its tag options are `omitzero`, `omitempty`, `string`, `case` and `embed`; check with `go doc encoding/json/v2`), so *error* and *other* entries cannot be fixed with a tag. For each one, stop and report it to Sam with the field and both outputs before changing any type; record the decision as a deviation.

Run the Task 6.1 test until it passes, then:
```bash
GENERATE_OPENAPI=1 go test -run '^TestOpenAPISpec$' ./internal/api/ -count=1
git diff --stat openapi.json
```
Expected: no diff. If `openapi.json` changes, stop and find out why before going on.

Commit with Task 6.1: `test(api): pin response encoding to v1 field presence`

### Task 6.3 — `writeJSON` and the problem writers encode with v2, before writing headers

**Files:** Modify `internal/api/contract.go:24-78`, `internal/api/readyz.go:~109`, `internal/api/server.go:~583`; test `internal/api/contract_test.go`.

**Step 1 — failing tests:**
- `writeJSON` of a struct with a nil `[]string` field → body has `[]`.
- `writeJSON` of a value whose marshal fails (a test type with a `MarshalJSON` that returns an error) → status 500 and a problem body, not a 200 with a cut-off body (today the status is written before encoding).
- `writeJSON` of a string holding byte `0xff` → 200 and U+FFFD in the body.
- `writeJSON` of a `map[string]int` with 20 keys → identical bytes across 10 calls.
- Body ends with `\n` (v1 `Encoder.Encode` adds it; keep it).

**Step 2 — implement:**

```go
// responseJSONOptions encode API responses: nil slices and maps as [] and {},
// map keys sorted so equal responses are equal bytes, and invalid UTF-8 replaced
// with U+FFFD rather than failing the response.
var responseJSONOptions = jsonv2.JoinOptions(jsonv2.Deterministic(true), jsontext.AllowInvalidUTF8(true))
```

A shared `writeEncoded(w, status, contentType string, v any)` marshals first with `jsonv2.Marshal(v, responseJSONOptions)`; on error it logs and writes a plain 500 problem built without `v`; otherwise it sets the content type, writes the status, the bytes and `\n`. `writeJSON`, `writeProblem`, `writeProblemWithErrors`, `writeProblemTyped`, readyz and the liveness handler use it. HTML characters are no longer escaped; huma's encoder does not escape them either (`SetEscapeHTML(false)`), so both paths now agree. Grep tests for `\\u003c`, `\\u003e`, `\\u0026` and update any assertion that depended on escaping. SCIM responses (`scim_types.go:104`) stay on v1: SCIM has its own schema and clients, outside this phase.

**Step 3 — run:** `go test ./internal/api/ -count=1` (whole package: every handler's output passes through these writers).

**Step 4 — commit:** `fix(api): encode responses with encoding/json/v2 and refuse partial bodies`

### Task 6.4 — huma responses use the same options

**Files:** Modify `internal/api/openapi_spec.go` (`newHumaConfig`, the `Marshal` of the format Task 3.1 added).

`Marshal: func(w io.Writer, v any) error { return jsonv2.MarshalWrite(w, v, responseJSONOptions) }` followed by writing `\n` to match huma's v1 encoder. huma's own response types (`huma.ErrorModel`, `huma.ErrorDetail`) cannot be retagged; add their names to the Task 6.1 test's input (if they are not in the component map already) and confirm they have no *presence* entries other than the allowlisted `ErrorModel.status`. If the interface variant shows `ErrorDetail.value` as a *presence* entry (v1 writes `"value":""`, v2 omits it), allowlist it with that reason: an empty echoed value carries no information for a client. Test: `go test ./internal/api/ -run 'TestLogin|TestCVE|TestMFA|TestResponseEncoding|TestOpenAPI' -count=1`.

Commit: `fix(api): encode huma responses with the API's response options`

### Task 6.5 — SPA and generated types

1. `cd web && npm run generate-api && git diff --exit-code src/lib/api/schema.d.ts` → no diff expected.
2. Search the SPA for code that tells `null` from an empty array or object on a response field: `grep -rnE '(===|!==|==|!=) ?null' web/src --include=*.ts --include=*.vue` and review each hit whose operand is a response array or object. With v2 such a field is `[]`/`{}` where it was `null`. Change each to test emptiness; record each file in the commit message.
3. `cd web && npm run type-check && npm run lint && npm run test:unit`.
4. Commit: `fix(web): treat empty response collections as empty, not null` (only if step 2 changed something).

---

## Phase 7 — Replace the JCS dependency with `jsontext.Value.Canonicalize`

**Precondition:** Sam's decision 2.

**Why.** `material_hash` and the match-inputs hash run `jsoncanonical.Transform` (RFC 8785) on v1 `json.Marshal` output (`internal/merge/hash.go:87-97`, `internal/merge/match_inputs.go:64-74`). Go 1.27's `jsontext.Value.Canonicalize` implements the same RFC. Removing the dependency is a supply-chain reduction; the v1 `json.Marshal` calls stay (Category "hash and dedup inputs").

**Files:** Modify `internal/merge/hash.go`, `internal/merge/match_inputs.go`, `go.mod`, `go.sum`; test `internal/merge/material_hash_golden_test.go` (existing), new `internal/merge/canonical_test.go`.

**Step 1 — one helper, no behaviour change.** Add `canonicalJSON(raw []byte) ([]byte, error)` in `internal/merge` that calls `jsoncanonical.Transform`, and make `hash.go` and `match_inputs.go` call it (keep their panics). Run `go test ./internal/merge/ -count=1`; the golden pins pass.

**Step 2 — differential test while both implementations exist** (`canonical_test.go`, package `merge`): a table of Go values, each marshaled with v1 `json.Marshal` exactly as production does before canonicalizing (so the input bytes have v1's escaping of `<`, `>`, `&`, U+2028 and U+2029), asserting `jsoncanonical.Transform(b)` equals the `jsontext.Value(b).Canonicalize()` result byte for byte. Values: the floats CVSS and EPSS use (`9.8`, `10.0`, `0.1`, `7.25`, `0.00043`, `1e-7`), an `int64` above 2^53 (`9007199254740993`), strings with `é`, `日本`, `<>&`, U+2028, U+FFFD, `\x01` and a tab, a struct whose fields are not in sorted order, a `map[string]any` with unsorted keys, an empty slice and an empty map. The real-data check is the golden corpus: `internal/merge/material_hash_golden_test.go` pins `material_hash` for 71 CVEs, and `match_inputs_test.go` / `match_inputs_integration_test.go` cover the match-inputs hash. (A per-patch differential inside package `merge` is not possible without an import cycle: `testutil` imports `merge`.) Run `go test ./internal/merge/ -run TestCanonical -count=1`. If any case differs, stop and report to Sam: the swap would move hashes.

**Step 3 — swap** `canonicalJSON`'s body to `v := jsontext.Value(slices.Clone(raw)); err := v.Canonicalize(); return v, err`, remove the import, `go mod tidy`, and turn the differential table into a table of expected canonical outputs (literal strings) for `canonicalJSON`.

**Step 4 — run:** `go test ./internal/merge/ -count=1` — the golden hash pins must pass unchanged. Then `grep -rn cyberphone --include=*.go .` → no hits. Update `dev/research.md:~389` ("JSON Canonicalization: cyberphone/json-canonicalization") to name `jsontext.Value.Canonicalize` and say why (standard library, same RFC 8785, one fewer dependency); `grep -rn -i 'cyberphone\|json-canonicalization' --include=*.md .` and update any other live reference outside `dev/implementation-log/` and `dev/plans/` (those are history).

**Step 5 — commit:** `refactor(merge): canonicalize hash input with the standard library` (Step 1 may be its own commit: `refactor(merge): one helper canonicalizes hash input`)

---

## Phase 8 — Pitfall entries, PLAN.md, final full suite

**Files:** `dev/implementation-pitfalls.md`, `PLAN.md`, `dev/implementation-log/`.

1. Add pitfall entries in the file's existing format (read two neighbouring entries first):
   - Validate and use with one decoder: a JSON value validated at the API and consumed by a worker must be decoded by one shared function; v1 case-insensitive struct decoding against case-sensitive map lookups produced a channel config that was shown, audited and delivered differently (Phase 1).
   - v2 map output is unordered: never hash or byte-compare `jsonv2.Marshal` output without `jsonv2.Deterministic(true)`; hash inputs stay on v1 `json.Marshal`.
   - v2 strictness does not reach `UnmarshalJSON([]byte)` methods; implement `UnmarshalJSONFrom` and call `jsonv2.UnmarshalDecode` (Phase 3).
   - Feeds stay on v1 (Category 4 reasoning, one paragraph, pointing at this plan).
2. PLAN.md: §11 (notification channels) states the config keys per type and, with decision 1, that other keys are refused; §16 (API contract) states that request JSON is decoded case-sensitively with duplicate names, trailing data and invalid UTF-8 refused, and (with Phase 6) that empty collections are `[]`/`{}`, never `null`. Read each section before editing and change only those statements.
3. Run the full suite on `dev` after the last phase merges, record `Full suite: passed at <sha>` in the table, and set **Overall**.
4. Commit: `docs: record encoding/json/v2 decisions and pitfalls`

---

## Order and parallelism

```
Phase 0 (other branch) ──────────────► Phase 5
Phase 1 (needs decision 1) ─┐
Phase 2 ────────────────────┼─ independent of each other and of 0
Phase 3 ────────────────────┴─► Phase 4 ─► Phase 6 (needs decision 3)
Phase 7 (needs decision 2), independent
Phase 8 last
Suggested order while decisions are open: 2, 3, 4, then 5 when Phase 0 lands, then 1, 6, 7 as decisions arrive.
```

Four phases edit `internal/api/contract.go` (Task 1.2 `bodyLocation`; Task 3.2 `clearableField`; Phase 4 `decodePageCursor`; Task 6.3 writers), and Phases 3 and 6 both edit `newHumaConfig`. Never run two of these phases at the same time; each starts from a `dev` that holds the previous one. Run integration tests from one session at a time: Docker on this host is shared, and parallel testcontainers runs have overloaded it before.

## Execution strategy

Recommended: **subagent-driven development in one session** (`/superpowers:subagent-driven-development`), one phase at a time, with a review between phases. The phases are small and mostly sequential because of the shared files, each needs Docker-backed tests that should not run in parallel, and Phases 1, 5 and 6 change behaviour that benefits from a review before the next phase builds on it. Parallel agents would save little and contend for Docker.

## Not doing (with reasons)

- No global switch (`GOEXPERIMENT`, a project-wide wrapper package): v2 is adopted where it gains something, and v1 stays supported.
- No migration of feed adapters, sqlc output, hash inputs, stored formats this app writes, outbound webhook and syslog payloads, third-party API responses, dev tools, or tests in bulk (reasons in the Inventory).
- No lint rule banning v1 imports: most remaining v1 uses are correct by this plan, so such a rule would be all exceptions.
- No change to SCIM response encoding or to SCIM `scimType` values.
