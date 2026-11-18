**R1 · seams & contracts; failure modes**

**Doc anchor:** §12, “Watchlists fed by a scanner”: “Recommendation: refuse on a mixed watchlist”.

**Claim:** The proposed safeguard has no atomic contract with the replacement endpoint. A client-side inspection cannot guarantee that `--cves` preserves package and CPE items added concurrently.

**Evidence:** I ran `rg -n 'ReplaceWatchlistItems|If-Match|ETag' internal/api/watchlists.go internal/store/watchlist.go` and read both implementations. `replaceWatchlistItemsHandler` passes only the desired items to `ReplaceWatchlistItems`. That method locks the watchlist, reads its current items, and removes every identity absent from the request (`internal/store/watchlist.go:288–317`). Neither side accepts an expected revision or a condition requiring the current list to contain only CVEs.

Consequently: the CLI inspects a CVE-only list; another writer adds a package; the CLI sends its CVE-only PUT; the transaction deletes the package and reports success. The same problem exists if a connection failure causes the PUT to be retried after the other writer’s addition. The transaction serializes writes but does not enforce the CLI’s prerequisite. Section 13 assigns no server change to establish that prerequisite.

**Axes:** Objective. Remedy is a choice: enforce the CVE-only condition inside the replacement transaction, or define and enforce a revision precondition across inspection, replacement, and retries.

---

**R2 · seams & contracts; failure modes**

**Doc anchor:** §7.7, “Results”: “`matched_ranges` holds up to 5 of the advisory’s matching ranges”.

**Claim:** MCP result shaping silently removes range evidence without preserving the API’s indication that additional ranges exist.

**Evidence:** I ran `rg -n 'MatchedRanges|MatchedRangesTotal' internal/api/check.go internal/check/evaluate.go`. The REST response explicitly supplies `matched_ranges_total`; `internal/check/evaluate.go:498–500` calculates that total before applying its own listing cap. The proposed MCP advisory fields omit this total and specify only `advisories_truncated`, which accounts for omitted advisories rather than omitted ranges within an advisory.

Thus an advisory with five matching ranges and one with six matching ranges can produce indistinguishable MCP range lists. This matters because §7.6 explicitly says the detail endpoint omits `last_affected`; a subsequent `get_advisory` call cannot recover that missing evidence. An agent cannot determine whether it has all the bounds relevant to a remediation decision.

**Axes:** Objective. Remedy is determinate: preserve the upstream total and expose how many matching ranges the MCP response omitted.

---

**R3 · seams & contracts; failure modes**

**Doc anchors:** §7.4, “Tools”: “the key’s org role is at least member, which `whoami` reports”; §7.9, “stdio”: “the first tool call retries `whoami`”.

**Claim:** Role discovery and tool registration lack a failure and recovery contract. The design requires an identity-dependent tool list before the operation designated to recover identity.

**Evidence:** The MCP package is constructed with the enabled write-tool set (§7.1), while eligibility depends on the effective role returned by `whoami` (§7.4). However:

- Over stdio, startup may continue without any successful `whoami`. The agent host can request `tools/list` before making its first tool call. The design does not define which write tools are registered then, or how registration changes after identity recovery.
- Over HTTP, §7.2 says `tools/list` costs no API request, but the role needed to construct that request’s server comes from `whoami`. No alternative source of the effective role is specified, and no behavior is assigned for a `whoami` 429 or failure during discovery.

I inspected `internal/api/whoami.go`: `api_key.role` is the key’s ceiling, while `org.role` includes the creator’s current membership restriction; the handler can return 403 and also charges the org bucket. These are materially different outcomes from merely having an authenticated key.

I also inspected SDK v1.8.0’s `mcp/server.go`: adding and removing registered tools are explicit operations that issue tool-list change notifications. The design assigns neither those operations nor the recovery state transition to a component.

**Axes:** Objective contract gap. Remedy is a choice: define identity acquisition during discovery and its errors, or define a conservative initial registry plus explicit recovery and list-update behavior.

---

**R4 · seams & contracts; failure modes**

**Doc anchor:** §5.5, “Retries”: “503 from `/check` without `Retry-After`, with a `application/problem+json` body”.

**Claim:** The client cannot identify a check timeout using this predicate. An unrelated intermediary failure with a Problem Details body will be misclassified as a timeout.

**Evidence:** I inspected `writeCheckFailure` in `internal/api/check.go:246–256` and `writeProblem` in `internal/api/contract.go:28–40`. The timeout uses the generic problem writer, which supplies HTTP status, status-text title, and detail, with no distinguishing problem type. By contrast, candidate-limit failures have a dedicated type.

A proxy response such as HTTP 503, no `Retry-After`, and:

```json
{"title":"Service Unavailable","status":503,"detail":"upstream unavailable"}
```

satisfies the design’s timeout predicate. The CLI consequently splits the batch instead of reporting the unrelated failure; MCP instead tells the agent to retry with fewer items. Neither response addresses the actual failure.

The wrapper does not yet exist, so the implementation probe is: return that response from a scripted `/check` handler for a two-item request; assert that the client makes one request and reports an ordinary server error. Section 9.1 currently tests only a proxy-style 503 **without** a problem body.

**Axes:** Objective. Remedy is a choice: establish a dedicated timeout problem type and match it, or stop treating an indistinguishable generic 503 as permission to split.

---

**R5 · seams & contracts**

**Doc anchor:** §7.7, “Results”: “Per tool:”.

**Claim:** Seven tools cross the MCP output boundary without a defined result contract.

**Evidence:** Section 7.4 defines twelve tools, but §7.7 specifies output fields for only five. It gives no per-tool result contract for `whoami`, `list_rules`, `validate_rule`, `list_watchlists`, `list_watchlist_items`, `add_watchlist_item`, or `remove_watchlist_item`. The general rules about IDs, nulls, booleans, and compact JSON do not establish whether these tools preserve REST responses or select fields, nor which pagination and mutation-result fields reach the agent.

This omission includes meaningful domain failures. I inspected `validateAlertRuleHandler` in `internal/api/alert_rules.go:629–657`: an invalid rule returns HTTP 200 with `valid: false`, indexed errors, and warnings. Section 7.7’s failed-HTTP-call rule does not cover this outcome. The MCP contract must state how those diagnostics are represented so an agent can correct the rule. Mutation outputs likewise need to define the returned item identity and the representation of the proposed `already_present` success.

**Axes:** Objective contract gap. Remedy is a choice: specify each result schema, or explicitly adopt the REST result contract for each omitted tool and identify any transformations.

Seams & contracts — findings listed: R1, R2, R3, R4, R5.

Failure modes — findings listed: R1, R2, R3, R4.