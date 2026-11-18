**R1 · seams & contracts; failure modes**

**Doc anchor:** §10, What waits for the parallel session — “An ascending order selected by `after`”.

**Claim:** The FEED-1 dependency contract does not guarantee that advancing a polling cursor cannot skip a concurrently committed event.

**Evidence:** Source probes found `first_fired_at DEFAULT now()` in `migrations/000016_create_alert_runs_events.up.sql`, an insert that leaves that default intact in `internal/store/queries/alert_rules.sql`, and timestamp-based pagination in `internal/store/alert_rule.go`. An older transaction can therefore publish an event behind a cursor already returned for a newer committed event. Ascending order and a UUID tiebreaker alone do not prevent this. Neither FEED-1’s stated obligations nor the client specify overlap, deduplication, or a watermark safe against delayed commits. This is the same failure described in implementation pitfall NOTIFY-20.

The required runner probe is: leave event A uncommitted; commit later event B; poll FEED-1 and save B’s cursor; commit A; poll with that cursor. A must remain retrievable. FEED-1 is unavailable here, and `docker ps` failed with access denied, so this interleaving was not executed.

**Axes:** Objective contract omission; remedy requires a choice.

---

**R2 · seams & contracts; failure modes**

**Doc anchor:** §7.4, Results — “`matched_ranges` is left out; `get_advisory` has the ranges.”

**Claim:** The fallback cannot recover all range semantics discarded from check results.

**Evidence:** Source inspection found `last_affected` in `CheckMatchedRange` (`internal/api/check.go`) and its propagation by the evaluator (`internal/check/verdict.go`). However, `AffectedPackageResponse` in `internal/api/cves.go` has no `last_affected`. The proposed MCP package-range shape also drops `range_type`, although `internal/check/packages.go` uses it to distinguish Git ranges and choose comparison rules.

Consequently, a package range ending inclusively at version 2.0 and an otherwise identical unbounded range become indistinguishable through the proposed fallback. Git commit bounds also lose their discriminator. The design assigns nobody responsibility for closing this API gap, despite promising that an agent can retrieve the ranges needed to answer version questions.

**Axes:** Objective; remedy requires a choice between preserving check evidence, extending the detail API, or narrowing the promised behavior.

---

**R3 · seams & contracts; failure modes**

**Doc anchor:** §5.2, Commands — “prints one envelope `{"items": [...]}` holding every item.”

**Claim:** `events list --after … --all` discards the checkpoint required to resume polling.

**Evidence:** Section 10 explicitly requires a cursor on the last nonempty page so a poller can save it. The generic `--all` contract returns only accumulated items, and §5.3 promises preservation of `{items, next_cursor}` only *without* `--all`. After draining pages and receiving an empty page, the caller therefore receives neither the last nonempty cursor nor a specified replacement checkpoint.

The API supplies the required state, but aggregation removes it before it reaches the script. Section 11’s timer-based polling workflow consequently has no stated checkpoint contract for this supported command combination.

**Axes:** Objective contradiction; remedy is determinate: preserve and expose the final resumable checkpoint.

---

**R4 · seams & contracts; failure modes**

**Doc anchor:** §6.2, Batches — “A half that times out again is not split further.”

**Claim:** A terminal timeout of a multi-item half has no defined result or error owner.

**Evidence:** Step 4 stops splitting that half, while step 5 assigns `unanswered` entries and exit 9 only to an item that times out *alone*. For example, a 500-item batch times out, its first 250-item half succeeds, and its second half times out. The second half cannot be split again and does not meet step 5’s singleton condition.

The design does not say whether to emit 250 unanswered indexes and preserve the successful half, abort with exit 7, or return an MCP tool error that discards the partial result. Sections 5.4 and 6.3 require partial-result handling but do not resolve this branch.

**Axes:** Objective missing branch; remedy requires a choice.

---

**R5 · seams & contracts; failure modes**

**Doc anchor:** §7.5, Limits inside a tool call — “a call waiting for its turn does not spend its retry budget while it waits.”

**Claim:** Serialization has no stated admission, queue-bound, or cancellation contract.

**Evidence:** The design accepts concurrent MCP calls, serializes their HTTP requests, and exempts queue waiting from its only tool-level budget. It specifies neither a maximum pending-call count nor who removes canceled callers, prevents a queued write from starting after cancellation, or bounds queue residence time. The 60-second HTTP timeout applies only after a request starts.

This leaves resource retention and canceled work unassigned between the SDK, MCP handlers, and shared API client. Naming SDK cancellation support in §4.1 does not specify propagation through this application-owned queue.

**Axes:** Objective contract omission; remedy requires a choice.

---

**R6 · seams & contracts; failure modes**

**Doc anchor:** §7.3, Descriptions — “`invalid`: the item could not be read; read `error`.”

**Claim:** The MCP result projection removes the error that agents are instructed to inspect.

**Evidence:** Section 7.4 lists the retained per-item fields for `check_components`; `error` is absent. Source inspection confirms that `CheckItemResult.Error` contains a `CheckItemError` with a stable code and explanatory message (`internal/api/check.go`). These describe failures such as conflicting versions, unsupported repositories, and invalid package URLs.

Thus an HTTP-successful check can yield `status: invalid` while the MCP caller receives no explanation or repair guidance. The tool-error rule does not cover this case because the API call itself succeeded.

**Axes:** Objective contradiction; remedy is determinate: retain the per-item error.

---

**R7 · seams & contracts**

**Doc anchor:** §5.2, Commands — “`watchlists list`” and “Added so a script can find a watchlist ID.”

**Claim:** The CLI contract provides no stated way to enumerate watchlists beyond the first page.

**Evidence:** Source inspection of `listWatchlistsHandler` in `internal/api/watchlists.go` found a 20-item page size and a `cursor` parameter. `internal/tier/limits.go` permits unlimited enterprise watchlists. Yet the command table exposes neither `--cursor` nor `--all` for `watchlists list`, although it explicitly lists pagination flags for other commands.

A response may therefore advertise a continuation that the documented CLI cannot submit. If `--all` is intended to apply globally, that applicability needs to be stated; otherwise the command cannot fulfill its ID-discovery purpose for larger organizations.

**Axes:** Objective contract omission; remedy requires a choice.

Seams & contracts: findings R1, R2, R3, R4, R5, R6, R7.

Failure modes: findings R1, R2, R3, R4, R5, R6.