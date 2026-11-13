# Alert-event feed with lock-ordered positions

## What was done

`GET /orgs/{org_id}/alert-events?order=asc&after=<cursor>&limit=<n>` is a polling feed. A consumer that stores `next_cursor` and polls on a schedule sees each fire of an event exactly once, across restarts, with no overlap window (requirement FEED-1 of the private homelab integration requirements).

- Migration 000062:
  - adds `alert_events.feed_seq bigint NOT NULL`, with no default, drawn from `alert_event_feed_seq` (CACHE 1, owned by the column, USAGE granted to `cvert_ops_app`)
  - adds a unique index on `(org_id, feed_seq)`, built concurrently
  - backfills existing events to `-N..-1` in first-fire order, so history reads ahead of new positions, which start at 1
- `LockAlertEventFeed` (`pg_advisory_xact_lock(1178944836, hashtext(org_id::text))`) is the first statement in `InsertAlertEvent` and `ReopenAlertEvent`. Each then draws `nextval` explicitly.
- A reopen moves the event to a new position, so the feed carries every fire, as channels do. A resolve does not move it.
- The ascending list orders by `feed_seq` and resumes after the cursor. The cursor is versioned base64 JSON, `{"v":1,"s":<feed_seq>}`. `next_cursor` is the last event's position, or the `after` that was passed when the page is empty.
- `limit` (1 to 1000, default 100) applies to both orders. With `expand=rule` it is at most 100.
- With `order=asc`, `last_match_state` and `since` answer 400, as does mixing `after` with the descending order or `cursor` with the ascending one.
- Pitfall API-12 records the flaw (sequence and timestamp cursors skip rows that commit out of order), the lock rules, and the rejected design.

## Decisions and gotchas

- **Why a lock and not a bare sequence.** A sequence value is taken at insert and the row appears at commit, so a poller can pass a smaller value that is still uncommitted. Postgres makes a commit visible before it releases the transaction's locks. So with the position drawn inside the org lock, the next writer draws a larger value only once the previous row is visible or rolled back.
- **Why not the inserting transaction's ID.** The first version of this change ordered by `pg_current_xact_id()` and fenced reads at `pg_snapshot_xmin(pg_current_snapshot())`. An independent review found that `pg_dump` and restore into a fresh cluster, the recovery runbook's path, restarts the transaction counter below every stored cursor, so new events would never be returned. It also stalled every org's feed while any write transaction on the server was open. The sequence's state is dumped with the data, and the lock only couples writers in one org for the length of their own short transaction.
- **Lock before row.** `ReopenAlertEvent` takes the org lock before its `UPDATE` locks the row. An `ON CONFLICT DO NOTHING` insert of the same event holds the org lock and can wait on that row, so the reverse order could deadlock. Resolve takes no org lock and so cannot close a cycle.
- **No default on `feed_seq`.** An insert that does not draw a position fails with a NOT NULL violation instead of taking an unordered value. The raw inserts in existing test fixtures now draw `nextval` themselves. They are not concurrent, so ordering does not matter there.
- **Rejected filters.** A resolve changes `last_match_state` without moving the event, so a filter on it, or on `last_fired_at`, could pass an event before it matches. A `cve_id` filter can miss an event renamed to that ID by late alias binding after the poller passed it; the API description says so.
- **`expand=rule` cap.** For each event, the watchlist-match lateral reads every live item of the rule's watchlists and probes the CVE's ranges for each. That cost was not measured at 1000 events, so those pages stay at the previous maximum of 100.
- **Hot-path cost.** Every evaluation that hits an existing event now takes the org lock and draws a sequence value before the conflict check. Gaps in the sequence are harmless.
- **Development databases.** Running the down migration and then the up migration restarts positions at 1, below any cursor held from before.

## Quality checks

- `internal/store/alert_event_feed_test.go`, through `AppStore` where reading:
  - `InsertAlertEvent` and `ReopenAlertEvent` each wait on the org lock held by another transaction, detected in `pg_locks` (break test: with the lock statement removed from both methods, this test and the acceptance test below failed, since no session waited for the lock)
  - insert, resolve and reopen through the application role (the sequence grant)
  - 200 rounds of a concurrent insert and reopen of one event with no deadlock
  - the acceptance case: a later writer blocks behind an open earlier one, the poll during that wait returns nothing, then both events arrive once and in order
  - paging by 2 across another org's events and a three-event transaction
  - an empty feed's first poll
  - a reopen re-entering once while a resolve does not
  - resuming from a negative history position and after the cursor's event was deleted
- `internal/api/alert_events_feed_test.go` (viewer API key): polling from `next_cursor`, the caught-up page returning the same cursor, descending `limit`, `rule_id` with `expand=cve,rule`, and every 400 (rejected filters, unknown cursor version, `expand=rule` over 100).
- `migrations/alert_events_feed_seq_test.go` runs the down file, seeds events out of fire order, then runs the up file through golang-migrate's splitter. It checks history at -3, -2, -1, a new event at 1 or more, an insert without a position refused, the unique index valid, and the sequence owned by the column.
- Targeted runs pass: `./migrations/`, `./internal/retention/`, and the store, API, notify and alert evaluator tests that insert, reopen or list events. golangci-lint v2.15.0 on the touched packages: 0 issues.
- Lock order across the code: realtime evaluation runs after the merge transaction commits (`internal/ingest/handler.go`), and `InsertAlertEvent` and `ReopenAlertEvent` are each their own transaction (lock, one statement, commit). No path holds the org lock while taking a CVE lock or another org's lock. An insert holding the org lock can wait only on a row changed by `moveAlertEvents` or retention, neither of which takes the org lock, so the wait ends when they commit.
