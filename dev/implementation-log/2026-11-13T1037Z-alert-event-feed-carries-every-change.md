# Alert-event feed carries every change to an event

## What was done

The ascending alert-event feed (`GET /orgs/{org_id}/alert-events?order=asc`) now gives an event a new position whenever it changes, not only when it fires. A poller sees an alert close, so a client can close the ticket it opened.

- **Resolve.** `ResolveAlertEvent` takes the org's feed lock first, then sets `feed_seq = nextval('alert_event_feed_seq')` on each event it closes. A resolve that changes nothing draws nothing.
- **Late-binding move.** `moveAlertEvents` (merge pipeline) gives each event it moves to the new CVE ID, and each colliding event it closes, a new position. It runs inside the merge transaction across orgs, so it first takes the feed lock of every org with an event under the old ID, in lock-key order, and updates only those orgs' events. It loops in case an event of an unlocked org appeared in between. The close now touches only events that were open.
- **Filters.** `last_match_state` and `since` are accepted with `order=asc` again. Every change to a filterable field (`last_match_state`, `last_fired_at`, `cve_id`) moves the event, so a filter is evaluated against the event's state at its latest position and cannot pass it for good. The caveat about renamed CVE IDs is gone from the API description.
- PLAN.md records a requirement for any multi-tenant hosted deployment: the cursor holds a value of one sequence shared by all orgs, so its advance reveals event volume across orgs. It must be encrypted, or replaced by per-org positions under cursor version 2, first.

## Decisions and gotchas

- **The feed is a change feed.** Each entry shows the event's state when read: `last_match_state` says open or closed, and `times_fired` counts fires. Changes not yet read collapse into one entry. This was chosen over a fires-only feed so a client acting on alerts can also act on resolutions.
- **Lock order in the merge.** The merge transaction already holds the CVE advisory locks (single-bigint key space), then takes org feed locks (two-int4 key space) in key order. No other holder of an org lock takes a CVE lock or a second org's lock, so no cycle forms. An org's event writes wait while a merge holding its lock runs. Late-binding moves are rare, so that wait is too.
- **The cursor leak is not fixed now.** No hosted deployment exists, and the cursor's version field makes a later change explicit to clients, so the work is recorded where a SaaS launch will read it.

## Quality checks

- `internal/store/alert_event_feed_test.go`:
  - `TestAlertEventFeed_WritersTakeFeedLock` now covers resolve as well as insert and reopen
  - the concurrent-writers test races insert, reopen and resolve of one event for 200 rounds with no deadlock
  - `TestListAlertEvents_AscendingChangesReenterFeed`: a poller sees the event open, then closed, then reopened with `times_fired` 2, and a resolve that changes nothing does not move it
- `internal/alert/late_binding_test.go`: a moved event and a closed colliding event take new positions, and the untouched target keeps its own.
- `internal/api/alert_events_feed_test.go`: `last_match_state` and `since` are accepted with `order=asc`.
- Each new expectation failed before the change (resolve not in the feed, no lock waiter for resolve, positions unchanged by the move, the filters answering 400).
