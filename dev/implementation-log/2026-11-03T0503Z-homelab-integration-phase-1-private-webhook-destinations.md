# Homelab Integration Phase 1 — Private Webhook Destinations

> **Date:** 2026-11-02
> **Commit:** `d8c388f` on `claude/safe-to-deploy-fixes`
> **Source:** homelab integration requirements review, requirement for delivery to a self-hosted ntfy receiver on the LAN

## What was built

| Part | Files | Description |
|---|---|---|
| Settings | `internal/config/config.go`, `.env.example` | `WEBHOOK_PRIVATE_HOSTS` (exact host names or IPv4 addresses), `WEBHOOK_PRIVATE_CIDRS` (required with hosts), `WEBHOOK_PRIVATE_PORTS` (optional, added to 80 and 443) |
| Parsing | `internal/notify/client.go` | `ParsePrivateDestinations` canonicalizes hosts and rejects IPv6 entries, hosts with scheme or port, networks or ports without hosts, and hosts without networks |
| Delivery client | `internal/notify/client.go`, `cmd/cvert-ops/main.go` | `BuildSafeClient(PrivateDestinations)` routes by `r.URL.Hostname()`: listed hosts go through a second safeurl client whose IP allowlist is the listed networks; every other host uses the default client. Serve and worker both build it from config |
| Registration and channel test | `internal/api/channels.go`, `internal/api/server.go` | `validateWebhookURL` accepts listed hosts after the scheme and empty-host checks. `NewServer` parses the settings and fails on invalid values. The test endpoint uses the same destinations as delivery |
| Runbook | `docs/deployment/runbooks/delivery-failure.md` | The SSRF row shows safeurl's real error text and points to the new settings |

## Key implementation decisions

- **Host names plus networks, not networks alone**: a listed name that later resolves outside the listed networks is refused at dial time, so a DNS change cannot turn an allowed host into a path to other internal addresses.
- **Routing by URL host is safe because redirects are disabled**: the host a request is routed by cannot change mid-request.
- **IPv6 entries are refused at startup**: safeurl's IPv6 block runs before its IP allowlist, so a listed IPv6 host or network could never be delivered to.
- **The allowance applies to the whole instance**: any org can target a listed host. Acceptable for single-org self-hosting, and documented on the setting.

## Gotchas discovered

- **safeurl v0.2.2 reports the IPv6 block first**: `localhost` resolves to `::1` first on Windows, and Go reports the first dial error. Refusal tests that dialed `localhost` passed because IPv6 was blocked, not because of the check under test. The tests use `127.0.0.1` and assert the exact refusal text (`ip: … not found in allowlist`, `port: … not found in allowlist`).
- **`SetAllowedPorts` replaces safeurl's default ports** rather than adding to them, so 80 and 443 are restated.
- **safeurl's scheme, host and credential checks run only in `WrappedClient.Do`**, which CVErt does not call. The bare `http.Client` applies only the dial-time IP and port checks, so scheme validation stays in `validateWebhookURL`.
- **Resolved addresses reached org users**: `POST /channels/{id}/test` returned safeurl's error text, which includes the resolved IP of any host an org admin registers, so the endpoint could map internal DNS. The delivery worker stored the same text in `notification_deliveries.last_error`, which `GET /orgs/{org_id}/deliveries` returned to org viewers. `notify.ErrorForOrg` now passes through only a receiver's answer (`*notify.StatusError`) and channel-config errors (`permanentDeliveryError`), and replaces everything else with `notify.ErrCauseWithheld`. The worker writes both texts through `store.DeliveryFailure` into `last_error` and `last_error_for_org` (migration 000047). The org list and get queries select only `last_error_for_org`, so the generated rows have no field holding the full text. `/admin/deliveries` keeps the full text. A CHECK constraint keeps the two columns set and cleared together, so a write path that sets only one fails in tests. The channel test endpoint uses the same `ErrorForOrg` and logs the full error.

## Quality checks

- **golangci-lint:** 0 issues on changed packages
- **Security review:** run on the change. Its one failure (IPv6 entries accepted but never deliverable) is fixed. Two warnings remain: the instance-wide allowance, and the channel test endpoint revealing resolved IPs.
- **Tests:** `internal/notify` (31.6s), `internal/config`, `cmd/cvert-ops` (14.9s), and `internal/api -run 'Channel|ValidateWebhook|NewServer|Server'` (27.8s) pass with `TESTCONTAINERS_RYUK_DISABLED=true`. Full suite not run.
- **New tests:** `TestParsePrivateDestinations_*` (3, including 11 invalid cases), `TestBuildSafeClient_*` (4), `TestValidateWebhookURL_PrivateDestinations`, `TestNewServer_InvalidPrivateDestinations`, `TestChannelTest_Webhook_RefusedDestinationHidesAddress`, `TestChannelTest_Webhook_ReportsReceiverStatus`, `TestErrorForOrg`, `TestWorker_RefusedDestinationWithheldFromOrg`, `TestExhaustDelivery_OrgQueriesReturnOrgError`, `TestExhaustDelivery_RejectsDetailWithoutOrgError`, `TestDeliveries_ReturnOrgErrorOnly`; org-error assertions added to `TestWorker_RetryOnNon2xx` and `TestWorker_ExhaustsUnknownChannelType`
