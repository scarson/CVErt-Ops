# Grant the app role the table privileges the application uses

## What was built

Migration `000055_grant_app_role_gaps` adds the privileges `cvert_ops_app` needs and no earlier migration granted:

| Table | Added | Used by | Failure without it |
|---|---|---|---|
| `security_events` | `SELECT, INSERT, DELETE` | `secure.EventWriter`, `store.ListSecurityEvents`, `store.CleanupSecurityEvents` | Every security event is dropped with a logged error, the admin list fails, retention fails |
| `ai_usage_counters` | `DELETE` | `store.CleanupAIUsageCounters` | Retention fails for the table |
| `cve_search_index` | `DELETE` | `merge.migrateCVEPK`, both paths | `merge.Ingest` fails each time an advisory gains a CVE alias |
| `cves` | `DELETE` | `migrateCVEPKMerge` | `merge.Ingest` fails when the alias target already exists |
| `schema_migrations` | `SELECT` | `/readyz`, `doctor`, the startup schema check | `/readyz` returns 503 with migrations `unknown` |

Docker Compose installs had all of these through the default privileges in `docker/init-app-role.sh`. Installs that create the role another way, and the test template database, did not.

## Key decisions

- `security_events` has no `UPDATE` grant. The application never edits an event.
- The sweep covered every `INSERT`, `UPDATE`, `DELETE` and `TRUNCATE` in production Go and `internal/store/queries`, every squirrel builder call, `ON CONFLICT DO UPDATE` and row locks (both need `UPDATE`). No migration defines a sequence, trigger, function or view, so none of those need a grant. Foreign-key cascades run as the table owner and need none.
- `schema_migrations` is outside `migrations/` but is the same kind of gap, so the same migration covers it. golang-migrate creates the table before the first migration runs.
- The down migration revokes every privilege the up grants. On a Compose install that also removes what the default privileges gave, so an operator who rolls back this migration there must grant those privileges again or the affected paths fail. `docs/deployment/upgrading.md` has the command. The down cannot branch on the install type: the migration runner splits files on every `;`, so a `DO` block does not survive it.

## Gotchas

- golang-migrate with `MultiStatementEnabled` splits a file on every `;`, including one inside a `--` comment. A semicolon in a migration comment fails with `syntax error` at the text after it, and `migration failed in line 0`.
- `cve_search_index` is deleted before `cves` in `migrateCVEPKMerge`, so removing only the `cves` grant is what proves that grant is needed.

## Quality checks

- Before the migration, the tests running as `db.AppStore` failed with `permission denied ... (SQLSTATE 42501)` for each table: both retention cleanups, `InsertSecurityEvent`, both alias promotion paths and `/readyz`. `TestSecurityEventWriter_WritesEvent` failed with 0 events written and the same error logged.
- After it they pass, as do the neighbouring `internal/store`, `internal/secure`, `internal/merge`, `internal/api`, `internal/retention` and `migrations` tests selected by name. With only the `cves` grant removed, the merge path fails on `cves` and the rename path passes.
- A throwaway test ran the migration down and up: all seven privileges went from granted to revoked to granted, and the version went 55, 54, 55 with no dirty flag.
- An executing `codex exec --yolo` review built its own table-by-verb comparison, migrated a fresh Postgres with no default privileges, and found no missing grant. It confirmed the Compose rollback behaviour above, an alias promotion assertion that discarded a lookup error, and missing `ABOUTME` headers on the migration. All three are addressed.
- `golangci-lint run` on the four packages with changed tests reports 0 issues. The full suite was not run locally.
