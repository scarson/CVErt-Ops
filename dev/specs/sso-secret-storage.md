# SSO Secret Storage Architecture

This document describes how CVErt Ops stores and manages user-provided secrets (specifically, OAuth/OIDC client secrets for enterprise SSO connections) in the production/SaaS configuration.

## What's Encrypted

The **only** user-input secret encrypted at rest in the database is `sso_connections.client_secret_enc` — the OIDC client secret that tenants provide when configuring enterprise SSO. It is stored as `BYTEA` in Postgres (migration `000028_sso_connections.up.sql`).

## Encryption Scheme

**AES-256-GCM** with random 12-byte nonces, implemented in `internal/crypto/aes.go`.

- **Ciphertext format:** `nonce (12 bytes) || ciphertext + GCM authentication tag`
- **Nonce source:** `crypto/rand.Reader` (OS CSPRNG)
- **Library:** Go stdlib `crypto/aes` and `crypto/cipher` — no external crypto dependencies

AES-256-GCM provides both confidentiality and integrity (authenticated encryption). An attacker who obtains a database dump cannot read or tamper with the client secrets without also possessing the encryption key.

## Key Sourcing

The encryption key is a raw 32-byte value provided as 64 hex characters via:

1. **Startup:** The `SSO_ENCRYPTION_KEY` environment variable, parsed by `internal/config/reloadable.go`
2. **Hot-reload:** A secrets file (one `KEY=VALUE` per line) can be reloaded at runtime via `SIGHUP` signal or the admin API reload endpoint. The key is swapped atomically using `atomic.Pointer` in `config.Holder`, so in-flight requests are never disrupted

The API handler reads the active key via `srv.ssoEncryptionKey()` in `internal/api/sso.go`, which prefers the hot-reloadable config, falling back to the startup config value.

## Key Rotation

Key rotation uses a **dual-key** strategy with zero downtime:

1. **Operator** generates a new 32-byte key (`openssl rand -hex 32`)
2. **Operator** moves the current `SSO_ENCRYPTION_KEY` value to `SSO_ENCRYPTION_KEY_PREVIOUS` and sets the new key as `SSO_ENCRYPTION_KEY` in the secrets file
3. **Operator** reloads config (SIGHUP or admin API)
4. **During the transition window**, all decryption uses `crypto.DecryptWithFallback()` — tries the current key first, then falls back to the previous key on GCM authentication failure. Structural errors (truncated ciphertext, invalid key length) fail fast without attempting fallback
5. **Operator** runs `cvert-ops rotate-encryption-key`, which re-encrypts every `sso_connections.client_secret_enc` row in a single Postgres transaction: decrypt with fallback, re-encrypt with current key
6. **After re-encryption succeeds**, the operator removes `SSO_ENCRYPTION_KEY_PREVIOUS` and reloads config

The re-encryption command is transactional — if it fails partway through, the transaction rolls back and all rows remain encrypted with the original key. Safe to retry.

The full step-by-step procedure is documented in `docs/deployment/runbooks/secret-rotation.md`.

## Security Boundaries and Assumptions

| Boundary | Status |
|----------|--------|
| **Encryption at rest** | AES-256-GCM. Protects against database dump or backup theft |
| **Tenant isolation** | Row-Level Security (RLS) on `sso_connections` + `org_id` scoping. One tenant cannot read another's encrypted secret |
| **Key storage** | The encryption key lives in an environment variable or secrets file on the host. There is no KMS or HSM wrapping — compromise of the application server's environment means compromise of the key |
| **Memory exposure** | The key is held in process memory as a `[32]byte`. Standard Go runtime — no `mlock` or secure memory wipe. Acceptable for non-HSM deployments |
| **Rotation atomicity** | The `rotate-encryption-key` command runs in a single DB transaction. Failure leaves all rows encrypted with the old key (safe to retry) |
| **No envelope encryption** | There is no KMS-wrapped DEK/KEK split. `SSO_ENCRYPTION_KEY` is the data encryption key directly. Key rotation therefore requires re-encrypting every row (currently only `sso_connections`, so the blast radius is small) |

### Deployment expectation

The security model assumes that the deployment environment adequately protects the `SSO_ENCRYPTION_KEY` value. In practice this means:

- **Container deployments:** Use the platform's native secret injection (Kubernetes Secrets, Docker Swarm secrets, ECS task definition secrets, etc.)
- **Cloud VMs:** Use a cloud secret manager (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault) to inject the value into the environment at startup
- **Self-hosted:** Ensure the secrets file has restrictive file permissions and is excluded from backups and version control

If CVErt Ops later needs to support a managed SaaS model where the operator controls infrastructure, the natural upgrade path would be envelope encryption with a cloud KMS wrapping the SSO encryption key.

## What's NOT Encrypted at Rest

These values are **not** stored in the database — they live only in environment variables or the secrets file:

- OAuth provider secrets (`GITHUB_CLIENT_SECRET`, `GOOGLE_CLIENT_SECRET`) — app-level config, not tenant-provided
- JWT signing secrets (`JWT_SECRET`, `JWT_SECRET_PREVIOUS`)
- SMTP credentials (`SMTP_PASSWORD`)

These values are stored in the database but use **hashing, not encryption** (correct approach — they never need to be recovered in plaintext):

- User passwords — argon2id
- API key hashes

## Key Files

| File | Role |
|------|------|
| `internal/crypto/aes.go` | AES-256-GCM Encrypt / Decrypt / DecryptWithFallback |
| `internal/config/reloadable.go` | Hot-reloadable config with atomic key swap |
| `internal/api/sso.go` | SSO handler — encrypts on write, decrypts on read |
| `cmd/cvert-ops/rotate.go` | CLI re-encryption command |
| `migrations/000028_sso_connections.up.sql` | Schema with `client_secret_enc BYTEA` column + RLS |
| `internal/store/queries/sso.sql` | sqlc queries (encrypted column passed as opaque bytes) |
| `docs/deployment/runbooks/secret-rotation.md` | Operator-facing rotation procedures |

## Dependencies

- **Go stdlib crypto** (`crypto/aes`, `crypto/cipher`, `crypto/rand`) — no third-party crypto libraries
- **pgx** for the rotation transaction
- **Operator-managed key** — no external secrets manager SDK dependency
