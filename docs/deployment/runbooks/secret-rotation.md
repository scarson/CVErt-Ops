# Secret Rotation Runbook

This runbook documents step-by-step procedures for rotating secrets used by CVErt Ops. Each procedure includes prerequisites, detailed steps, verification, and rollback instructions. Follow these procedures during scheduled rotation cycles or in response to a suspected credential compromise.

## JWT Key Rotation (dual-key, zero-downtime)

**Prerequisites:** Access to server config (secrets file), ability to trigger SIGHUP or call the admin API reload endpoint.

1. Generate a new JWT secret (>= 32 bytes):

   ```bash
   openssl rand -base64 48
   ```

2. Set `JWT_SECRET_PREVIOUS` to the current `JWT_SECRET` value in the secrets file.

3. Set `JWT_SECRET` to the newly generated value in the secrets file.

4. Reload config:

   ```bash
   # Unix
   kill -HUP <pid>

   # All platforms
   curl -X POST https://<host>/api/v1/admin/reload-config
   ```

5. Wait for all existing tokens to expire:
   - Access tokens: 15 minutes
   - Refresh tokens: 7 days

   > **Warning:** Removing the previous key before tokens expire will immediately invalidate all sessions signed with the old key.

6. Remove `JWT_SECRET_PREVIOUS` from the secrets file.

7. Reload config again (SIGHUP or admin API).

8. **Verify:**

   ```bash
   cvert-ops doctor
   ```

   The `jwt_configuration` check should pass.

**Rollback:** Swap `JWT_SECRET` back to the previous value, clear `JWT_SECRET_PREVIOUS`, and reload config.

## SSO Encryption Key Rotation (dual-key + re-encryption)

**Prerequisites:** Access to server config (secrets file), database connection for the re-encryption command.

1. Generate a new 32-byte key:

   ```bash
   openssl rand -hex 32
   ```

2. Set `SSO_ENCRYPTION_KEY_PREVIOUS` to the current `SSO_ENCRYPTION_KEY` value in the secrets file.

3. Set `SSO_ENCRYPTION_KEY` to the newly generated hex value in the secrets file.

4. Reload config (SIGHUP or admin API).

5. Run re-encryption:

   ```bash
   cvert-ops rotate-encryption-key
   ```

   > **Warning:** This command re-encrypts all SSO provider tokens in the database. Ensure you have a recent database backup before proceeding.

6. **Verify:**

   ```bash
   cvert-ops doctor
   ```

   The `encryption_sentinel` check should pass.

7. Remove `SSO_ENCRYPTION_KEY_PREVIOUS` from the secrets file.

8. Reload config again.

**Rollback:** If re-encryption fails, swap keys back (restore the old value to `SSO_ENCRYPTION_KEY`, remove `SSO_ENCRYPTION_KEY_PREVIOUS`) and reload. The old key remains valid because re-encryption is transactional -- a failed run leaves all data encrypted with the original key.

## Database Credential Rotation

**Prerequisites:** Database admin access (ability to ALTER ROLE or create new roles).

1. Create new database credentials:

   ```sql
   -- Option A: Change password on existing role
   ALTER ROLE cvert_app WITH PASSWORD 'new-secure-password';

   -- Option B: Create a new role and grant permissions
   CREATE ROLE cvert_app_v2 WITH LOGIN PASSWORD 'new-secure-password';
   GRANT cvert_app TO cvert_app_v2;
   ```

2. Update `DATABASE_URL` in the secrets file with the new credentials.

3. **Restart the service.** The database connection pool is initialized at startup and is not hot-reloadable.

   > **Warning:** This causes a brief service interruption. Schedule during a maintenance window.

4. **Verify:**

   ```bash
   cvert-ops doctor
   ```

   The `database_connectivity` check should pass.

5. If using Option B above, revoke the old role after confirming the new credentials work.

**Rollback:** Revert `DATABASE_URL` to the old credentials and restart. Old credentials remain valid until explicitly revoked.

## SMTP Credential Rotation (hot-reloadable)

**Prerequisites:** New SMTP credentials from your email provider.

1. Update the following values in the secrets file:
   - `SMTP_HOST`
   - `SMTP_PORT`
   - `SMTP_USERNAME`
   - `SMTP_PASSWORD`
   - `SMTP_TLS`

2. Reload config (SIGHUP or admin API).

3. **Verify:**

   ```bash
   cvert-ops doctor
   ```

   The `smtp_connectivity` check should pass.

4. Send a test notification to verify end-to-end delivery.

**Rollback:** Revert SMTP credentials in the secrets file and reload config.

## OAuth Client Secret Rotation (provider-specific)

**Prerequisites:** Access to the OAuth provider's developer console (GitHub, Google, etc.).

1. Generate a new client secret in the provider's developer console.

   > **Warning:** Do NOT revoke the old client secret yet. Keep it active until the new secret is verified.

2. Update the corresponding environment variable in the secrets file:
   - GitHub: `GITHUB_CLIENT_SECRET`
   - Google: `GOOGLE_CLIENT_SECRET`

3. **Restart the service.** OAuth config is not hot-reloadable.

4. **Verify:** Test the OAuth login flow end-to-end by signing in with the affected provider.

5. After confirming the new secret works, revoke the old client secret in the provider's developer console.

**Rollback:** Revert to the old secret in the secrets file and restart. Do NOT revoke the old secret until the new secret is verified working.
