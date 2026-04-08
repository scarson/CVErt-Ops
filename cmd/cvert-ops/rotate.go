// ABOUTME: CLI subcommand that re-encrypts all encrypted DB values with the current key.
// ABOUTME: Enables safe rotation by decrypting with fallback and re-encrypting in a single transaction.
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/crypto"
)

func rotateEncryptionKeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate-encryption-key",
		Short: "Re-encrypt all secrets with the current SSO_ENCRYPTION_KEY",
		Long: `Re-encrypts all encrypted values in the database using the current
SSO_ENCRYPTION_KEY so that SSO_ENCRYPTION_KEY_PREVIOUS can be safely removed.

Requires both SSO_ENCRYPTION_KEY and SSO_ENCRYPTION_KEY_PREVIOUS to be set.
Runs in a single transaction; safe to retry on failure.`,
		RunE: runRotateEncryptionKey,
	}
}

func runRotateEncryptionKey(cmd *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	currentKey, err := parseHexKey(cfg.SSOEncryptionKey, "SSO_ENCRYPTION_KEY")
	if err != nil {
		return err
	}

	previousKey, err := parseHexKey(cfg.SSOEncryptionKeyPrevious, "SSO_ENCRYPTION_KEY_PREVIOUS")
	if err != nil {
		return err
	}

	ctx := cmd.Context()
	pool, err := newPool(ctx, cfg)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer pool.Close()

	count, err := rotateEncryptionKeys(ctx, pool, currentKey, previousKey)
	if err != nil {
		return err
	}

	slog.Info("encryption key rotation complete", "rows_re_encrypted", count)
	fmt.Printf("Done: %d row(s) re-encrypted.\n", count)
	return nil
}

// parseHexKey decodes a hex-encoded 32-byte key, returning a descriptive error
// that names the environment variable on failure.
func parseHexKey(hexStr, envVar string) ([32]byte, error) {
	var key [32]byte
	if hexStr == "" {
		return key, fmt.Errorf("%s is not set", envVar)
	}
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return key, fmt.Errorf("%s: invalid hex: %w", envVar, err)
	}
	if len(raw) != 32 {
		return key, fmt.Errorf("%s: need 32 bytes, got %d", envVar, len(raw))
	}
	copy(key[:], raw)
	return key, nil
}

// rotateEncryptionKeys re-encrypts all sso_connections.client_secret_enc values.
// Decrypts each value using DecryptWithFallback (currentKey, then previousKey),
// then re-encrypts with currentKey. Runs in a single transaction.
//
// Returns the number of rows re-encrypted and any error.
func rotateEncryptionKeys(ctx context.Context, pool *pgxpool.Pool, currentKey, previousKey [32]byte) (int, error) {
	if previousKey == [32]byte{} {
		return 0, fmt.Errorf("previous encryption key is required for rotation")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Bypass RLS so the CLI can access all orgs' SSO connections.
	if _, err := tx.Exec(ctx, "SET LOCAL app.bypass_rls = 'on'"); err != nil {
		return 0, fmt.Errorf("set bypass_rls: %w", err)
	}

	rows, err := tx.Query(ctx, "SELECT id, org_id, client_secret_enc FROM sso_connections")
	if err != nil {
		return 0, fmt.Errorf("query sso_connections: %w", err)
	}
	defer rows.Close()

	type pending struct {
		id    string
		orgID [16]byte
		enc   []byte
	}

	var updates []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.orgID, &p.enc); err != nil {
			return 0, fmt.Errorf("scan row: %w", err)
		}
		updates = append(updates, p)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate rows: %w", err)
	}

	count := 0
	for _, u := range updates {
		plaintext, err := crypto.DecryptWithFallback(currentKey, previousKey, u.enc, u.orgID[:])
		if err != nil {
			return 0, fmt.Errorf("decrypt row %s: %w", u.id, err)
		}

		newEnc, err := crypto.Encrypt(currentKey, plaintext, u.orgID[:])
		if err != nil {
			return 0, fmt.Errorf("re-encrypt row %s: %w", u.id, err)
		}

		tag, err := tx.Exec(ctx,
			"UPDATE sso_connections SET client_secret_enc = $1 WHERE id = $2",
			newEnc, u.id,
		)
		if err != nil {
			return 0, fmt.Errorf("update row %s: %w", u.id, err)
		}
		if tag.RowsAffected() != 1 {
			return 0, fmt.Errorf("update row %s: expected 1 row affected, got %d", u.id, tag.RowsAffected())
		}
		count++
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}

	return count, nil
}
