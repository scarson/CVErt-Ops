// ABOUTME: `cvert-ops doctor` CLI subcommand — runs health checks and prints results.
// ABOUTME: Connects to DB, verifies config, prints colored pass/warn/fail per check.
package main

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/doctor"
)

func doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Run system health checks and report status",
		RunE:  runDoctor,
	}
}

func runDoctor(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	ctx := context.Background()

	db, err := newPool(ctx, cfg)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer db.Close()

	checks := buildDoctorChecks(cfg, db)
	results := doctor.Run(ctx, checks)

	// Print results with colored status markers.
	for _, r := range results {
		marker := statusMarker(r.Status)
		fmt.Printf("  %s %s: %s\n", marker, r.Name, r.Message)
		if r.Error != "" {
			fmt.Printf("       error: %s\n", r.Error)
		}
	}

	// Summary line.
	pass, warn, fail := countByStatus(results)
	fmt.Printf("\n  %d passed, %d warnings, %d failed\n", pass, warn, fail)

	if doctor.HasFailures(results) || warn > 0 {
		return fmt.Errorf("doctor found issues (%d warnings, %d failures)", warn, fail)
	}
	return nil
}

// buildDoctorChecks constructs the standard set of health checks from config
// and DB pool. Used by both CLI and API doctor endpoints.
func buildDoctorChecks(cfg *config.Config, pool *pgxpool.Pool) []doctor.Check {
	var encKey [32]byte
	if cfg.SSOEncryptionKey != "" {
		decoded, err := hex.DecodeString(cfg.SSOEncryptionKey)
		if err == nil && len(decoded) == 32 {
			copy(encKey[:], decoded)
		}
	}

	smtpHost := cfg.SMTPHost
	// Default SMTP host is "localhost" — treat as unconfigured unless explicitly
	// set with a real hostname and non-default port or credentials.
	if smtpHost == "localhost" && cfg.SMTPUsername == "" {
		smtpHost = ""
	}

	return []doctor.Check{
		&doctor.DBConnectivityCheck{DB: pool},
		&doctor.MigrationCheck{DB: pool, ExpectedVersion: expectedSchemaVersion},
		&doctor.DBRoleCheck{DB: pool},
		&doctor.RLSCheck{DB: pool, Tables: doctor.OrgScopedTables()},
		&doctor.EncryptionSentinelCheck{DB: pool, Key: encKey},
		&doctor.JWTCheck{Secret: cfg.JWTSecret},
		&doctor.SMTPCheck{Host: smtpHost, Port: cfg.SMTPPort},
		&doctor.DiskCheck{},
		&doctor.FeedCheck{DB: pool},
	}
}

func statusMarker(status string) string {
	switch status {
	case doctor.StatusPass:
		return "\033[32m✓\033[0m" // green
	case doctor.StatusWarn:
		return "\033[33m!\033[0m" // yellow
	case doctor.StatusFail:
		return "\033[31m✗\033[0m" // red
	default:
		return "?"
	}
}

func countByStatus(results []doctor.Result) (pass, warn, fail int) {
	for _, r := range results {
		switch r.Status {
		case doctor.StatusPass:
			pass++
		case doctor.StatusWarn:
			warn++
		case doctor.StatusFail:
			fail++
		}
	}
	return
}
