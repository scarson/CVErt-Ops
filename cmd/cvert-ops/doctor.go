// ABOUTME: `cvert-ops doctor` CLI subcommand — runs health checks and prints results.
// ABOUTME: Connects to DB, verifies config, prints colored pass/warn/fail per check.
package main

import (
	"context"
	"fmt"

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

	checks := doctor.StandardChecks(doctor.StandardChecksConfig{
		DB:                       db,
		ExpectedSchemaVersion:    expectedSchemaVersion,
		SSOEncryptionKey:         cfg.SSOEncryptionKey,
		SSOEncryptionKeyPrevious: cfg.SSOEncryptionKeyPrevious,
		JWTSecret:                cfg.JWTSecret,
		SMTPHost:                 cfg.SMTPHost,
		SMTPPort:                 cfg.SMTPPort,
		SMTPUsername:             cfg.SMTPUsername,
	})
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
