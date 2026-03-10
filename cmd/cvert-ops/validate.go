// ABOUTME: Cobra subcommand that validates all YAML feed configs in a directory.
// ABOUTME: Checks syntax, required fields, reserved names, and optionally tests connectivity.
package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/scarson/cvert-ops/internal/feed/generic"
)

func validateFeedsCmd() *cobra.Command {
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "validate-feeds",
		Short: "Validate generic feed YAML configs in CVERTOPS_FEEDS_DIR",
		RunE: func(_ *cobra.Command, _ []string) error {
			dir := os.Getenv("CVERTOPS_FEEDS_DIR")
			if dir == "" {
				return fmt.Errorf("CVERTOPS_FEEDS_DIR is not set")
			}
			return runValidateFeeds(dir, dryRun)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "fetch first page from each feed URL to verify connectivity")
	return cmd
}

// runValidateFeeds validates all YAML feed configs in the given directory.
// Returns an error if any config is invalid or the directory is empty/unreadable.
func runValidateFeeds(dir string, dryRun bool) error {
	configs, errs := generic.LoadDir(dir)

	for _, e := range errs {
		slog.Error("invalid feed config", "error", e)
	}

	if len(errs) > 0 {
		return fmt.Errorf("validation failed: %d error(s)", len(errs))
	}
	if len(configs) == 0 {
		return fmt.Errorf("no valid feed configs found in %s", dir)
	}

	if dryRun {
		slog.Info("dry-run: connectivity checks not yet implemented")
	}

	_, _ = fmt.Fprintf(os.Stdout, "OK: %d feed config(s) valid\n", len(configs))
	return nil
}
