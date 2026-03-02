// ABOUTME: CLI subcommand for managing per-org AI quota overrides.
// ABOUTME: Direct DB connection (bypasses RLS), like the migrate command.
package main

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/store"
)

func quotaCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "quota",
		Short: "Manage per-org AI quota overrides",
	}
	cmd.AddCommand(quotaSetCmd(), quotaGetCmd(), quotaListCmd(), quotaDeleteCmd())
	return cmd
}

func quotaSetCmd() *cobra.Command {
	var orgIDStr, feature string
	var limit int

	cmd := &cobra.Command{
		Use:   "set",
		Short: "Set a per-org AI quota override",
		RunE: func(cmd *cobra.Command, _ []string) error {
			orgID, err := uuid.Parse(orgIDStr)
			if err != nil {
				return fmt.Errorf("invalid org ID: %w", err)
			}
			if err := validateFeature(feature); err != nil {
				return err
			}

			cfg, err := config.Load()
			if err != nil {
				return err
			}
			pool, err := newPool(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			defer pool.Close()

			s := store.New(pool)
			return s.SetAIQuotaOverride(cmd.Context(), orgID, feature, limit)
		},
	}

	cmd.Flags().StringVar(&orgIDStr, "org", "", "Organization ID (UUID)")
	cmd.Flags().StringVar(&feature, "feature", "", "Feature name (nl_search or summarize)")
	cmd.Flags().IntVar(&limit, "limit", 0, "Daily request limit")
	cmd.MarkFlagRequired("org")     //nolint:errcheck,gosec // flag name is a hardcoded literal
	cmd.MarkFlagRequired("feature") //nolint:errcheck,gosec // flag name is a hardcoded literal
	cmd.MarkFlagRequired("limit")   //nolint:errcheck,gosec // flag name is a hardcoded literal
	return cmd
}

func quotaGetCmd() *cobra.Command {
	var orgIDStr string

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get quota overrides for an org",
		RunE: func(cmd *cobra.Command, _ []string) error {
			orgID, err := uuid.Parse(orgIDStr)
			if err != nil {
				return fmt.Errorf("invalid org ID: %w", err)
			}

			cfg, err := config.Load()
			if err != nil {
				return err
			}
			pool, err := newPool(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			defer pool.Close()

			s := store.New(pool)
			overrides, err := s.ListAIQuotaOverridesForOrg(cmd.Context(), orgID)
			if err != nil {
				return err
			}
			if len(overrides) == 0 {
				fmt.Println("No overrides set for this org.")
				return nil
			}
			for _, o := range overrides {
				fmt.Printf("  %s: %d/day\n", o.Feature, o.DailyLimit)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&orgIDStr, "org", "", "Organization ID (UUID)")
	cmd.MarkFlagRequired("org") //nolint:errcheck,gosec // flag name is a hardcoded literal
	return cmd
}

func quotaListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all quota overrides across all orgs",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			pool, err := newPool(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			defer pool.Close()

			s := store.New(pool)
			overrides, err := s.ListAIQuotaOverrides(cmd.Context())
			if err != nil {
				return err
			}
			if len(overrides) == 0 {
				fmt.Println("No overrides configured.")
				return nil
			}
			for _, o := range overrides {
				fmt.Printf("  org=%s  feature=%s  limit=%d/day\n", o.OrgID, o.Feature, o.DailyLimit)
			}
			return nil
		},
	}
}

func quotaDeleteCmd() *cobra.Command {
	var orgIDStr, feature string

	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Remove a per-org quota override (reverts to tier default)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			orgID, err := uuid.Parse(orgIDStr)
			if err != nil {
				return fmt.Errorf("invalid org ID: %w", err)
			}

			cfg, err := config.Load()
			if err != nil {
				return err
			}
			pool, err := newPool(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			defer pool.Close()

			s := store.New(pool)
			return s.DeleteAIQuotaOverride(cmd.Context(), orgID, feature)
		},
	}

	cmd.Flags().StringVar(&orgIDStr, "org", "", "Organization ID (UUID)")
	cmd.Flags().StringVar(&feature, "feature", "", "Feature name")
	cmd.MarkFlagRequired("org")     //nolint:errcheck,gosec // flag name is a hardcoded literal
	cmd.MarkFlagRequired("feature") //nolint:errcheck,gosec // flag name is a hardcoded literal
	return cmd
}

// validFeatures enumerates the AI features that support quota overrides.
var validFeatures = map[string]bool{
	"nl_search":  true,
	"summarize":  true,
}

// validateFeature rejects unrecognized feature names before any DB call.
func validateFeature(feature string) error {
	if !validFeatures[feature] {
		return fmt.Errorf("feature must be 'nl_search' or 'summarize', got %q", feature)
	}
	return nil
}
