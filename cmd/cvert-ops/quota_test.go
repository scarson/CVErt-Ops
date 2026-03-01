// ABOUTME: Tests for the quota CLI subcommand.
// ABOUTME: Integration tests for store methods and unit test for feature validation.
package main

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestQuotaCmd_SetAndGet(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org, _ := s.CreateOrg(ctx, "Quota CLI Test Org")

	err := s.SetAIQuotaOverride(ctx, org.ID, "nl_search", 500)
	if err != nil {
		t.Fatalf("SetAIQuotaOverride: %v", err)
	}

	limit, ok, err := s.GetAIQuotaOverride(ctx, org.ID, "nl_search")
	if err != nil {
		t.Fatalf("GetAIQuotaOverride: %v", err)
	}
	if !ok {
		t.Fatal("expected override to exist")
	}
	if limit != 500 {
		t.Errorf("limit = %d, want 500", limit)
	}

	overrides, err := s.ListAIQuotaOverridesForOrg(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListAIQuotaOverridesForOrg: %v", err)
	}
	if len(overrides) != 1 {
		t.Fatalf("got %d overrides, want 1", len(overrides))
	}
	if overrides[0].Feature != "nl_search" || overrides[0].DailyLimit != 500 {
		t.Errorf("override = %+v, want nl_search/500", overrides[0])
	}
}

func TestQuotaCmd_Delete(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org, _ := s.CreateOrg(ctx, "Quota Delete Test Org")

	if err := s.SetAIQuotaOverride(ctx, org.ID, "summarize", 100); err != nil {
		t.Fatalf("SetAIQuotaOverride: %v", err)
	}
	err := s.DeleteAIQuotaOverride(ctx, org.ID, "summarize")
	if err != nil {
		t.Fatalf("DeleteAIQuotaOverride: %v", err)
	}

	_, ok, _ := s.GetAIQuotaOverride(ctx, org.ID, "summarize")
	if ok {
		t.Error("expected override to be deleted")
	}
}

func TestQuotaCmd_SetInvalidFeature(t *testing.T) {
	t.Parallel()
	cmd := quotaSetCmd()
	cmd.SetArgs([]string{
		"--org", uuid.New().String(),
		"--feature", "invalid_feature",
		"--limit", "100",
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid feature name")
	}
}
