// ABOUTME: Integration tests for store/ai.go — AI quota, cache, and request log store methods.
// ABOUTME: Uses testutil.NewTestDB; each test runs in its own container (t.Parallel).
package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestIncrementAIUsage_CreatesAndIncrements(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AIUsageOrg1")

	// First call creates the row with count=1.
	count, err := s.IncrementAIUsage(ctx, org.ID, "nl_search")
	if err != nil {
		t.Fatalf("IncrementAIUsage (first): %v", err)
	}
	if count != 1 {
		t.Errorf("count after first increment = %d, want 1", count)
	}

	// Second call increments to 2.
	count, err = s.IncrementAIUsage(ctx, org.ID, "nl_search")
	if err != nil {
		t.Fatalf("IncrementAIUsage (second): %v", err)
	}
	if count != 2 {
		t.Errorf("count after second increment = %d, want 2", count)
	}
}

func TestIncrementAIUsage_SeparateFeatures(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AIUsageOrg2")

	// Increment nl_search twice.
	s.IncrementAIUsage(ctx, org.ID, "nl_search") //nolint:gosec,errcheck // G104: first increment is a setup step
	count, err := s.IncrementAIUsage(ctx, org.ID, "nl_search")
	if err != nil {
		t.Fatalf("IncrementAIUsage nl_search: %v", err)
	}
	if count != 2 {
		t.Errorf("nl_search count = %d, want 2", count)
	}

	// Increment summarize once — independent counter.
	count, err = s.IncrementAIUsage(ctx, org.ID, "summarize")
	if err != nil {
		t.Fatalf("IncrementAIUsage summarize: %v", err)
	}
	if count != 1 {
		t.Errorf("summarize count = %d, want 1", count)
	}
}

func TestDecrementAIUsage_FloorsAtZero(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AIUsageOrg3")

	// Create a row with count=1.
	_, err := s.IncrementAIUsage(ctx, org.ID, "nl_search")
	if err != nil {
		t.Fatalf("IncrementAIUsage: %v", err)
	}

	// Decrement to 0.
	if err := s.DecrementAIUsage(ctx, org.ID, "nl_search"); err != nil {
		t.Fatalf("DecrementAIUsage (to 0): %v", err)
	}

	// Decrement again — should stay at 0 (GREATEST floor).
	if err := s.DecrementAIUsage(ctx, org.ID, "nl_search"); err != nil {
		t.Fatalf("DecrementAIUsage (below 0): %v", err)
	}

	// Increment to verify count is 1, proving it was at 0.
	count, err := s.IncrementAIUsage(ctx, org.ID, "nl_search")
	if err != nil {
		t.Fatalf("IncrementAIUsage (after decrement): %v", err)
	}
	if count != 1 {
		t.Errorf("count after decrement+increment = %d, want 1", count)
	}
}

func TestUpdateAIUsageTokens(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AIUsageOrg4")

	// IncrementAIUsage creates the row (count=1, tokens=0).
	_, err := s.IncrementAIUsage(ctx, org.ID, "summarize")
	if err != nil {
		t.Fatalf("IncrementAIUsage: %v", err)
	}

	// Add token counts.
	if err := s.UpdateAIUsageTokens(ctx, org.ID, "summarize", 100, 50); err != nil {
		t.Fatalf("UpdateAIUsageTokens: %v", err)
	}

	// Add more tokens — should accumulate.
	if err := s.UpdateAIUsageTokens(ctx, org.ID, "summarize", 200, 150); err != nil {
		t.Fatalf("UpdateAIUsageTokens (second): %v", err)
	}

	// No direct way to read tokens from store methods, but if no error, the update succeeded.
	// The DB constraint validates non-negative values.
}

func TestGetAIQuotaOverride_NotFound(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AIQuotaOrg1")

	limit, found, err := s.GetAIQuotaOverride(ctx, org.ID, "nl_search")
	if err != nil {
		t.Fatalf("GetAIQuotaOverride: %v", err)
	}
	if found {
		t.Error("expected found=false for missing override")
	}
	if limit != 0 {
		t.Errorf("limit = %d, want 0 when not found", limit)
	}
}

func TestSetAndGetAIQuotaOverride(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AIQuotaOrg2")

	// Set an override.
	if err := s.SetAIQuotaOverride(ctx, org.ID, "nl_search", 500); err != nil {
		t.Fatalf("SetAIQuotaOverride: %v", err)
	}

	// Read it back.
	limit, found, err := s.GetAIQuotaOverride(ctx, org.ID, "nl_search")
	if err != nil {
		t.Fatalf("GetAIQuotaOverride: %v", err)
	}
	if !found {
		t.Fatal("expected found=true after setting override")
	}
	if limit != 500 {
		t.Errorf("limit = %d, want 500", limit)
	}

	// Upsert with a different value.
	if err := s.SetAIQuotaOverride(ctx, org.ID, "nl_search", 1000); err != nil {
		t.Fatalf("SetAIQuotaOverride (upsert): %v", err)
	}
	limit, found, err = s.GetAIQuotaOverride(ctx, org.ID, "nl_search")
	if err != nil {
		t.Fatalf("GetAIQuotaOverride (after upsert): %v", err)
	}
	if !found || limit != 1000 {
		t.Errorf("after upsert: found=%v, limit=%d, want found=true, limit=1000", found, limit)
	}
}

func TestDeleteAIQuotaOverride(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AIQuotaOrg3")

	if err := s.SetAIQuotaOverride(ctx, org.ID, "summarize", 200); err != nil {
		t.Fatalf("SetAIQuotaOverride: %v", err)
	}

	if err := s.DeleteAIQuotaOverride(ctx, org.ID, "summarize"); err != nil {
		t.Fatalf("DeleteAIQuotaOverride: %v", err)
	}

	_, found, err := s.GetAIQuotaOverride(ctx, org.ID, "summarize")
	if err != nil {
		t.Fatalf("GetAIQuotaOverride (after delete): %v", err)
	}
	if found {
		t.Error("expected found=false after deleting override")
	}
}

func TestListAIQuotaOverrides(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1 := s.MustCreateOrg(t, ctx, "AIQuotaOrg4a")
	org2 := s.MustCreateOrg(t, ctx, "AIQuotaOrg4b")

	// Set overrides for two orgs.
	if err := s.SetAIQuotaOverride(ctx, org1.ID, "nl_search", 100); err != nil {
		t.Fatalf("SetAIQuotaOverride org1 nl_search: %v", err)
	}
	if err := s.SetAIQuotaOverride(ctx, org2.ID, "summarize", 200); err != nil {
		t.Fatalf("SetAIQuotaOverride org2 summarize: %v", err)
	}

	rows, err := s.ListAIQuotaOverrides(ctx)
	if err != nil {
		t.Fatalf("ListAIQuotaOverrides: %v", err)
	}
	if len(rows) < 2 {
		t.Fatalf("ListAIQuotaOverrides returned %d rows, want >= 2", len(rows))
	}

	// Verify our overrides are in the results.
	foundOrg1, foundOrg2 := false, false
	for _, r := range rows {
		if r.OrgID == org1.ID && r.Feature == "nl_search" && r.DailyLimit == 100 {
			foundOrg1 = true
		}
		if r.OrgID == org2.ID && r.Feature == "summarize" && r.DailyLimit == 200 {
			foundOrg2 = true
		}
	}
	if !foundOrg1 {
		t.Error("org1 nl_search override not found in list")
	}
	if !foundOrg2 {
		t.Error("org2 summarize override not found in list")
	}
}

func TestListAIQuotaOverridesForOrg(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AIQuotaOrg5")

	if err := s.SetAIQuotaOverride(ctx, org.ID, "nl_search", 100); err != nil {
		t.Fatalf("SetAIQuotaOverride nl_search: %v", err)
	}
	if err := s.SetAIQuotaOverride(ctx, org.ID, "summarize", 200); err != nil {
		t.Fatalf("SetAIQuotaOverride summarize: %v", err)
	}

	rows, err := s.ListAIQuotaOverridesForOrg(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListAIQuotaOverridesForOrg: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("ListAIQuotaOverridesForOrg returned %d rows, want 2", len(rows))
	}

	// Ordered by feature: nl_search, summarize.
	if rows[0].Feature != "nl_search" || rows[0].DailyLimit != 100 {
		t.Errorf("rows[0] = {%q, %d}, want {nl_search, 100}", rows[0].Feature, rows[0].DailyLimit)
	}
	if rows[1].Feature != "summarize" || rows[1].DailyLimit != 200 {
		t.Errorf("rows[1] = {%q, %d}, want {summarize, 200}", rows[1].Feature, rows[1].DailyLimit)
	}
}

func TestGetAICache_Miss(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AICacheOrg1")

	resp, found, err := s.GetAICache(ctx, org.ID, "nl_search", "v1", "abc123")
	if err != nil {
		t.Fatalf("GetAICache: %v", err)
	}
	if found {
		t.Error("expected found=false for cache miss")
	}
	if resp != nil {
		t.Errorf("expected nil response for cache miss, got %s", resp)
	}
}

func TestPutAndGetAICache(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AICacheOrg2")

	payload := json.RawMessage(`{"result":"test response"}`)

	// Put a cache entry with 1 hour TTL.
	if err := s.PutAICache(ctx, org.ID, "nl_search", "v1", "hash123", payload, time.Hour); err != nil {
		t.Fatalf("PutAICache: %v", err)
	}

	// Get it back.
	resp, found, err := s.GetAICache(ctx, org.ID, "nl_search", "v1", "hash123")
	if err != nil {
		t.Fatalf("GetAICache: %v", err)
	}
	if !found {
		t.Fatal("expected found=true for cached entry")
	}

	var got map[string]string
	if err := json.Unmarshal(resp, &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if got["result"] != "test response" {
		t.Errorf("cached response = %q, want 'test response'", got["result"])
	}
}

func TestPutAICache_Upsert(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AICacheOrg3")

	// Put initial entry.
	if err := s.PutAICache(ctx, org.ID, "nl_search", "v1", "hash456", json.RawMessage(`{"v":1}`), time.Hour); err != nil {
		t.Fatalf("PutAICache (initial): %v", err)
	}

	// Upsert with different response.
	if err := s.PutAICache(ctx, org.ID, "nl_search", "v1", "hash456", json.RawMessage(`{"v":2}`), time.Hour); err != nil {
		t.Fatalf("PutAICache (upsert): %v", err)
	}

	// Verify the upserted value.
	resp, found, err := s.GetAICache(ctx, org.ID, "nl_search", "v1", "hash456")
	if err != nil {
		t.Fatalf("GetAICache: %v", err)
	}
	if !found {
		t.Fatal("expected found=true after upsert")
	}
	var got map[string]int
	if err := json.Unmarshal(resp, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["v"] != 2 {
		t.Errorf("cached v = %d, want 2", got["v"])
	}
}

func TestGetAICache_DifferentPromptVersion(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AICacheOrg4")

	// Cache for v1.
	if err := s.PutAICache(ctx, org.ID, "nl_search", "v1", "hash789", json.RawMessage(`{"v":"v1"}`), time.Hour); err != nil {
		t.Fatalf("PutAICache v1: %v", err)
	}

	// Miss for v2 (different prompt version).
	_, found, err := s.GetAICache(ctx, org.ID, "nl_search", "v2", "hash789")
	if err != nil {
		t.Fatalf("GetAICache v2: %v", err)
	}
	if found {
		t.Error("expected cache miss for different prompt version")
	}
}

func TestInsertAIRequestLog(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AILogOrg1")
	userID := uuid.New()

	// Insert a success entry.
	err := s.InsertAIRequestLog(ctx, store.AIRequestLogEntry{
		OrgID:         org.ID,
		UserID:        userID,
		Feature:       "nl_search",
		InputHash:     "abc123",
		PromptVersion: "v1",
		Model:         "gemini-2.0-flash",
		CacheHit:      false,
		InputTokens:   100,
		OutputTokens:  50,
		LatencyMS:     250,
		Status:        "success",
	})
	if err != nil {
		t.Fatalf("InsertAIRequestLog (success): %v", err)
	}

	// Insert an error entry with error_type.
	err = s.InsertAIRequestLog(ctx, store.AIRequestLogEntry{
		OrgID:         org.ID,
		UserID:        userID,
		Feature:       "summarize",
		InputHash:     "def456",
		PromptVersion: "v1",
		Model:         "gemini-2.0-flash",
		CacheHit:      false,
		InputTokens:   0,
		OutputTokens:  0,
		LatencyMS:     500,
		Status:        "error",
		ErrorType:     "rate_limited",
	})
	if err != nil {
		t.Fatalf("InsertAIRequestLog (error): %v", err)
	}

	// Insert a cache hit entry (no tokens).
	err = s.InsertAIRequestLog(ctx, store.AIRequestLogEntry{
		OrgID:         org.ID,
		UserID:        userID,
		Feature:       "nl_search",
		InputHash:     "ghi789",
		PromptVersion: "v1",
		Model:         "gemini-2.0-flash",
		CacheHit:      true,
		LatencyMS:     5,
		Status:        "success",
	})
	if err != nil {
		t.Fatalf("InsertAIRequestLog (cache hit): %v", err)
	}
}

func TestAIUsage_OrgIsolation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1 := s.MustCreateOrg(t, ctx, "AIIsoOrg1")
	org2 := s.MustCreateOrg(t, ctx, "AIIsoOrg2")

	// Increment org1's counter.
	count, err := s.IncrementAIUsage(ctx, org1.ID, "nl_search")
	if err != nil {
		t.Fatalf("IncrementAIUsage org1: %v", err)
	}
	if count != 1 {
		t.Errorf("org1 count = %d, want 1", count)
	}

	// Org2's counter is independent.
	count, err = s.IncrementAIUsage(ctx, org2.ID, "nl_search")
	if err != nil {
		t.Fatalf("IncrementAIUsage org2: %v", err)
	}
	if count != 1 {
		t.Errorf("org2 count = %d, want 1 (independent from org1)", count)
	}
}

func TestAICache_OrgIsolation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1 := s.MustCreateOrg(t, ctx, "AICacheIso1")
	org2 := s.MustCreateOrg(t, ctx, "AICacheIso2")

	// Cache entry for org1.
	if err := s.PutAICache(ctx, org1.ID, "nl_search", "v1", "shared_hash", json.RawMessage(`{"org":1}`), time.Hour); err != nil {
		t.Fatalf("PutAICache org1: %v", err)
	}

	// Org2 should not see org1's cache.
	_, found, err := s.GetAICache(ctx, org2.ID, "nl_search", "v1", "shared_hash")
	if err != nil {
		t.Fatalf("GetAICache org2: %v", err)
	}
	if found {
		t.Error("org2 should not see org1's cache entry")
	}
}

// ── AppStore RLS tests ──────────────────────────────────────────────────────
// These tests use AppStore (cvert_ops_app, NOBYPASSRLS) to verify that
// RLS policies on ai_usage_counters, ai_cache, and ai_request_log are enforced.

func TestIncrementAIUsage_AppStoreRLS(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1 := s.MustCreateOrg(t, ctx, "AIUsageRLS1")
	org2 := s.MustCreateOrg(t, ctx, "AIUsageRLS2")

	// Increment via AppStore for both orgs.
	count1, err := s.AppStore.IncrementAIUsage(ctx, org1.ID, "nl_search")
	if err != nil {
		t.Fatalf("AppStore.IncrementAIUsage org1: %v", err)
	}
	if count1 != 1 {
		t.Errorf("org1 count = %d, want 1", count1)
	}

	count2, err := s.AppStore.IncrementAIUsage(ctx, org2.ID, "nl_search")
	if err != nil {
		t.Fatalf("AppStore.IncrementAIUsage org2: %v", err)
	}
	if count2 != 1 {
		t.Errorf("org2 count = %d, want 1 (independent from org1)", count2)
	}

	// Increment org1 again — should be 2, not 3 (no cross-org contamination).
	count1, err = s.AppStore.IncrementAIUsage(ctx, org1.ID, "nl_search")
	if err != nil {
		t.Fatalf("AppStore.IncrementAIUsage org1 (2nd): %v", err)
	}
	if count1 != 2 {
		t.Errorf("org1 count after 2nd increment = %d, want 2", count1)
	}
}

func TestDecrementAIUsage_AppStoreRLS(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AIDecrRLS")

	// Create a row via superuser store, decrement via AppStore.
	if _, err := s.IncrementAIUsage(ctx, org.ID, "nl_search"); err != nil {
		t.Fatalf("seed IncrementAIUsage: %v", err)
	}

	if err := s.AppStore.DecrementAIUsage(ctx, org.ID, "nl_search"); err != nil {
		t.Fatalf("AppStore.DecrementAIUsage: %v", err)
	}

	// Verify count is 0 by incrementing back to 1.
	count, err := s.AppStore.IncrementAIUsage(ctx, org.ID, "nl_search")
	if err != nil {
		t.Fatalf("AppStore.IncrementAIUsage after decrement: %v", err)
	}
	if count != 1 {
		t.Errorf("count after decrement+increment = %d, want 1", count)
	}
}

func TestUpdateAIUsageTokens_AppStoreRLS(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AITokenRLS")

	// Create usage row first.
	if _, err := s.IncrementAIUsage(ctx, org.ID, "summarize"); err != nil {
		t.Fatalf("seed IncrementAIUsage: %v", err)
	}

	// Update tokens via AppStore.
	if err := s.AppStore.UpdateAIUsageTokens(ctx, org.ID, "summarize", 100, 50); err != nil {
		t.Fatalf("AppStore.UpdateAIUsageTokens: %v", err)
	}
}

func TestGetAIQuotaOverride_AppStoreRLS(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1 := s.MustCreateOrg(t, ctx, "AIQuotaRLS1")
	org2 := s.MustCreateOrg(t, ctx, "AIQuotaRLS2")

	// Set override via superuser bypass TX.
	if err := s.SetAIQuotaOverride(ctx, org1.ID, "nl_search", 500); err != nil {
		t.Fatalf("SetAIQuotaOverride org1: %v", err)
	}
	if err := s.SetAIQuotaOverride(ctx, org2.ID, "nl_search", 999); err != nil {
		t.Fatalf("SetAIQuotaOverride org2: %v", err)
	}

	// Read via AppStore — org1 should see 500, not 999.
	limit, found, err := s.AppStore.GetAIQuotaOverride(ctx, org1.ID, "nl_search")
	if err != nil {
		t.Fatalf("AppStore.GetAIQuotaOverride org1: %v", err)
	}
	if !found {
		t.Fatal("expected found=true for org1 override")
	}
	if limit != 500 {
		t.Errorf("org1 limit = %d, want 500", limit)
	}
}

func TestGetAICache_AppStoreRLS(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1 := s.MustCreateOrg(t, ctx, "AICacheRLS1")
	org2 := s.MustCreateOrg(t, ctx, "AICacheRLS2")

	// Seed cache via superuser store.
	if err := s.PutAICache(ctx, org1.ID, "nl_search", "v1", "rlshash", json.RawMessage(`{"org":"one"}`), time.Hour); err != nil {
		t.Fatalf("PutAICache org1: %v", err)
	}

	// AppStore with org1 context should find it.
	resp, found, err := s.AppStore.GetAICache(ctx, org1.ID, "nl_search", "v1", "rlshash")
	if err != nil {
		t.Fatalf("AppStore.GetAICache org1: %v", err)
	}
	if !found {
		t.Fatal("expected cache hit for org1")
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	// AppStore with org2 context should miss — RLS isolates the cache.
	_, found, err = s.AppStore.GetAICache(ctx, org2.ID, "nl_search", "v1", "rlshash")
	if err != nil {
		t.Fatalf("AppStore.GetAICache org2: %v", err)
	}
	if found {
		t.Error("org2 should not see org1's cache entry via AppStore (RLS violation)")
	}
}

func TestPutAICache_AppStoreRLS(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AIPutCacheRLS")

	// Put via AppStore.
	if err := s.AppStore.PutAICache(ctx, org.ID, "nl_search", "v1", "putrlshash", json.RawMessage(`{"ok":true}`), time.Hour); err != nil {
		t.Fatalf("AppStore.PutAICache: %v", err)
	}

	// Verify readable via AppStore.
	_, found, err := s.AppStore.GetAICache(ctx, org.ID, "nl_search", "v1", "putrlshash")
	if err != nil {
		t.Fatalf("AppStore.GetAICache: %v", err)
	}
	if !found {
		t.Error("expected cache hit after AppStore.PutAICache")
	}
}

func TestInsertAIRequestLog_AppStoreRLS(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AILogRLS")
	userID := uuid.New()

	// Insert via AppStore — must succeed (WITH CHECK clause for org_id).
	err := s.AppStore.InsertAIRequestLog(ctx, store.AIRequestLogEntry{
		OrgID:         org.ID,
		UserID:        userID,
		Feature:       "nl_search",
		InputHash:     "rlshash1",
		PromptVersion: "v1",
		Model:         "gemini-2.0-flash",
		CacheHit:      false,
		InputTokens:   50,
		OutputTokens:  25,
		LatencyMS:     100,
		Status:        "success",
	})
	if err != nil {
		t.Fatalf("AppStore.InsertAIRequestLog: %v", err)
	}
}
