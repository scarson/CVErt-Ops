// ABOUTME: Integration tests for audit log store methods.
// ABOUTME: Covers keyset cursor pagination, ActorID filtering, and entity_type/action filtering.
package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func seedAuditOrg(t *testing.T, s *testutil.TestDB, name string) uuid.UUID {
	t.Helper()
	var orgID uuid.UUID
	err := s.DB().QueryRowContext(context.Background(),
		`INSERT INTO organizations (name) VALUES ($1) RETURNING id`, name,
	).Scan(&orgID)
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	return orgID
}

func insertAuditRow(t *testing.T, s *testutil.TestDB, e store.AuditEntry) {
	t.Helper()
	if err := s.InsertAuditEntry(context.Background(), e); err != nil {
		t.Fatalf("insert audit entry: %v", err)
	}
}

func TestListAuditEntries_KeysetPagination(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID := seedAuditOrg(t, s, "audit-cursor")
	actorID := uuid.New()

	// Insert 5 entries with slight time gaps (serial inserts guarantee ordering).
	for i := 0; i < 5; i++ {
		insertAuditRow(t, s, store.AuditEntry{
			OrgID:      orgID,
			ActorID:    &actorID,
			Action:     "create",
			EntityType: "alert_rule",
			EntityID:   uuid.New().String(),
			Success:    true,
		})
	}

	// Page 1: fetch first 2
	page1, err := s.ListAuditEntries(ctx, store.AuditListParams{
		OrgID:    orgID,
		After:    time.Now().Add(-1 * time.Hour),
		Before:   time.Now().Add(1 * time.Hour),
		PageSize: 2,
	})
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if len(page1) != 2 {
		t.Fatalf("page 1: got %d rows, want 2", len(page1))
	}

	// Page 2: use cursor from last row of page 1
	cursor := page1[len(page1)-1]
	page2, err := s.ListAuditEntries(ctx, store.AuditListParams{
		OrgID:           orgID,
		After:           time.Now().Add(-1 * time.Hour),
		Before:          time.Now().Add(1 * time.Hour),
		CursorCreatedAt: &cursor.CreatedAt,
		CursorID:        &cursor.ID,
		PageSize:        2,
	})
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if len(page2) != 2 {
		t.Fatalf("page 2: got %d rows, want 2", len(page2))
	}

	// Verify no overlap between pages.
	for _, r1 := range page1 {
		for _, r2 := range page2 {
			if r1.ID == r2.ID {
				t.Errorf("overlap: row %s appears in both page 1 and page 2", r1.ID)
			}
		}
	}

	// Page 3: should have 1 remaining.
	cursor2 := page2[len(page2)-1]
	page3, err := s.ListAuditEntries(ctx, store.AuditListParams{
		OrgID:           orgID,
		After:           time.Now().Add(-1 * time.Hour),
		Before:          time.Now().Add(1 * time.Hour),
		CursorCreatedAt: &cursor2.CreatedAt,
		CursorID:        &cursor2.ID,
		PageSize:        2,
	})
	if err != nil {
		t.Fatalf("page 3: %v", err)
	}
	if len(page3) != 1 {
		t.Fatalf("page 3: got %d rows, want 1", len(page3))
	}
}

func TestListAuditEntries_ActorIDFilter(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID := seedAuditOrg(t, s, "audit-actor-filter")
	alice := uuid.New()
	bob := uuid.New()

	// Insert 2 entries from alice, 1 from bob.
	for i := 0; i < 2; i++ {
		insertAuditRow(t, s, store.AuditEntry{
			OrgID:      orgID,
			ActorID:    &alice,
			Action:     "create",
			EntityType: "alert_rule",
			EntityID:   uuid.New().String(),
			Success:    true,
		})
	}
	insertAuditRow(t, s, store.AuditEntry{
		OrgID:      orgID,
		ActorID:    &bob,
		Action:     "delete",
		EntityType: "channel",
		EntityID:   uuid.New().String(),
		Success:    true,
	})

	// Filter by alice — should get 2.
	rows, err := s.ListAuditEntries(ctx, store.AuditListParams{
		OrgID:    orgID,
		ActorID:  &alice,
		After:    time.Now().Add(-1 * time.Hour),
		Before:   time.Now().Add(1 * time.Hour),
		PageSize: 100,
	})
	if err != nil {
		t.Fatalf("list by alice: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("alice rows: got %d, want 2", len(rows))
	}

	// Filter by bob — should get 1.
	rows, err = s.ListAuditEntries(ctx, store.AuditListParams{
		OrgID:    orgID,
		ActorID:  &bob,
		After:    time.Now().Add(-1 * time.Hour),
		Before:   time.Now().Add(1 * time.Hour),
		PageSize: 100,
	})
	if err != nil {
		t.Fatalf("list by bob: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("bob rows: got %d, want 1", len(rows))
	}
}

func TestListAuditEntries_EntityTypeAndActionFilter(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID := seedAuditOrg(t, s, "audit-type-filter")
	actorID := uuid.New()

	insertAuditRow(t, s, store.AuditEntry{
		OrgID: orgID, ActorID: &actorID, Action: "create", EntityType: "alert_rule",
		EntityID: uuid.New().String(), Success: true,
	})
	insertAuditRow(t, s, store.AuditEntry{
		OrgID: orgID, ActorID: &actorID, Action: "delete", EntityType: "channel",
		EntityID: uuid.New().String(), Success: true,
	})
	insertAuditRow(t, s, store.AuditEntry{
		OrgID: orgID, ActorID: &actorID, Action: "update", EntityType: "alert_rule",
		EntityID: uuid.New().String(), Success: true,
	})

	// Filter by entity_type only.
	rows, err := s.ListAuditEntries(ctx, store.AuditListParams{
		OrgID: orgID, EntityType: "alert_rule",
		After: time.Now().Add(-1 * time.Hour), Before: time.Now().Add(1 * time.Hour),
		PageSize: 100,
	})
	if err != nil {
		t.Fatalf("filter entity_type: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("alert_rule rows: got %d, want 2", len(rows))
	}

	// Filter by action only.
	rows, err = s.ListAuditEntries(ctx, store.AuditListParams{
		OrgID: orgID, Action: "create",
		After: time.Now().Add(-1 * time.Hour), Before: time.Now().Add(1 * time.Hour),
		PageSize: 100,
	})
	if err != nil {
		t.Fatalf("filter action: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("create rows: got %d, want 1", len(rows))
	}

	// Filter by both.
	rows, err = s.ListAuditEntries(ctx, store.AuditListParams{
		OrgID: orgID, EntityType: "alert_rule", Action: "update",
		After: time.Now().Add(-1 * time.Hour), Before: time.Now().Add(1 * time.Hour),
		PageSize: 100,
	})
	if err != nil {
		t.Fatalf("filter both: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("alert_rule+update rows: got %d, want 1", len(rows))
	}
}
