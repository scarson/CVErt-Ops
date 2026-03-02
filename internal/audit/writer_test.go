// ABOUTME: Integration tests for the audit Writer using testcontainers Postgres.
// ABOUTME: Verifies insert, redaction, system actions, and non-blocking error handling.
package audit_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/audit"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestWriter_CreateAction(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID := seedOrg(t, db, "audit-create")
	actorID := uuid.New()

	w := audit.NewWriter(db.Store, slog.Default())
	w.Log(ctx, audit.Entry{
		OrgID:      orgID,
		ActorID:    &actorID,
		ActorEmail: "actor@example.com",
		Action:     "create",
		EntityType: "alert_rule",
		EntityID:   uuid.New().String(),
		EntityName: "My Rule",
		Success:    true,
		NewState:   map[string]any{"name": "My Rule", "enabled": true},
	})

	// Wait briefly for the async goroutine.
	time.Sleep(500 * time.Millisecond)

	rows := listAuditRows(t, db, orgID)
	if len(rows) != 1 {
		t.Fatalf("expected 1 audit row, got %d", len(rows))
	}
	r := rows[0]
	if r.Action != "create" {
		t.Errorf("action: got %s, want create", r.Action)
	}
	if r.EntityType != "alert_rule" {
		t.Errorf("entity_type: got %s, want alert_rule", r.EntityType)
	}
	if !r.Success {
		t.Error("success: got false, want true")
	}
	if r.OldState != nil {
		t.Errorf("old_state: got %s, want nil", string(r.OldState))
	}
	if r.NewState == nil {
		t.Fatal("new_state: got nil, want populated")
	}
}

func TestWriter_UpdateAction(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID := seedOrg(t, db, "audit-update")
	actorID := uuid.New()

	w := audit.NewWriter(db.Store, slog.Default())
	w.Log(ctx, audit.Entry{
		OrgID:      orgID,
		ActorID:    &actorID,
		ActorEmail: "editor@example.com",
		Action:     "update",
		EntityType: "channel",
		EntityID:   uuid.New().String(),
		EntityName: "Slack Channel",
		Success:    true,
		OldState:   map[string]any{"signing_secret": "old-secret", "url": "https://hooks.slack.com/old/path"},
		NewState:   map[string]any{"signing_secret": "new-secret", "url": "https://hooks.slack.com/new/path"},
	})

	time.Sleep(500 * time.Millisecond)

	rows := listAuditRows(t, db, orgID)
	if len(rows) != 1 {
		t.Fatalf("expected 1 audit row, got %d", len(rows))
	}
	r := rows[0]

	// Verify redaction was applied.
	var oldState map[string]any
	if err := json.Unmarshal(r.OldState, &oldState); err != nil {
		t.Fatalf("unmarshal old_state: %v", err)
	}
	if oldState["signing_secret"] != "[REDACTED]" {
		t.Errorf("old signing_secret: got %v, want [REDACTED]", oldState["signing_secret"])
	}
	if oldState["url"] != "https://hooks.slack.com/***" {
		t.Errorf("old url: got %v, want https://hooks.slack.com/***", oldState["url"])
	}

	var newState map[string]any
	if err := json.Unmarshal(r.NewState, &newState); err != nil {
		t.Fatalf("unmarshal new_state: %v", err)
	}
	if newState["signing_secret"] != "[REDACTED]" {
		t.Errorf("new signing_secret: got %v, want [REDACTED]", newState["signing_secret"])
	}
}

func TestWriter_DeleteAction(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID := seedOrg(t, db, "audit-delete")
	actorID := uuid.New()

	w := audit.NewWriter(db.Store, slog.Default())
	w.Log(ctx, audit.Entry{
		OrgID:      orgID,
		ActorID:    &actorID,
		ActorEmail: "deleter@example.com",
		Action:     "delete",
		EntityType: "watchlist",
		EntityID:   uuid.New().String(),
		EntityName: "Old Watchlist",
		Success:    true,
		OldState:   map[string]any{"name": "Old Watchlist"},
	})

	time.Sleep(500 * time.Millisecond)

	rows := listAuditRows(t, db, orgID)
	if len(rows) != 1 {
		t.Fatalf("expected 1 audit row, got %d", len(rows))
	}
	r := rows[0]
	if r.Action != "delete" {
		t.Errorf("action: got %s, want delete", r.Action)
	}
	if r.NewState != nil {
		t.Errorf("new_state: got %s, want nil", string(r.NewState))
	}
	if r.OldState == nil {
		t.Fatal("old_state: got nil, want populated")
	}
}

func TestWriter_DeniedAction(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID := seedOrg(t, db, "audit-denied")
	actorID := uuid.New()

	w := audit.NewWriter(db.Store, slog.Default())
	w.Log(ctx, audit.Entry{
		OrgID:      orgID,
		ActorID:    &actorID,
		ActorEmail: "denied@example.com",
		Action:     "create",
		EntityType: "alert_rule",
		EntityID:   "",
		Success:    false,
		Metadata:   map[string]any{"reason": "tier_limit"},
	})

	time.Sleep(500 * time.Millisecond)

	rows := listAuditRows(t, db, orgID)
	if len(rows) != 1 {
		t.Fatalf("expected 1 audit row, got %d", len(rows))
	}
	r := rows[0]
	if r.Success {
		t.Error("success: got true, want false")
	}
	if r.Metadata == nil {
		t.Fatal("metadata: got nil, want populated")
	}
}

func TestWriter_SystemAction(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID := seedOrg(t, db, "audit-system")

	w := audit.NewWriter(db.Store, slog.Default())
	w.Log(ctx, audit.Entry{
		OrgID:      orgID,
		Action:     "delete",
		EntityType: "alert_rule",
		EntityID:   uuid.New().String(),
		EntityName: "Expired Rule",
		Success:    true,
	})

	time.Sleep(500 * time.Millisecond)

	rows := listAuditRows(t, db, orgID)
	if len(rows) != 1 {
		t.Fatalf("expected 1 audit row, got %d", len(rows))
	}
	r := rows[0]
	if r.ActorID != nil {
		t.Errorf("actor_id: got %v, want nil", r.ActorID)
	}
	if r.ActorEmail != "" {
		t.Errorf("actor_email: got %s, want empty", r.ActorEmail)
	}
}

func TestWriter_NonBlocking(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)

	// Break the audit_log table so inserts fail.
	ctx := context.Background()
	_, err := db.DB().ExecContext(ctx, `DROP TABLE audit_log CASCADE`)
	if err != nil {
		t.Fatalf("drop table: %v", err)
	}

	w := audit.NewWriter(db.Store, slog.Default())
	// This must not panic.
	w.Log(ctx, audit.Entry{
		OrgID:      uuid.New(),
		Action:     "create",
		EntityType: "test",
		EntityID:   "test-id",
		Success:    true,
	})

	// Wait for async goroutine to complete (and fail gracefully).
	time.Sleep(500 * time.Millisecond)
}

// --- test helpers ---

func seedOrg(t *testing.T, db *testutil.TestDB, name string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	var orgID uuid.UUID
	err := db.DB().QueryRowContext(ctx,
		`INSERT INTO organizations (name) VALUES ($1) RETURNING id`, name,
	).Scan(&orgID)
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	return orgID
}

func listAuditRows(t *testing.T, db *testutil.TestDB, orgID uuid.UUID) []store.AuditRow {
	t.Helper()
	rows, err := db.ListAuditEntries(context.Background(), store.AuditListParams{
		OrgID:    orgID,
		After:    time.Now().Add(-1 * time.Hour),
		Before:   time.Now().Add(1 * time.Hour),
		PageSize: 100,
	})
	if err != nil {
		t.Fatalf("list audit entries: %v", err)
	}
	return rows
}
