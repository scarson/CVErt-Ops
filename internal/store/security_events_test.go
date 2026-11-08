// ABOUTME: Integration tests for security event storage, run as the restricted application role.
// ABOUTME: cvert_ops_app holds only the grants its migrations give it, so a missing grant fails here.
package store_test

import (
	"context"
	"testing"

	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestSecurityEvents_InsertAndListAsAppRole(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	if err := db.AppStore.InsertSecurityEvent(ctx, store.InsertSecurityEventParams{
		EventType: "auth.login_failed",
		Severity:  "info",
		ActorIP:   "10.0.0.1",
	}); err != nil {
		t.Fatalf("InsertSecurityEvent: %v", err)
	}

	events, err := db.AppStore.ListSecurityEvents(ctx, "", "", "", nil, nil, nil, nil, 10)
	if err != nil {
		t.Fatalf("ListSecurityEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].EventType != "auth.login_failed" || events[0].ActorIP != "10.0.0.1" {
		t.Errorf("event = (%q, %q), want (auth.login_failed, 10.0.0.1)", events[0].EventType, events[0].ActorIP)
	}
}
