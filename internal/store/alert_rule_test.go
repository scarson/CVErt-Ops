// ABOUTME: Integration tests for store/alert_rule.go -- alert rule, run, and event CRUD.
// ABOUTME: Uses testutil.NewTestDB; each test runs in its own container (t.Parallel).
package store_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// helpers

func mustCreateAlertRule(t *testing.T, s *testutil.TestDB, ctx context.Context, orgID uuid.UUID, name string) *store.AlertRuleRow {
	t.Helper()
	r, err := s.CreateAlertRule(ctx, orgID, store.CreateAlertRuleParams{
		Name:       name,
		Logic:      "and",
		Conditions: json.RawMessage(`[{"field":"severity","operator":"eq","value":"critical"}]`),
		Status:     "draft",
	})
	if err != nil {
		t.Fatalf("CreateAlertRule(%q): %v", name, err)
	}
	return r
}

// tests

func TestCreateAndGetAlertRule(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "AROrg1")

	r, err := s.CreateAlertRule(ctx, org.ID, store.CreateAlertRuleParams{
		Name:             "Critical CVEs",
		Logic:            "and",
		Conditions:       json.RawMessage(`[{"field":"severity","operator":"eq","value":"critical"}]`),
		HasEpssCondition: false,
		IsEpssOnly:       false,
		Status:           "draft",
	})
	if err != nil {
		t.Fatalf("CreateAlertRule: %v", err)
	}
	if r.Name != "Critical CVEs" {
		t.Errorf("Name = %q, want Critical CVEs", r.Name)
	}
	if r.Status != "draft" {
		t.Errorf("Status = %q, want draft", r.Status)
	}

	got, err := s.GetAlertRule(ctx, org.ID, r.ID)
	if err != nil {
		t.Fatalf("GetAlertRule: %v", err)
	}
	if got == nil {
		t.Fatal("GetAlertRule returned nil for existing rule")
	}
	if got.ID != r.ID {
		t.Errorf("ID mismatch: got %v, want %v", got.ID, r.ID)
	}
}

func TestGetAlertRule_WrongOrgReturnsNil(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1, _ := s.CreateOrg(ctx, "AROrg2a")
	org2, _ := s.CreateOrg(ctx, "AROrg2b")
	r := mustCreateAlertRule(t, s, ctx, org1.ID, "Rule A")

	got, err := s.GetAlertRule(ctx, org2.ID, r.ID)
	if err != nil {
		t.Fatalf("GetAlertRule(wrong org): %v", err)
	}
	if got != nil {
		t.Error("GetAlertRule with wrong org should return nil")
	}
}

func TestUpdateAlertRule(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "AROrg3")
	r := mustCreateAlertRule(t, s, ctx, org.ID, "Original")

	updated, err := s.UpdateAlertRule(ctx, org.ID, r.ID, store.UpdateAlertRuleParams{
		Name:             "Updated",
		Logic:            "or",
		Conditions:       json.RawMessage(`[{"field":"in_cisa_kev","operator":"eq","value":true}]`),
		HasEpssCondition: false,
		IsEpssOnly:       false,
		Status:           "activating",
	})
	if err != nil {
		t.Fatalf("UpdateAlertRule: %v", err)
	}
	if updated == nil {
		t.Fatal("UpdateAlertRule returned nil")
	}
	if updated.Name != "Updated" {
		t.Errorf("Name = %q, want Updated", updated.Name)
	}
	if updated.Logic != "or" {
		t.Errorf("Logic = %q, want or", updated.Logic)
	}
}

func TestSoftDeleteAlertRule(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "AROrg4")
	r := mustCreateAlertRule(t, s, ctx, org.ID, "DeleteMe")

	if err := s.SoftDeleteAlertRule(ctx, org.ID, r.ID); err != nil {
		t.Fatalf("SoftDeleteAlertRule: %v", err)
	}

	got, err := s.GetAlertRule(ctx, org.ID, r.ID)
	if err != nil {
		t.Fatalf("GetAlertRule(deleted): %v", err)
	}
	if got != nil {
		t.Error("GetAlertRule should return nil for soft-deleted rule")
	}
}

func TestSetAlertRuleStatus(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "AROrg5")
	r := mustCreateAlertRule(t, s, ctx, org.ID, "StatusRule")

	if err := s.SetAlertRuleStatus(ctx, org.ID, r.ID, "active"); err != nil {
		t.Fatalf("SetAlertRuleStatus: %v", err)
	}

	got, _ := s.GetAlertRule(ctx, org.ID, r.ID)
	if got == nil {
		t.Fatal("GetAlertRule returned nil after status change")
	}
	if got.Status != "active" {
		t.Errorf("Status = %q, want active", got.Status)
	}
}

func TestInsertAlertEvent_DeduplicatesOnConflict(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "AROrg6")
	r := mustCreateAlertRule(t, s, ctx, org.ID, "DedupeRule")

	// First insert returns a new ID.
	id1, err := s.InsertAlertEvent(ctx, org.ID, r.ID, "CVE-2024-0001", "hash1", false)
	if err != nil {
		t.Fatalf("InsertAlertEvent (first): %v", err)
	}
	if id1 == uuid.Nil {
		t.Error("first insert should return a non-nil UUID")
	}

	// Second insert with same (org, rule, cve, hash) returns zero UUID (DO NOTHING).
	id2, err := s.InsertAlertEvent(ctx, org.ID, r.ID, "CVE-2024-0001", "hash1", false)
	if err != nil {
		t.Fatalf("InsertAlertEvent (duplicate): %v", err)
	}
	if id2 != uuid.Nil {
		t.Errorf("duplicate insert should return uuid.Nil, got %v", id2)
	}
}

func TestResolveAlertEvent(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "AROrg7")
	r := mustCreateAlertRule(t, s, ctx, org.ID, "ResolveRule")

	_, _ = s.InsertAlertEvent(ctx, org.ID, r.ID, "CVE-2024-0002", "hash2", false)

	// Before resolving: should appear in unresolved list.
	unresolvedBefore, err := s.GetUnresolvedAlertEventCVEs(ctx, r.ID, org.ID)
	if err != nil {
		t.Fatalf("GetUnresolvedAlertEventCVEs: %v", err)
	}
	if len(unresolvedBefore) != 1 || unresolvedBefore[0] != "CVE-2024-0002" {
		t.Errorf("unresolved before = %v, want [CVE-2024-0002]", unresolvedBefore)
	}

	if err := s.ResolveAlertEvent(ctx, r.ID, org.ID, "CVE-2024-0002"); err != nil {
		t.Fatalf("ResolveAlertEvent: %v", err)
	}

	unresolvedAfter, err := s.GetUnresolvedAlertEventCVEs(ctx, r.ID, org.ID)
	if err != nil {
		t.Fatalf("GetUnresolvedAlertEventCVEs after resolve: %v", err)
	}
	if len(unresolvedAfter) != 0 {
		t.Errorf("unresolved after = %v, want []", unresolvedAfter)
	}
}

func TestInsertAndUpdateAlertRuleRun(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "AROrg8")
	r := mustCreateAlertRule(t, s, ctx, org.ID, "RunRule")

	run, err := s.InsertAlertRuleRun(ctx, r.ID, org.ID, "batch")
	if err != nil {
		t.Fatalf("InsertAlertRuleRun: %v", err)
	}
	if run.Status != "running" {
		t.Errorf("initial status = %q, want running", run.Status)
	}

	if err := s.UpdateAlertRuleRun(ctx, run.ID, "complete", 100, 5, nil); err != nil {
		t.Fatalf("UpdateAlertRuleRun: %v", err)
	}
}

func TestListActiveRulesForEvaluation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "AROrg9")
	r := mustCreateAlertRule(t, s, ctx, org.ID, "ActiveRule")
	_ = s.SetAlertRuleStatus(ctx, org.ID, r.ID, "active")

	// Also create a draft rule — should not appear.
	_ = mustCreateAlertRule(t, s, ctx, org.ID, "DraftRule")

	rules, err := s.ListActiveRulesForEvaluation(ctx)
	if err != nil {
		t.Fatalf("ListActiveRulesForEvaluation: %v", err)
	}

	found := false
	for _, rule := range rules {
		if rule.ID == r.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("active rule %v not found in ListActiveRulesForEvaluation", r.ID)
	}

	for _, rule := range rules {
		if rule.Status != "active" {
			t.Errorf("non-active rule %v (status=%q) found in active list", rule.ID, rule.Status)
		}
		if rule.IsEpssOnly {
			t.Errorf("EPSS-only rule %v should not be in evaluation list", rule.ID)
		}
	}
}

func TestListAlertRules_StatusFilter(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "AROrg10")
	r1 := mustCreateAlertRule(t, s, ctx, org.ID, "Draft1")
	r2 := mustCreateAlertRule(t, s, ctx, org.ID, "Active1")
	_ = s.SetAlertRuleStatus(ctx, org.ID, r2.ID, "active")

	// No filter: both rules returned.
	all, err := s.ListAlertRules(ctx, org.ID, nil, nil, nil, 10)
	if err != nil {
		t.Fatalf("ListAlertRules(all): %v", err)
	}
	if len(all) < 2 {
		t.Errorf("all rules: got %d, want >= 2", len(all))
	}

	// Filter by status=active.
	activeStr := "active"
	active, err := s.ListAlertRules(ctx, org.ID, &activeStr, nil, nil, 10)
	if err != nil {
		t.Fatalf("ListAlertRules(active): %v", err)
	}
	for _, rule := range active {
		if rule.Status != "active" {
			t.Errorf("rule %v has status %q, want active", rule.ID, rule.Status)
		}
	}
	_ = r1
}

func TestListAlertEvents_Filters(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "AROrg11")
	r1 := mustCreateAlertRule(t, s, ctx, org.ID, "EventRule1")
	r2 := mustCreateAlertRule(t, s, ctx, org.ID, "EventRule2")

	_, _ = s.InsertAlertEvent(ctx, org.ID, r1.ID, "CVE-2024-0010", "h10", false)
	_, _ = s.InsertAlertEvent(ctx, org.ID, r1.ID, "CVE-2024-0011", "h11", false)
	_, _ = s.InsertAlertEvent(ctx, org.ID, r2.ID, "CVE-2024-0012", "h12", false)

	// Filter by rule_id.
	events, err := s.ListAlertEvents(ctx, org.ID, store.ListAlertEventsParams{
		RuleID: &r1.ID,
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("ListAlertEvents(by rule): %v", err)
	}
	if len(events) != 2 {
		t.Errorf("by rule_id: got %d, want 2", len(events))
	}

	// Filter by cve_id.
	cveID := "CVE-2024-0010"
	events2, err := s.ListAlertEvents(ctx, org.ID, store.ListAlertEventsParams{
		CveID: &cveID,
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("ListAlertEvents(by cve_id): %v", err)
	}
	if len(events2) != 1 {
		t.Errorf("by cve_id: got %d, want 1", len(events2))
	}

	// No filter: all 3 events.
	all, err := s.ListAlertEvents(ctx, org.ID, store.ListAlertEventsParams{Limit: 10})
	if err != nil {
		t.Fatalf("ListAlertEvents(all): %v", err)
	}
	if len(all) != 3 {
		t.Errorf("all: got %d, want 3", len(all))
	}
}
