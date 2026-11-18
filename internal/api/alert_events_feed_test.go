// ABOUTME: Integration tests for GET .../alert-events?order=asc, the polling feed, called with an API key.
// ABOUTME: Covers paging with after and limit, resuming from next_cursor, filters with expand, and parameter validation.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/store"
)

type feedPage struct {
	Items []struct {
		CveID string `json:"cve_id"`
	} `json:"items"`
	NextCursor string `json:"next_cursor"`
}

func (f *expandAPIFixture) feedPage(t *testing.T, query string) feedPage {
	t.Helper()
	status, body := f.list(t, query)
	if status != http.StatusOK {
		t.Fatalf("%s: status = %d, want 200 (body %s)", query, status, body)
	}
	var page feedPage
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatalf("%s: decode: %v (body %s)", query, err, body)
	}
	return page
}

// TestAlertEvents_FeedPollsFromCursor polls the feed as a script does: pages of two,
// each request resuming from the last next_cursor, until it has every event.
func TestAlertEvents_FeedPollsFromCursor(t *testing.T) {
	t.Parallel()
	f := newExpandAPIFixture(t) // holds one event, for expandCVEID
	ctx := context.Background()
	want := []string{expandCVEID, "CVE-2024-72002", "CVE-2024-72003"}
	for _, cve := range want[1:] {
		if _, err := f.db.InsertAlertEvent(ctx, f.orgID, f.ruleID, cve, "hash-1", false); err != nil {
			t.Fatalf("insert event: %v", err)
		}
	}

	var seen []string
	cursor := ""
	for {
		q := "?order=asc&limit=2"
		if cursor != "" {
			q += "&after=" + url.QueryEscape(cursor)
		}
		page := f.feedPage(t, q)
		if len(page.Items) > 2 {
			t.Fatalf("page of %d items, want at most limit 2", len(page.Items))
		}
		for _, it := range page.Items {
			seen = append(seen, it.CveID)
		}
		if len(page.Items) > 0 && page.NextCursor == "" {
			t.Fatalf("page with items has no next_cursor")
		}
		if page.NextCursor != "" {
			cursor = page.NextCursor
		}
		if len(page.Items) < 2 {
			break
		}
	}
	if len(seen) != len(want) || seen[0] != want[0] || seen[1] != want[1] || seen[2] != want[2] {
		t.Fatalf("seen %v, want %v", seen, want)
	}

	// Caught up: an empty page that hands back the same cursor.
	page := f.feedPage(t, "?order=asc&after="+url.QueryEscape(cursor))
	if len(page.Items) != 0 || page.NextCursor != cursor {
		t.Errorf("poll after catching up = %d items, next_cursor %q; want 0 items and the same cursor", len(page.Items), page.NextCursor)
	}
}

// TestAlertEvents_DescendingHonoursLimit pages the default order with limit and cursor.
func TestAlertEvents_DescendingHonoursLimit(t *testing.T) {
	t.Parallel()
	f := newExpandAPIFixture(t)
	if _, err := f.db.InsertAlertEvent(context.Background(), f.orgID, f.ruleID, "CVE-2024-72009", "hash-1", false); err != nil {
		t.Fatalf("insert event: %v", err)
	}
	first := f.feedPage(t, "?limit=1")
	if len(first.Items) != 1 || first.NextCursor == "" {
		t.Fatalf("first page = %d items, next_cursor %q; want 1 item and a cursor", len(first.Items), first.NextCursor)
	}
	second := f.feedPage(t, "?limit=1&cursor="+url.QueryEscape(first.NextCursor))
	if len(second.Items) != 1 || second.Items[0].CveID == first.Items[0].CveID || second.NextCursor != "" {
		t.Errorf("second page = %+v, want the other event and no cursor", second)
	}
}

func TestAlertEvents_FeedParameterValidation(t *testing.T) {
	t.Parallel()
	f := newExpandAPIFixture(t)
	descCursor := encodePageCursor(alertEventCursor{T: time.Now().UTC().Format(time.RFC3339Nano), ID: f.ruleID.String()})
	feedCursor := encodeAlertEventFeedCursor(12345)
	for _, q := range []string{
		"?order=sideways",
		"?after=" + feedCursor,            // after needs order=asc
		"?order=desc&after=" + feedCursor, // likewise
		"?order=asc&cursor=" + descCursor, // cursor pages the descending order
		"?order=asc&after=not-a-cursor",   // undecodable
		"?order=asc&after=" + descCursor,  // a descending cursor is not a feed position
		"?order=asc&after=" + encodePageCursor(alertEventFeedCursor{V: 2, Seq: 5}), // unknown cursor format
		"?limit=0",
		"?limit=1001",
		"?expand=rule&limit=101", // expand=rule pages are capped at 100
		"?order=asc&expand=cve,rule&limit=101",
		"?order=asc&limit=abc",
	} {
		if status, body := f.list(t, q); status != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (body %s)", q, status, body)
		}
	}
	for _, q := range []string{
		"?order=asc", "?order=asc&limit=1000", "?order=desc&limit=1", "?order=asc&after=" + feedCursor,
		"?order=asc&after=" + encodeAlertEventFeedCursor(-3), // history positions are negative
		"?expand=rule&limit=100", "?expand=cve&limit=1000",
		"?order=asc&rule_id=" + f.ruleID.String() + "&cve_id=" + expandCVEID,
		"?order=asc&last_match_state=true", "?order=asc&since=2026-01-01T00:00:00Z",
	} {
		if status, body := f.list(t, q); status != http.StatusOK {
			t.Errorf("%s: status = %d, want 200 (body %s)", q, status, body)
		}
	}
}

// TestAlertEvents_FeedWithRuleFilterAndExpand polls the feed for one rule, with
// context embedded, as an agent watching a single rule would.
func TestAlertEvents_FeedWithRuleFilterAndExpand(t *testing.T) {
	t.Parallel()
	f := newExpandAPIFixture(t)
	ctx := context.Background()
	other, err := f.db.CreateAlertRule(ctx, f.orgID, store.CreateAlertRuleParams{
		Name: "Other", Logic: "and", Conditions: json.RawMessage(`[{"field":"severity","operator":"eq","value":"low"}]`), Status: "active",
	})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	if _, err := f.db.InsertAlertEvent(ctx, f.orgID, other.ID, expandCVEID, "hash-1", false); err != nil {
		t.Fatalf("insert event: %v", err)
	}

	status, body := f.list(t, "?order=asc&expand=cve,rule&rule_id="+f.ruleID.String())
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", status, body)
	}
	var page struct {
		Items []struct {
			RuleID string `json:"rule_id"`
			CVE    *struct {
				Severity *string `json:"severity"`
			} `json:"cve"`
			Rule *struct {
				Name string `json:"name"`
			} `json:"rule"`
		} `json:"items"`
		NextCursor string `json:"next_cursor"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatalf("decode: %v (body %s)", err, body)
	}
	if len(page.Items) != 1 || page.Items[0].RuleID != f.ruleID.String() || page.NextCursor == "" {
		t.Fatalf("page = %s, want only the filtered rule's event and a cursor", body)
	}
	if e := page.Items[0]; e.CVE == nil || e.CVE.Severity == nil || e.Rule == nil || e.Rule.Name != "Python deps" {
		t.Errorf("event context missing: %s", body)
	}
}
