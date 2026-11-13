// ABOUTME: HTTP handler for listing alert events with optional filters and, on request, CVE and rule context.
// ABOUTME: Alert events are created by the evaluator worker; this handler provides read-only access.
package api

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/store"
)

type alertEventEntry struct {
	ID               string `json:"id"`
	RuleID           string `json:"rule_id"`
	CveID            string `json:"cve_id"`
	MaterialHash     string `json:"material_hash"`
	LastMatchState   bool   `json:"last_match_state"`
	SuppressDelivery bool   `json:"suppress_delivery"`
	FirstFiredAt     string `json:"first_fired_at"`
	LastFiredAt      string `json:"last_fired_at"`
	TimesFired       int32  `json:"times_fired"`

	CVE  *AlertEventCVEContext  `json:"cve,omitempty" doc:"With expand=cve: the CVE's fields as held now. Absent when the CVE is not in the corpus."`
	Rule *AlertEventRuleContext `json:"rule,omitempty" doc:"With expand=rule: the rule's name and the watchlist items that match the CVE."`
}

// AlertEventCVEContext is the CVE context of an alert event, read with the list.
type AlertEventCVEContext struct {
	Status      *string  `json:"status" doc:"The CVE's status as the feed sent it."`
	Severity    *string  `json:"severity" doc:"Severity as the feed sent it; compare case-insensitively."`
	CVSSv3Score *float64 `json:"cvss_v3_score" doc:"CVSS v3 base score."`
	CVSSv4Score *float64 `json:"cvss_v4_score" doc:"CVSS v4 base score."`
	InCISAKEV   bool     `json:"in_cisa_kev" doc:"Whether the CVE is in the CISA Known Exploited Vulnerabilities catalog."`
	EPSSScore   *float64 `json:"epss_score" doc:"EPSS probability, 0 to 1; null when not scored."`
}

// AlertEventRuleContext is the rule context of an alert event.
type AlertEventRuleContext struct {
	Name                  string                     `json:"name" doc:"The rule's name."`
	Deleted               bool                       `json:"deleted" doc:"The rule has been deleted since the event fired."`
	MatchedWatchlistItems []AlertEventWatchlistMatch `json:"matched_watchlist_items" doc:"Items of the rule's watchlists that match the CVE, by the conditions rule evaluation uses, read now: an item added or removed since the event fired is reflected. Empty for a rule with no watchlists."`
}

// AlertEventWatchlistMatch is a watchlist item that matches an alert event's CVE.
type AlertEventWatchlistMatch struct {
	WatchlistID string  `json:"watchlist_id" format:"uuid" doc:"Watchlist ID."`
	ItemID      string  `json:"item_id" format:"uuid" doc:"Watchlist item ID."`
	ItemType    string  `json:"item_type" enum:"cve,package,cpe" doc:"Item type."`
	CveID       *string `json:"cve_id,omitempty" doc:"For a cve item: the CVE ID."`
	Ecosystem   *string `json:"ecosystem,omitempty" doc:"For a package item: the ecosystem as listed."`
	PackageName *string `json:"package_name,omitempty" doc:"For a package item: the package name as listed."`
	Namespace   *string `json:"namespace,omitempty" doc:"For a package item: the namespace, when listed."`
	CPE         *string `json:"cpe,omitempty" doc:"For a cpe item: the normalized CPE prefix."`
}

// parseAlertEventExpand reads ?expand=, a comma-separated subset of cve and rule.
func parseAlertEventExpand(r *http.Request) (expandCVE, expandRule bool, ok bool) {
	raw, present := r.URL.Query()["expand"]
	if !present {
		return false, false, true
	}
	if len(raw) != 1 {
		return false, false, false
	}
	for v := range strings.SplitSeq(raw[0], ",") {
		switch v {
		case "cve":
			expandCVE = true
		case "rule":
			expandRule = true
		default:
			return false, false, false
		}
	}
	return expandCVE, expandRule, true
}

// alertEventEntryFrom converts a store row, with any expanded context, to the response entry.
func alertEventEntryFrom(e store.AlertEventListRow) alertEventEntry {
	entry := alertEventEntry{
		ID:               e.ID.String(),
		RuleID:           e.RuleID.String(),
		CveID:            e.CveID,
		MaterialHash:     e.MaterialHash,
		LastMatchState:   e.LastMatchState,
		SuppressDelivery: e.SuppressDelivery,
		FirstFiredAt:     e.FirstFiredAt.Format(time.RFC3339),
		LastFiredAt:      e.LastFiredAt.Format(time.RFC3339),
		TimesFired:       e.TimesFired,
	}
	if c := e.CVE; c != nil {
		entry.CVE = &AlertEventCVEContext{
			Status:      c.Status,
			Severity:    c.Severity,
			CVSSv3Score: c.CVSSv3Score,
			CVSSv4Score: c.CVSSv4Score,
			InCISAKEV:   c.InCISAKEV,
			EPSSScore:   c.EPSSScore,
		}
	}
	if rule := e.Rule; rule != nil {
		matches := make([]AlertEventWatchlistMatch, 0, len(rule.WatchlistMatches))
		for _, m := range rule.WatchlistMatches {
			matches = append(matches, AlertEventWatchlistMatch{
				WatchlistID: m.WatchlistID.String(),
				ItemID:      m.ItemID.String(),
				ItemType:    m.ItemType,
				CveID:       m.CveID,
				Ecosystem:   m.Ecosystem,
				PackageName: m.PackageName,
				Namespace:   m.Namespace,
				CPE:         m.CPE,
			})
		}
		entry.Rule = &AlertEventRuleContext{Name: rule.Name, Deleted: rule.Deleted, MatchedWatchlistItems: matches}
	}
	return entry
}

type alertEventCursor struct {
	T  string `json:"t"`  // first_fired_at RFC3339Nano
	ID string `json:"id"` // UUID tiebreaker
}

// listAlertEventsHandler handles GET /api/v1/orgs/{org_id}/alert-events.
// Optional filters: ?rule_id=, ?cve_id=, ?last_match_state=, ?since=.
// ?since= keeps events whose most recent fire is at or after the given time.
// Cursor-based pagination on (first_fired_at DESC, id DESC) via ?cursor= parameter.
func (srv *Server) listAlertEventsHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}

	const limit = 100
	p := store.ListAlertEventsParams{Limit: limit + 1}

	expandCVE, expandRule, ok := parseAlertEventExpand(r)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid expand (comma-separated cve, rule)")
		return
	}
	p.ExpandCVE, p.ExpandRule = expandCVE, expandRule

	if s := r.URL.Query().Get("rule_id"); s != "" {
		id, err := uuid.Parse(s)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid rule_id")
			return
		}
		p.RuleID = &id
	}
	if s := r.URL.Query().Get("cve_id"); s != "" {
		p.CveID = &s
	}
	if s := r.URL.Query().Get("last_match_state"); s != "" {
		v := s == "true"
		p.LastMatchState = &v
	}
	if s := r.URL.Query().Get("since"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid since (RFC3339)")
			return
		}
		p.Since = &t
	}
	if c := r.URL.Query().Get("cursor"); c != "" {
		var cur alertEventCursor
		if err := decodePageCursor(c, &cur); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		t, err := time.Parse(time.RFC3339Nano, cur.T)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		id, err := uuid.Parse(cur.ID)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		p.AfterTime = &t
		p.AfterID = &id
	}

	events, err := srv.store.ListAlertEvents(r.Context(), orgID, p)
	if err != nil {
		slog.ErrorContext(r.Context(), "list alert events", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	var cursor string
	if len(events) > limit {
		events = events[:limit]
		last := events[len(events)-1]
		cursor = encodePageCursor(alertEventCursor{
			T:  last.FirstFiredAt.UTC().Format(time.RFC3339Nano),
			ID: last.ID.String(),
		})
	}

	entries := make([]alertEventEntry, 0, len(events))
	for _, e := range events {
		entries = append(entries, alertEventEntryFrom(e))
	}
	writeList(w, entries, cursor)
}
