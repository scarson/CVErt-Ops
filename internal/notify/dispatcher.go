// ABOUTME: Dispatcher fans out alert events to notification delivery rows via debounced upsert.
// ABOUTME: Fanout builds a CVE snapshot and calls UpsertDelivery for each channel bound to a rule.
package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/store"
)

// cveSnapshot is the alert delivery payload for a single CVE match.
type cveSnapshot struct {
	CVEID       string   `json:"cve_id"`
	Severity    *string  `json:"severity,omitempty"`
	CVSSV3Score *float64 `json:"cvss_v3_score,omitempty"`
	CVSSV4Score *float64 `json:"cvss_v4_score,omitempty"`
	EPSSScore   *float64 `json:"epss_score,omitempty"`
	Description string   `json:"description_primary,omitempty"`

	ExploitAvail bool `json:"exploit_available"`
	InCISAKEV    bool `json:"in_cisa_kev"`
}

// Dispatcher fans out alert events to notification delivery rows.
type Dispatcher struct {
	st              *store.Store
	debounceSeconds int
}

// NewDispatcher creates a Dispatcher backed by st.
// debounceSeconds controls the UpsertDelivery window: 0 means deliver immediately.
func NewDispatcher(st *store.Store, debounceSeconds int) *Dispatcher {
	return &Dispatcher{st: st, debounceSeconds: debounceSeconds}
}

// Fanout creates or appends to pending delivery rows for all channels bound to ruleID.
// It fetches a CVE snapshot and calls UpsertDelivery for each active channel.
// Per-channel upsert errors are logged and do not abort remaining channels — Fanout
// returns nil even when all upserts fail; the caller's job is to fire and forget.
// Returns an error only if ListActiveChannelsForFanout fails or JSON marshaling fails.
func (d *Dispatcher) Fanout(ctx context.Context, orgID, ruleID uuid.UUID, cveID string) error {
	channels, err := d.st.ListActiveChannelsForFanout(ctx, ruleID, orgID)
	if err != nil {
		return fmt.Errorf("fanout: list channels: %w", err)
	}
	if len(channels) == 0 {
		return nil
	}

	snap := d.buildSnapshot(ctx, cveID)

	payload, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("fanout: marshal snapshot: %w", err)
	}

	for _, ch := range channels {
		if err := d.st.UpsertDelivery(ctx, orgID, ruleID, ch.ID, payload, d.debounceSeconds); err != nil {
			slog.ErrorContext(ctx, "fanout: upsert delivery failed",
				"org_id", orgID,
				"rule_id", ruleID,
				"channel_id", ch.ID,
				"cve_id", cveID,
				"error", err,
			)
		}
	}

	return nil
}

// buildSnapshot fetches a CVE snapshot from the database. If the CVE does not exist,
// it logs a warning and returns a minimal snapshot containing only the cve_id.
func (d *Dispatcher) buildSnapshot(ctx context.Context, cveID string) cveSnapshot {
	row, err := d.st.GetCVESnapshot(ctx, cveID)
	if err != nil {
		slog.WarnContext(ctx, "fanout: get cve snapshot failed, using minimal snapshot",
			"cve_id", cveID,
			"error", err,
		)
		return cveSnapshot{CVEID: cveID}
	}
	if row == nil {
		slog.WarnContext(ctx, "fanout: cve not found, using minimal snapshot",
			"cve_id", cveID,
		)
		return cveSnapshot{CVEID: cveID}
	}

	snap := cveSnapshot{
		CVEID:        row.CveID,
		ExploitAvail: row.ExploitAvailable,
		InCISAKEV:    row.InCisaKev,
	}
	if row.Severity.Valid {
		snap.Severity = &row.Severity.String
	}
	if row.CvssV3Score.Valid {
		snap.CVSSV3Score = &row.CvssV3Score.Float64
	}
	if row.CvssV4Score.Valid {
		snap.CVSSV4Score = &row.CvssV4Score.Float64
	}
	if row.EpssScore.Valid {
		snap.EPSSScore = &row.EpssScore.Float64
	}
	if row.DescriptionPrimary.Valid {
		snap.Description = row.DescriptionPrimary.String
	}

	return snap
}
