// ABOUTME: Applies the channel header scrub to seeded audit rows on real Postgres.
// ABOUTME: Runs the file as a non-superuser table owner, the case row level security restricts.
package migrations_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/golang-migrate/migrate/v4/database/multistmt"
	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/testutil"
	"github.com/scarson/cvert-ops/migrations"
)

const scrubMigrationFile = "000056_scrub_channel_headers_from_audit_log.up.sql"

// applyScrubAsTableOwner runs the migration the way the migrate command does:
// one statement at a time on one connection, split by golang-migrate's parser.
func applyScrubAsTableOwner(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	script, err := migrations.FS.ReadFile(scrubMigrationFile)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}

	// Roles are cluster-wide and test databases share a cluster.
	owner := "scrub_owner_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	for _, stmt := range []string{
		`CREATE ROLE ` + owner + ` NOSUPERUSER NOBYPASSRLS`,
		`ALTER TABLE audit_log OWNER TO ` + owner,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("open connection: %v", err)
	}
	defer conn.Close() //nolint:errcheck,gosec // G104
	if _, err := conn.ExecContext(ctx, `SET ROLE `+owner); err != nil {
		t.Fatalf("set role: %v", err)
	}
	// The connection returns to a shared pool, and the assertions read as the
	// test superuser.
	defer conn.ExecContext(ctx, `RESET ROLE`) //nolint:errcheck // test cleanup
	var execErr error
	parseErr := multistmt.Parse(bytes.NewReader(script), []byte(";"), 1<<20, func(stmt []byte) bool {
		if len(bytes.TrimSpace(stmt)) == 0 {
			return true
		}
		if _, execErr = conn.ExecContext(ctx, string(stmt)); execErr != nil {
			t.Errorf("statement %q: %v", stmt, execErr)
			return false
		}
		return true
	})
	if parseErr != nil && !errors.Is(parseErr, io.EOF) {
		t.Fatalf("parse migration: %v", parseErr)
	}
	if execErr != nil {
		t.FailNow()
	}
}

func TestMain(m *testing.M) {
	os.Exit(testutil.Run(m))
}

func TestScrubChannelHeadersFromAuditLog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.NewTestDB(t).DB()
	orgID := uuid.New()

	masked := `"[REDACTED]"`
	cases := []struct {
		name       string
		entityType string
		oldState   *string
		newState   *string
		wantOld    *string
		wantNew    *string
	}{
		{
			name:       "custom headers masked in both states, other fields kept",
			entityType: "channel",
			oldState:   new(`{"name":"Hook","url":"https://h.example.com/***","custom_headers":{"Authorization":"Bearer old","X-Team":"red"}}`),
			newState:   new(`{"name":"Hook","type":"webhook","custom_headers":{"Authorization":"Bearer new"}}`),
			wantOld:    new(`{"name":"Hook","url":"https://h.example.com/***","custom_headers":{"Authorization":` + masked + `,"X-Team":` + masked + `}}`),
			wantNew:    new(`{"name":"Hook","type":"webhook","custom_headers":{"Authorization":` + masked + `}}`),
		},
		{
			name:       "headers key used by the channel test route",
			entityType: "channel",
			newState:   new(`{"headers":{"Authorization":"Bearer test-route"}}`),
			wantNew:    new(`{"headers":{"Authorization":` + masked + `}}`),
		},
		{
			name:       "key matched without regard to case",
			entityType: "channel",
			newState:   new(`{"Custom_Headers":{"Authorization":"Bearer mixed"}}`),
			wantNew:    new(`{"Custom_Headers":{"Authorization":` + masked + `}}`),
		},
		{
			name:       "headers value that is not an object masked whole",
			entityType: "channel",
			newState:   new(`{"custom_headers":"Authorization: Bearer text"}`),
			wantNew:    new(`{"custom_headers":` + masked + `}`),
		},
		{
			name:       "empty headers object stays an object",
			entityType: "channel",
			newState:   new(`{"name":"Hook","custom_headers":{}}`),
			wantNew:    new(`{"name":"Hook","custom_headers":{}}`),
		},
		{
			name:       "old state alone holds headers",
			entityType: "channel",
			oldState:   new(`{"custom_headers":{"Authorization":"Bearer deleted"}}`),
			wantOld:    new(`{"custom_headers":{"Authorization":` + masked + `}}`),
		},
		{
			name:       "fields delivery never reads masked whole",
			entityType: "channel",
			newState:   new(`{"name":"Hook","type":"webhook","auth":"plain","extra":[{"custom_headers":{"Authorization":"Bearer nested"}}],"nested":{"custom_headers":{"Authorization":"Bearer deep"}}}`),
			wantNew:    new(`{"name":"Hook","type":"webhook","auth":` + masked + `,"extra":` + masked + `,"nested":` + masked + `}`),
		},
		{
			name:       "recipients that are not an address list masked",
			entityType: "channel",
			newState:   new(`{"recipients":{"Authorization":"Bearer private"}}`),
			wantNew:    new(`{"recipients":` + masked + `}`),
		},
		{
			name:       "config key that replaced the channel name masked",
			entityType: "channel",
			oldState:   new(`{"name":"receiver-credential"}`),
			newState:   new(`{"name":"receiver-credential"}`),
			wantOld:    new(`{"name":` + masked + `}`),
			wantNew:    new(`{"name":` + masked + `}`),
		},
		{
			name:       "renamed channel keeps its previous name",
			entityType: "channel",
			oldState:   new(`{"name":"Previous Name"}`),
			newState:   new(`{"name":"Hook"}`),
			wantOld:    new(`{"name":"Previous Name"}`),
			wantNew:    new(`{"name":"Hook"}`),
		},
		{
			name:       "deleted channel name that is not the entity name masked",
			entityType: "channel",
			oldState:   new(`{"name":"receiver-credential"}`),
			wantOld:    new(`{"name":` + masked + `}`),
		},
		{
			name:       "type outside the channel types masked",
			entityType: "channel",
			newState:   new(`{"type":"receiver-credential"}`),
			wantNew:    new(`{"type":` + masked + `}`),
		},
		{
			name:       "empty state stays an object",
			entityType: "channel",
			newState:   new(`{}`),
			wantNew:    new(`{}`),
		},
		{
			name:       "channel row without headers untouched",
			entityType: "channel",
			newState:   new(`{"name":"Hook","recipients":["ops@example.com"]}`),
			wantNew:    new(`{"name":"Hook","recipients":["ops@example.com"]}`),
		},
		{
			name:       "json null state untouched",
			entityType: "channel",
			newState:   new(`null`),
			wantNew:    new(`null`),
		},
		{
			name:       "other entity types untouched",
			entityType: "alert_rule",
			newState:   new(`{"custom_headers":{"Authorization":"not a channel"}}`),
			wantNew:    new(`{"custom_headers":{"Authorization":"not a channel"}}`),
		},
	}

	ids := make([]uuid.UUID, len(cases))
	for i, tc := range cases {
		ids[i] = uuid.New()
		if _, err := db.ExecContext(ctx,
			`INSERT INTO audit_log (id, org_id, action, entity_type, entity_id, entity_name, old_state, new_state)
			 VALUES ($1, $2, 'update', $3, 'entity', 'Hook', $4::jsonb, $5::jsonb)`,
			ids[i], orgID, tc.entityType, tc.oldState, tc.newState); err != nil {
			t.Fatalf("seed %q: %v", tc.name, err)
		}
	}

	applyScrubAsTableOwner(t, ctx, db)

	for i, tc := range cases {
		var gotOld, gotNew *string
		if err := db.QueryRowContext(ctx,
			`SELECT old_state::text, new_state::text FROM audit_log WHERE id = $1`, ids[i]).Scan(&gotOld, &gotNew); err != nil {
			t.Fatalf("read %q: %v", tc.name, err)
		}
		assertSameJSON(t, tc.name+" old_state", gotOld, tc.wantOld)
		assertSameJSON(t, tc.name+" new_state", gotNew, tc.wantNew)
	}
}

func assertSameJSON(t *testing.T, label string, got, want *string) {
	t.Helper()
	if got == nil || want == nil {
		if got != want {
			t.Errorf("%s: got %v, want %v", label, deref(got), deref(want))
		}
		return
	}
	var gotValue, wantValue any
	if err := json.Unmarshal([]byte(*got), &gotValue); err != nil {
		t.Fatalf("%s: decode stored value: %v", label, err)
	}
	if err := json.Unmarshal([]byte(*want), &wantValue); err != nil {
		t.Fatalf("%s: decode expected value: %v", label, err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Errorf("%s: got %s, want %s", label, *got, *want)
	}
}

func deref(s *string) string {
	if s == nil {
		return "<sql null>"
	}
	return *s
}
