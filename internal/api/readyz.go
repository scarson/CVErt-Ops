// ABOUTME: Readiness probe handler for /readyz — checks DB, migrations, and worker status.
// ABOUTME: Returns 200 when all checks pass, 503 when any critical check fails.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"runtime"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// readyzHandler returns a readiness probe handler that checks database
// connectivity, migration currency, and worker goroutine count.
func readyzHandler(db *pgxpool.Pool, expectedSchemaVersion int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ready := true

		// ── Database connectivity ────────────────────────────────────────
		var dbStatus string
		var dbLatencyMS int64
		if db == nil {
			dbStatus = "down"
			ready = false
		} else {
			start := time.Now()
			if err := db.Ping(r.Context()); err != nil {
				slog.WarnContext(r.Context(), "readyz: db ping failed", "error", err)
				dbStatus = "down"
				ready = false
			} else {
				dbLatencyMS = time.Since(start).Milliseconds()
				dbStatus = "up"
			}
		}

		// ── Migration currency ───────────────────────────────────────────
		var migStatus string
		var migVersion int
		if db == nil {
			migStatus = "unknown"
			ready = false
		} else {
			err := db.QueryRow(r.Context(),
				"SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1",
			).Scan(&migVersion)
			if err != nil {
				slog.WarnContext(r.Context(), "readyz: migration version query failed", "error", err)
				migStatus = "unknown"
				ready = false
			} else if migVersion != expectedSchemaVersion {
				migStatus = "behind"
				ready = false
			} else {
				migStatus = "current"
			}
		}

		// ── Worker goroutines ────────────────────────────────────────────
		goroutines := runtime.NumGoroutine()
		workerStatus := "running"
		if goroutines <= 0 {
			workerStatus = "stopped"
			ready = false
		}

		// ── Response ─────────────────────────────────────────────────────
		status := "ready"
		statusCode := http.StatusOK
		if !ready {
			status = "not_ready"
			statusCode = http.StatusServiceUnavailable
		}

		resp := map[string]any{
			"status": status,
			"checks": map[string]any{
				"database": map[string]any{
					"status":     dbStatus,
					"latency_ms": dbLatencyMS,
				},
				"migrations": map[string]any{
					"status":  migStatus,
					"version": migVersion,
				},
				"worker": map[string]any{
					"status":     workerStatus,
					"goroutines": goroutines,
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			slog.ErrorContext(r.Context(), "readyz: failed to encode response", "error", err)
		}
	}
}
