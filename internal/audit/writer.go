// ABOUTME: Appends audit log entries with write-time secret redaction.
// ABOUTME: Non-blocking — errors are logged, never propagated to callers.
package audit

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/store"
)

// Entry represents a single audit log event. Callers construct this and pass to Writer.Log().
type Entry struct {
	OrgID      uuid.UUID
	ActorID    *uuid.UUID     // nil for system actions (retention, feed sync)
	ActorEmail string         // empty for system actions
	Action     string         // "create", "update", "delete"
	EntityType string         // "alert_rule", "channel", "watchlist", "member", "saved_search", "sso_connection"
	EntityID   string         // UUID or other identifier
	EntityName string         // denormalized for readability after entity deletion
	Success    bool           // false for 403 denied mutations
	OldState   any            // pre-mutation snapshot (nil for create)
	NewState   any            // post-mutation snapshot (nil for delete)
	Metadata   map[string]any // optional extra context
}

// Writer appends audit log entries to the database.
type Writer struct {
	store *store.Store
	log   *slog.Logger
}

// NewWriter creates a Writer backed by the given store.
func NewWriter(s *store.Store, log *slog.Logger) *Writer {
	return &Writer{store: s, log: log}
}

// Log records an audit entry. Non-blocking: fires a goroutine, errors are logged not propagated.
func (w *Writer) Log(ctx context.Context, entry Entry) {
	// Detach from request context so the goroutine survives handler return.
	ctx = context.WithoutCancel(ctx)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				w.log.Error("audit log panic", "recover", r)
			}
		}()

		storeEntry, err := w.buildStoreEntry(entry)
		if err != nil {
			w.log.Error("audit log marshal", "err", err, "entity_type", entry.EntityType, "action", entry.Action)
			return
		}

		if err := w.store.InsertAuditEntry(ctx, storeEntry); err != nil {
			w.log.Error("audit log insert", "err", err, "entity_type", entry.EntityType, "action", entry.Action)
		}
	}()
}

// buildStoreEntry converts an Entry to a store.AuditEntry, applying redaction and marshaling.
func (w *Writer) buildStoreEntry(entry Entry) (store.AuditEntry, error) {
	oldJSON, err := marshalState(entry.EntityType, entry.OldState)
	if err != nil {
		return store.AuditEntry{}, err
	}
	newJSON, err := marshalState(entry.EntityType, entry.NewState)
	if err != nil {
		return store.AuditEntry{}, err
	}
	metaJSON, err := marshalMap(entry.Metadata)
	if err != nil {
		return store.AuditEntry{}, err
	}

	return store.AuditEntry{
		OrgID:      entry.OrgID,
		ActorID:    entry.ActorID,
		ActorEmail: entry.ActorEmail,
		Action:     entry.Action,
		EntityType: entry.EntityType,
		EntityID:   entry.EntityID,
		EntityName: entry.EntityName,
		Success:    entry.Success,
		OldState:   oldJSON,
		NewState:   newJSON,
		Metadata:   metaJSON,
	}, nil
}

// marshalState converts an arbitrary state value to JSON, applying secret redaction.
// Returns nil for nil input.
func marshalState(entityType string, state any) (json.RawMessage, error) {
	if state == nil {
		return nil, nil
	}

	// If it's already a map, redact directly.
	if m, ok := state.(map[string]any); ok {
		redacted := redactSecrets(entityType, m)
		return json.Marshal(redacted)
	}

	// For any other type, marshal to JSON then unmarshal to map for redaction.
	raw, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}

	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		// Not a JSON object (e.g., string, number) — return as-is without redaction.
		return raw, nil
	}

	redacted := redactSecrets(entityType, m)
	return json.Marshal(redacted)
}

// marshalMap marshals a map to JSON. Returns nil for nil input.
func marshalMap(m map[string]any) (json.RawMessage, error) {
	if m == nil {
		return nil, nil
	}
	return json.Marshal(m)
}
