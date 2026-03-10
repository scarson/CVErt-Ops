// ABOUTME: Tests for context-aware slog helpers.
// ABOUTME: Verifies logger storage, retrieval, and field enrichment via context.
package log_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"

	logpkg "github.com/scarson/cvert-ops/internal/log"
	"github.com/stretchr/testify/assert"
)

func TestFromContext_FallsBackToDefault(t *testing.T) {
	logger := logpkg.FromContext(context.Background())
	assert.NotNil(t, logger)
}

func TestWithLogger_RoundTrip(t *testing.T) {
	custom := slog.New(slog.NewJSONHandler(io.Discard, nil))
	ctx := logpkg.WithLogger(context.Background(), custom)
	got := logpkg.FromContext(ctx)
	assert.Equal(t, custom, got)
}

func TestEnrich_AddsField(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger := slog.New(handler)
	ctx := logpkg.WithLogger(context.Background(), logger)
	ctx = logpkg.Enrich(ctx, "request_id", "abc-123")
	logpkg.FromContext(ctx).Info("test message")
	assert.Contains(t, buf.String(), "abc-123")
}
