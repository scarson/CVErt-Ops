// ABOUTME: Context-aware slog helpers for structured log correlation.
// ABOUTME: Middleware injects request_id, org_id, user_id; handlers use FromContext.
package log

import (
	"context"
	"log/slog"
)

type ctxKey struct{}

// FromContext retrieves the logger from context, falling back to slog.Default().
func FromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(ctxKey{}).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}

// WithLogger stores a logger in the context.
func WithLogger(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

// Enrich adds a structured field to the context's logger.
func Enrich(ctx context.Context, key string, value any) context.Context {
	return WithLogger(ctx, FromContext(ctx).With(key, value))
}
