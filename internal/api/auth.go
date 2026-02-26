// ABOUTME: HTTP handlers for authentication: register, login, refresh, logout, me.
// ABOUTME: All auth endpoints live at /api/v1/auth/... and are rate-limited.
package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/scarson/cvert-ops/internal/auth"
)

// pgErrCode extracts the Postgres error code from err, or "" if err is not a pg error.
func pgErrCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// registerInput is the request body for POST /auth/register.
type registerInput struct {
	Body struct {
		Email       string `json:"email"        format:"email" doc:"User email address"`
		Password    string `json:"password"     minLength:"8"  doc:"Password (min 8 characters)"`
		DisplayName string `json:"display_name,omitempty"       doc:"Display name (optional)"`
	}
}

// registerOutput is the response body for POST /auth/register.
type registerOutput struct {
	Status int
	Body   struct {
		UserID string `json:"user_id"`
		OrgID  string `json:"org_id,omitempty"`
	}
}

// registerHandler handles POST /api/v1/auth/register.
// In "open" mode the first registered user gets a default org (owner role).
func (srv *Server) registerHandler(ctx context.Context, input *registerInput) (*registerOutput, error) {
	if srv.cfg.RegistrationMode != "open" {
		return nil, huma.Error403Forbidden("registration is not open on this server")
	}

	// Reject duplicate email before the expensive hash.
	existing, err := srv.store.GetUserByEmail(ctx, input.Body.Email)
	if err != nil {
		slog.ErrorContext(ctx, "register: lookup email", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if existing != nil {
		return nil, huma.Error409Conflict("email already registered")
	}

	// Snapshot user count before creation to detect first-user scenario.
	priorCount, err := srv.store.CountUsers(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "register: count users", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	if !srv.acquireArgon2() {
		return nil, huma.Error503ServiceUnavailable("server busy, please retry")
	}
	defer srv.releaseArgon2()

	hash, err := auth.HashPassword(input.Body.Password)
	if err != nil {
		slog.ErrorContext(ctx, "register: hash password", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	displayName := input.Body.DisplayName
	if displayName == "" {
		// Derive a display name from the email local-part.
		if at := strings.Index(input.Body.Email, "@"); at > 0 {
			displayName = input.Body.Email[:at]
		} else {
			displayName = input.Body.Email
		}
	}

	user, err := srv.store.CreateUser(ctx, input.Body.Email, displayName, hash, 1)
	if err != nil {
		if pgErrCode(err) == "23505" { // unique_violation — race on concurrent register
			return nil, huma.Error409Conflict("email already registered")
		}
		slog.ErrorContext(ctx, "register: create user", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	out := &registerOutput{}
	out.Status = http.StatusCreated
	out.Body.UserID = user.ID.String()

	// Bootstrap a default org for the first user in open mode.
	if priorCount == 0 {
		orgName := displayName + "'s Organization"
		org, err := srv.store.CreateOrg(ctx, orgName)
		if err != nil {
			slog.ErrorContext(ctx, "register: create org", "error", err)
			return nil, huma.Error500InternalServerError("internal error")
		}
		if err := srv.store.CreateOrgMember(ctx, org.ID, user.ID, "owner"); err != nil {
			slog.ErrorContext(ctx, "register: create org member", "error", err)
			return nil, huma.Error500InternalServerError("internal error")
		}
		out.Body.OrgID = org.ID.String()
	}

	return out, nil
}

// registerAuthRoutes registers all auth-related routes on the huma API.
func registerAuthRoutes(api huma.API, srv *Server) {
	huma.Register(api, huma.Operation{
		OperationID:   "register",
		Method:        http.MethodPost,
		Path:          "/auth/register",
		Tags:          []string{"auth"},
		Summary:       "Register a new user account",
		DefaultStatus: http.StatusCreated,
	}, srv.registerHandler)
}
