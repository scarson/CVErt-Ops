// ABOUTME: Request context key types and constants for the api package.
// ABOUTME: Used by middleware to inject auth state and by handlers to read it.
package api

type contextKey int

const (
	ctxUserID       contextKey = iota // uuid.UUID — authenticated user
	ctxOrgID                          // uuid.UUID — org from URL path param
	ctxRole                           // Role — effective RBAC role for this request
	ctxAPIKeyRole                     // string — role from the API key (may cap org role)
	ctxAPIKeyOrgID                    // uuid.UUID — org the API key belongs to (restricts access to that org only)
	ctxClientIP                       // string — client IP address for rate limiting
	ctxTierResolver                   // *tier.Resolver — resolved tier limits for this org
)
