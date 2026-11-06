// ABOUTME: Declares each API operation's credentials and minimum role in the served OpenAPI spec.
// ABOUTME: One table for all operations, checked against the running server by openapi_security_test.go.
package api

import (
	"fmt"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

const (
	bearerAuthScheme = "bearerAuth"
	cookieAuthScheme = "cookieAuth"
	// roleSiteAdmin is the x-min-role value for routes behind RequireSiteAdmin,
	// which is not an org role.
	roleSiteAdmin = "site-admin"
)

// accessKind says which credentials an operation accepts.
type accessKind int

const (
	// accessPublic needs no credential.
	accessPublic accessKind = iota
	// accessOwnCredential is authenticated by a dedicated cookie that the operation
	// documents as a parameter (a refresh token, MFA pending token or enrollment token).
	accessOwnCredential
	// accessSession accepts only a browser session. API keys cannot reach these
	// operations, which manage the user's own account or the whole instance.
	accessSession
	// accessAny accepts an API key or a browser session.
	accessAny
)

// accessRule is one operation's declared security.
type accessRule struct {
	kind    accessKind
	minRole string // "" when the operation has no role requirement
}

func publicOp() accessRule        { return accessRule{kind: accessPublic} }
func ownCredentialOp() accessRule { return accessRule{kind: accessOwnCredential} }
func sessionOp() accessRule       { return accessRule{kind: accessSession} }
func siteAdminOp() accessRule {
	return accessRule{kind: accessSession, minRole: roleSiteAdmin}
}
func anyCredentialOp() accessRule { return accessRule{kind: accessAny} }
func roleOp(role string) accessRule {
	return accessRule{kind: accessAny, minRole: role}
}

// operationAccess gives every operation in the spec its access. Org roles mirror
// the RequireOrgRole middleware on each route in Handler. A separate table, rather
// than a field on each huma.Operation, keeps the chi routes and their spec-only
// declarations from each holding a copy of the rules.
var operationAccess = map[string]accessRule{
	// Accounts and sessions.
	"POST /auth/register":                      publicOp(),
	"POST /auth/login":                         publicOp(),
	"POST /auth/forgot-password":               publicOp(),
	"POST /auth/reset-password":                publicOp(),
	"POST /auth/verify-email":                  publicOp(),
	"POST /auth/discover":                      publicOp(),
	"GET /auth/providers":                      publicOp(),
	"GET /auth/invitations/{token}":            publicOp(),
	"POST /auth/refresh":                       ownCredentialOp(),
	"POST /auth/logout":                        ownCredentialOp(),
	"POST /auth/mfa/challenge":                 ownCredentialOp(),
	"POST /auth/mfa/verify":                    ownCredentialOp(),
	"GET /auth/me":                             sessionOp(),
	"POST /auth/change-password":               sessionOp(),
	"POST /auth/resend-verification":           sessionOp(),
	"POST /auth/invitations/{token}/accept":    sessionOp(),
	"POST /auth/mfa/totp/setup":                sessionOp(),
	"POST /auth/mfa/totp/confirm":              ownCredentialOp(),
	"POST /auth/mfa/email-otp/setup":           sessionOp(),
	"POST /auth/mfa/email-otp/confirm":         ownCredentialOp(),
	"GET /auth/mfa/methods":                    sessionOp(),
	"DELETE /auth/mfa/methods/{method}":        sessionOp(),
	"POST /auth/mfa/recovery-codes/regenerate": sessionOp(),

	// CVE corpus: any authenticated caller.
	"GET /cves":                  anyCredentialOp(),
	"GET /cves/{cve_id}":         anyCredentialOp(),
	"GET /cves/{cve_id}/sources": anyCredentialOp(),

	// Organizations.
	"POST /orgs":                        anyCredentialOp(),
	"GET /orgs/{org_id}":                roleOp("viewer"),
	"PATCH /orgs/{org_id}":              roleOp("admin"),
	"GET /orgs/{org_id}/tier":           roleOp("viewer"),
	"PATCH /orgs/{org_id}/mfa-settings": roleOp("owner"),

	// Members.
	"GET /orgs/{org_id}/members":                                 roleOp("viewer"),
	"PATCH /orgs/{org_id}/members/{user_id}":                     roleOp("admin"),
	"DELETE /orgs/{org_id}/members/{user_id}":                    roleOp("admin"),
	"POST /orgs/{org_id}/members/{user_id}/reset-mfa":            roleOp("admin"),
	"POST /orgs/{org_id}/members/{user_id}/force-password-reset": roleOp("admin"),
	"POST /orgs/{org_id}/members/{user_id}/require-mfa":          roleOp("admin"),
	"DELETE /orgs/{org_id}/members/{user_id}/require-mfa":        roleOp("admin"),

	// Invitations.
	"POST /orgs/{org_id}/invitations":             roleOp("admin"),
	"GET /orgs/{org_id}/invitations":              roleOp("admin"),
	"DELETE /orgs/{org_id}/invitations/{id}":      roleOp("admin"),
	"POST /orgs/{org_id}/invitations/{id}/resend": roleOp("admin"),

	// API keys.
	"POST /orgs/{org_id}/api-keys":        roleOp("member"),
	"GET /orgs/{org_id}/api-keys":         roleOp("viewer"),
	"DELETE /orgs/{org_id}/api-keys/{id}": roleOp("viewer"),

	// Watchlists.
	"GET /orgs/{org_id}/watchlists":                         roleOp("viewer"),
	"POST /orgs/{org_id}/watchlists":                        roleOp("member"),
	"GET /orgs/{org_id}/watchlists/{id}":                    roleOp("viewer"),
	"PATCH /orgs/{org_id}/watchlists/{id}":                  roleOp("member"),
	"DELETE /orgs/{org_id}/watchlists/{id}":                 roleOp("member"),
	"GET /orgs/{org_id}/watchlists/{id}/items":              roleOp("viewer"),
	"POST /orgs/{org_id}/watchlists/{id}/items":             roleOp("member"),
	"DELETE /orgs/{org_id}/watchlists/{id}/items/{item_id}": roleOp("member"),

	// Notification channels.
	"GET /orgs/{org_id}/channels":                       roleOp("viewer"),
	"POST /orgs/{org_id}/channels":                      roleOp("admin"),
	"GET /orgs/{org_id}/channels/{id}":                  roleOp("viewer"),
	"PATCH /orgs/{org_id}/channels/{id}":                roleOp("admin"),
	"DELETE /orgs/{org_id}/channels/{id}":               roleOp("admin"),
	"POST /orgs/{org_id}/channels/{id}/rotate-secret":   roleOp("admin"),
	"POST /orgs/{org_id}/channels/{id}/clear-secondary": roleOp("admin"),
	"POST /orgs/{org_id}/channels/{id}/test":            roleOp("admin"),

	// Alert events, audit log and deliveries.
	"GET /orgs/{org_id}/alert-events":            roleOp("viewer"),
	"GET /orgs/{org_id}/audit-log":               roleOp("admin"),
	"GET /orgs/{org_id}/deliveries":              roleOp("viewer"),
	"GET /orgs/{org_id}/deliveries/{id}":         roleOp("viewer"),
	"POST /orgs/{org_id}/deliveries/{id}/replay": roleOp("admin"),

	// SSO and SCIM configuration.
	"POST /orgs/{org_id}/sso":                           roleOp("owner"),
	"GET /orgs/{org_id}/sso":                            roleOp("owner"),
	"PATCH /orgs/{org_id}/sso":                          roleOp("owner"),
	"DELETE /orgs/{org_id}/sso":                         roleOp("owner"),
	"PUT /orgs/{org_id}/sso/domains":                    roleOp("owner"),
	"GET /orgs/{org_id}/sso/link":                       roleOp("member"),
	"POST /orgs/{org_id}/sso/scim":                      roleOp("owner"),
	"GET /orgs/{org_id}/sso/scim":                       roleOp("admin"),
	"PATCH /orgs/{org_id}/sso/scim":                     roleOp("owner"),
	"DELETE /orgs/{org_id}/sso/scim":                    roleOp("owner"),
	"POST /orgs/{org_id}/sso/scim/rotate-token":         roleOp("owner"),
	"GET /orgs/{org_id}/sso/scim/groups":                roleOp("admin"),
	"PATCH /orgs/{org_id}/sso/scim/groups/{id}/mapping": roleOp("admin"),

	// Alert rules.
	"GET /orgs/{org_id}/alert-rules":                               roleOp("viewer"),
	"POST /orgs/{org_id}/alert-rules":                              roleOp("member"),
	"POST /orgs/{org_id}/alert-rules/validate":                     roleOp("viewer"),
	"GET /orgs/{org_id}/alert-rules/{id}":                          roleOp("viewer"),
	"PATCH /orgs/{org_id}/alert-rules/{id}":                        roleOp("member"),
	"DELETE /orgs/{org_id}/alert-rules/{id}":                       roleOp("member"),
	"POST /orgs/{org_id}/alert-rules/{id}/dry-run":                 roleOp("viewer"),
	"GET /orgs/{org_id}/alert-rules/{id}/channels":                 roleOp("viewer"),
	"PUT /orgs/{org_id}/alert-rules/{id}/channels/{channel_id}":    roleOp("member"),
	"DELETE /orgs/{org_id}/alert-rules/{id}/channels/{channel_id}": roleOp("member"),

	// Reports.
	"GET /orgs/{org_id}/reports":                               roleOp("viewer"),
	"POST /orgs/{org_id}/reports":                              roleOp("member"),
	"GET /orgs/{org_id}/reports/{id}":                          roleOp("viewer"),
	"PATCH /orgs/{org_id}/reports/{id}":                        roleOp("member"),
	"DELETE /orgs/{org_id}/reports/{id}":                       roleOp("member"),
	"GET /orgs/{org_id}/reports/{id}/channels":                 roleOp("viewer"),
	"PUT /orgs/{org_id}/reports/{id}/channels/{channel_id}":    roleOp("member"),
	"DELETE /orgs/{org_id}/reports/{id}/channels/{channel_id}": roleOp("member"),

	// Ingest, AI and saved searches.
	"POST /orgs/{org_id}/ingest":                      roleOp("member"),
	"POST /orgs/{org_id}/ai/nl-search":                roleOp("viewer"),
	"POST /orgs/{org_id}/ai/summarize/{cve_id}":       roleOp("viewer"),
	"GET /orgs/{org_id}/saved-searches":               roleOp("viewer"),
	"POST /orgs/{org_id}/saved-searches":              roleOp("member"),
	"GET /orgs/{org_id}/saved-searches/{id}":          roleOp("viewer"),
	"PATCH /orgs/{org_id}/saved-searches/{id}":        roleOp("member"),
	"DELETE /orgs/{org_id}/saved-searches/{id}":       roleOp("member"),
	"POST /orgs/{org_id}/saved-searches/{id}/execute": roleOp("viewer"),

	// Groups.
	"GET /orgs/{org_id}/groups":                                 roleOp("viewer"),
	"POST /orgs/{org_id}/groups":                                roleOp("admin"),
	"GET /orgs/{org_id}/groups/{group_id}":                      roleOp("viewer"),
	"PATCH /orgs/{org_id}/groups/{group_id}":                    roleOp("admin"),
	"DELETE /orgs/{org_id}/groups/{group_id}":                   roleOp("admin"),
	"GET /orgs/{org_id}/groups/{group_id}/members":              roleOp("viewer"),
	"POST /orgs/{org_id}/groups/{group_id}/members":             roleOp("admin"),
	"DELETE /orgs/{org_id}/groups/{group_id}/members/{user_id}": roleOp("admin"),

	// Instance administration.
	"GET /admin/feeds":                           siteAdminOp(),
	"POST /admin/feeds/{feed}/run":               siteAdminOp(),
	"POST /admin/feeds/{feed}/pause":             siteAdminOp(),
	"POST /admin/feeds/{feed}/resume":            siteAdminOp(),
	"GET /admin/feeds/{feed}/logs":               siteAdminOp(),
	"GET /admin/version":                         siteAdminOp(),
	"GET /admin/doctor":                          siteAdminOp(),
	"GET /admin/orgs":                            siteAdminOp(),
	"PATCH /admin/orgs/{org_id}":                 siteAdminOp(),
	"GET /admin/orgs/{org_id}/usage":             siteAdminOp(),
	"GET /admin/users":                           siteAdminOp(),
	"POST /admin/users/{user_id}/disable":        siteAdminOp(),
	"POST /admin/users/{user_id}/enable":         siteAdminOp(),
	"POST /admin/users/{user_id}/unlock":         siteAdminOp(),
	"POST /admin/users/{user_id}/reset-password": siteAdminOp(),
	"GET /admin/deliveries":                      siteAdminOp(),
	"POST /admin/deliveries/{id}/retry":          siteAdminOp(),
	"POST /admin/deliveries/retry-failed":        siteAdminOp(),
	"POST /admin/reindex":                        siteAdminOp(),
	"POST /admin/reload-config":                  siteAdminOp(),
	"GET /admin/config":                          siteAdminOp(),
	"GET /admin/audit-log":                       siteAdminOp(),
	"GET /admin/security-events":                 siteAdminOp(),
}

// applyOperationSecurity declares the security schemes and sets each operation's
// access from operationAccess. It panics on an operation with no entry: the spec
// would otherwise present it as public, and every test that builds a Handler
// catches this before it can ship.
func applyOperationSecurity(api huma.API) {
	spec := api.OpenAPI()
	if spec.Components.SecuritySchemes == nil {
		spec.Components.SecuritySchemes = map[string]*huma.SecurityScheme{}
	}
	spec.Components.SecuritySchemes[bearerAuthScheme] = &huma.SecurityScheme{
		Type:        "http",
		Scheme:      "bearer",
		Description: "An API key (cvo_...) in the Authorization header. Keys are never accepted in a query parameter.",
	}
	spec.Components.SecuritySchemes[cookieAuthScheme] = &huma.SecurityScheme{
		Type:        "apiKey",
		In:          "cookie",
		Name:        "access_token",
		Description: "The browser session cookie set by login.",
	}

	for path, item := range spec.Paths {
		for method, op := range map[string]*huma.Operation{
			http.MethodGet:    item.Get,
			http.MethodPost:   item.Post,
			http.MethodPut:    item.Put,
			http.MethodPatch:  item.Patch,
			http.MethodDelete: item.Delete,
		} {
			if op == nil {
				continue
			}
			name := method + " " + path
			access, ok := operationAccess[name]
			if !ok {
				panic(fmt.Sprintf("applyOperationSecurity: %s has no operationAccess entry", name))
			}
			switch access.kind {
			case accessPublic:
			case accessOwnCredential:
				setOperationExtension(op, "x-own-credential", true)
			case accessSession:
				op.Security = []map[string][]string{{cookieAuthScheme: {}}}
			case accessAny:
				op.Security = []map[string][]string{{bearerAuthScheme: {}}, {cookieAuthScheme: {}}}
			}
			// The role goes in an extension, not the security requirement's list:
			// OpenAPI 3.0 requires that list to be empty for these schemes, and
			// values there mean "all of these", not "this role or higher".
			if access.minRole != "" {
				setOperationExtension(op, "x-min-role", access.minRole)
			}
		}
	}
}

func setOperationExtension(op *huma.Operation, name string, value any) {
	if op.Extensions == nil {
		op.Extensions = map[string]any{}
	}
	op.Extensions[name] = value
}
