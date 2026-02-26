// ABOUTME: RBAC Role type with ordered integer constants for permission comparison.
// ABOUTME: parseRole converts a string role name to a Role value.
package api

// Role represents an RBAC permission level. Higher integer values grant more permissions.
type Role int

// Role permission level constants, ordered from least to most privileged.
const (
	RoleViewer Role = 1 // read-only access
	RoleMember Role = 2 // standard org member
	RoleAdmin  Role = 3 // org administrator
	RoleOwner  Role = 4 // full control including org deletion
)

// parseRole converts a role string from the database to a Role.
// Unknown or empty values map to RoleViewer (least privilege).
func parseRole(s string) Role {
	switch s {
	case "owner":
		return RoleOwner
	case "admin":
		return RoleAdmin
	case "member":
		return RoleMember
	default:
		return RoleViewer
	}
}
