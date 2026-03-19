// ABOUTME: Role recomputation from SCIM group mappings.
// ABOUTME: Called on group membership change and admin mapping change. Apply-on-write.
package api

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
)

// roleHierarchy maps SCIM-assignable roles to a numeric rank for comparison.
// Owner is excluded — SCIM never assigns owner.
var roleHierarchy = map[string]int{
	"viewer": 1,
	"member": 2,
	"admin":  3,
}

// recomputeSCIMRole recalculates a user's org role based on their SCIM group
// memberships and the groups' mapped roles. If the user is an owner or SCIM-exempt,
// their role is left unchanged. If no mapped roles exist, the defaultRole is used.
func (srv *Server) recomputeSCIMRole(ctx context.Context, orgID, userID uuid.UUID, defaultRole string) error {
	// 1. Load current membership.
	member, err := srv.store.GetOrgMemberFull(ctx, orgID, userID)
	if err != nil {
		return err
	}
	if member == nil {
		return nil // not a member of this org
	}

	// 2. Owner is always manual.
	if member.Role == "owner" {
		return nil
	}

	// 3. SCIM-exempt users are not modified.
	if member.ScimExempt {
		return nil
	}

	// 4. Load all SCIM groups the user belongs to.
	groups, err := srv.store.ListUserSCIMGroups(ctx, userID, orgID)
	if err != nil {
		return err
	}

	// 5. Find the highest mapped role.
	highestRank := 0
	for _, g := range groups {
		if g.MappedRole.Valid {
			rank, ok := roleHierarchy[g.MappedRole.String]
			if ok && rank > highestRank {
				highestRank = rank
			}
		}
	}

	// 6. Determine effective role.
	effectiveRole := defaultRole
	if highestRank > 0 {
		for role, rank := range roleHierarchy {
			if rank == highestRank {
				effectiveRole = role
				break
			}
		}
	}

	// 7. Update if changed.
	if effectiveRole != member.Role {
		slog.InfoContext(ctx, "scim role recomputation changed role",
			slog.String("org_id", orgID.String()),
			slog.String("user_id", userID.String()),
			slog.String("old_role", member.Role),
			slog.String("new_role", effectiveRole),
		)
		return srv.store.UpdateOrgMemberRole(ctx, orgID, userID, effectiveRole)
	}

	return nil
}
