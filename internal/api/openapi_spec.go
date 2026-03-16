// ABOUTME: Spec-only Huma operation declarations for Chi-backed routes.
// ABOUTME: Generates OpenAPI specs without affecting production routing or middleware.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
)

// noopHandler returns a huma handler that does nothing. Used for spec-only
// operation declarations where no request will ever be routed.
func noopHandler[I, O any]() func(context.Context, *I) (*O, error) {
	return func(context.Context, *I) (*O, error) {
		return nil, nil
	}
}

// newSpecOnlyAPI creates a throwaway Huma API instance for spec generation.
func newSpecOnlyAPI() huma.API {
	r := chi.NewMux()
	return humachi.New(r, huma.DefaultConfig("CVErt Ops Spec-Only", "0.0.0"))
}

// registerAllSpecOps registers spec-only declarations for all Chi-backed
// route families. Called during OpenAPI spec generation to produce a merged spec.
func registerAllSpecOps(api huma.API) {
	registerGroupsSpecOps(api)
	registerOrgsSpecOps(api)
	registerAPIKeysSpecOps(api)
}

// mergeSpecPaths copies paths and component schemas from a spec-only API
// into the production OpenAPI document.
//
// Collision rules:
// - Path collision: panics (spec-only path exists in production = bug).
// - Schema collision: compares JSON. Identical = safe dedup. Different = panic.
func mergeSpecPaths(prod, specOnly huma.API) {
	prodSpec := prod.OpenAPI()
	soSpec := specOnly.OpenAPI()

	if prodSpec.Paths == nil {
		prodSpec.Paths = map[string]*huma.PathItem{}
	}
	for path, item := range soSpec.Paths {
		if _, exists := prodSpec.Paths[path]; exists {
			panic(fmt.Sprintf("mergeSpecPaths: path collision on %q", path))
		}
		prodSpec.Paths[path] = item
	}

	if prodSpec.Components == nil {
		prodSpec.Components = &huma.Components{}
	}
	if prodSpec.Components.Schemas == nil {
		prodSpec.Components.Schemas = huma.NewMapRegistry("#/components/schemas/", huma.DefaultSchemaNamer)
	}
	if soSpec.Components != nil && soSpec.Components.Schemas != nil {
		soSchemas := soSpec.Components.Schemas.Map()
		existing := prodSpec.Components.Schemas.Map()
		for name, schema := range soSchemas {
			if existingSchema, exists := existing[name]; exists {
				existingJSON, _ := json.Marshal(existingSchema)
				newJSON, _ := json.Marshal(schema)
				if string(existingJSON) != string(newJSON) {
					panic(fmt.Sprintf("mergeSpecPaths: schema collision on %q", name))
				}
				continue
			}
			existing[name] = schema
		}
	}
}

// ── Groups spec-only declarations ──────────────────────────────────────────

// Huma input/output wrapper types for groups routes.
// These embed existing Chi DTO types so spec and runtime share field definitions.

type specCreateGroupInput struct {
	OrgID string         `path:"org_id" format:"uuid" doc:"Organization ID"`
	Body  createGroupBody `json:"body"`
}
type specCreateGroupOutput struct {
	Location string     `header:"Location"`
	Body     groupEntry
}

type specListGroupsInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
}
type specListGroupsOutput struct {
	Body struct {
		Items []groupEntry `json:"items"`
	}
}

type specGetGroupInput struct {
	OrgID   string `path:"org_id" format:"uuid" doc:"Organization ID"`
	GroupID string `path:"group_id" format:"uuid" doc:"Group ID"`
}
type specGetGroupOutput struct {
	Body groupEntry
}

type specUpdateGroupInput struct {
	OrgID   string          `path:"org_id" format:"uuid" doc:"Organization ID"`
	GroupID string          `path:"group_id" format:"uuid" doc:"Group ID"`
	Body    updateGroupBody `json:"body"`
}
type specUpdateGroupOutput struct {
	Body groupEntry
}

type specDeleteGroupInput struct {
	OrgID   string `path:"org_id" format:"uuid" doc:"Organization ID"`
	GroupID string `path:"group_id" format:"uuid" doc:"Group ID"`
}

type specListGroupMembersInput struct {
	OrgID   string `path:"org_id" format:"uuid" doc:"Organization ID"`
	GroupID string `path:"group_id" format:"uuid" doc:"Group ID"`
}
type specListGroupMembersOutput struct {
	Body struct {
		Items []groupMemberEntry `json:"items"`
	}
}

type specAddGroupMemberInput struct {
	OrgID   string             `path:"org_id" format:"uuid" doc:"Organization ID"`
	GroupID string             `path:"group_id" format:"uuid" doc:"Group ID"`
	Body    addGroupMemberBody `json:"body"`
}

type specRemoveGroupMemberInput struct {
	OrgID   string `path:"org_id" format:"uuid" doc:"Organization ID"`
	GroupID string `path:"group_id" format:"uuid" doc:"Group ID"`
	UserID  string `path:"user_id" format:"uuid" doc:"User ID to remove"`
}

func registerGroupsSpecOps(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "create-group",
		Method:      http.MethodPost,
		Path:        "/orgs/{org_id}/groups",
		Summary:     "Create a group",
		Tags:        []string{"Groups"},
	}, noopHandler[specCreateGroupInput, specCreateGroupOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "list-groups",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/groups",
		Summary:     "List groups",
		Tags:        []string{"Groups"},
	}, noopHandler[specListGroupsInput, specListGroupsOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "get-group",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/groups/{group_id}",
		Summary:     "Get a group",
		Tags:        []string{"Groups"},
	}, noopHandler[specGetGroupInput, specGetGroupOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "update-group",
		Method:      http.MethodPatch,
		Path:        "/orgs/{org_id}/groups/{group_id}",
		Summary:     "Update a group",
		Tags:        []string{"Groups"},
	}, noopHandler[specUpdateGroupInput, specUpdateGroupOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "delete-group",
		Method:      http.MethodDelete,
		Path:        "/orgs/{org_id}/groups/{group_id}",
		Summary:     "Delete a group",
		Tags:        []string{"Groups"},
	}, noopHandler[specDeleteGroupInput, struct{}]())

	huma.Register(api, huma.Operation{
		OperationID: "list-group-members",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/groups/{group_id}/members",
		Summary:     "List group members",
		Tags:        []string{"Groups"},
	}, noopHandler[specListGroupMembersInput, specListGroupMembersOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "add-group-member",
		Method:      http.MethodPost,
		Path:        "/orgs/{org_id}/groups/{group_id}/members",
		Summary:     "Add a member to a group",
		Tags:        []string{"Groups"},
	}, noopHandler[specAddGroupMemberInput, struct{}]())

	huma.Register(api, huma.Operation{
		OperationID: "remove-group-member",
		Method:      http.MethodDelete,
		Path:        "/orgs/{org_id}/groups/{group_id}/members/{user_id}",
		Summary:     "Remove a member from a group",
		Tags:        []string{"Groups"},
	}, noopHandler[specRemoveGroupMemberInput, struct{}]())
}

// ── Orgs spec-only declarations ───────────────────────────────────────────

type specCreateOrgInput struct {
	Body createOrgBody `json:"body"`
}
type specCreateOrgOutput struct {
	Location string              `header:"Location"`
	Body     createOrgResponseBody
}

type specGetOrgInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
}
type specGetOrgOutput struct {
	Body orgResponseBody
}

type specUpdateOrgInput struct {
	OrgID string        `path:"org_id" format:"uuid" doc:"Organization ID"`
	Body  updateOrgBody `json:"body"`
}
type specUpdateOrgOutput struct {
	Body orgResponseBody
}

type specListMembersInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
}
type specListMembersOutput struct {
	Body struct {
		Items []memberEntry `json:"items"`
	}
}

type specUpdateMemberRoleInput struct {
	OrgID  string                 `path:"org_id" format:"uuid" doc:"Organization ID"`
	UserID string                 `path:"user_id" format:"uuid" doc:"User ID"`
	Body   updateMemberRoleBody   `json:"body"`
}
type specUpdateMemberRoleOutput struct {
	Body updateMemberRoleResponseBody
}

type specRemoveMemberInput struct {
	OrgID  string `path:"org_id" format:"uuid" doc:"Organization ID"`
	UserID string `path:"user_id" format:"uuid" doc:"User ID"`
}

type specCreateInvitationInput struct {
	OrgID string               `path:"org_id" format:"uuid" doc:"Organization ID"`
	Body  createInvitationBody `json:"body"`
}
type specCreateInvitationOutput struct {
	Body invitationEntry
}

type specListInvitationsInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
}
type specListInvitationsOutput struct {
	Body struct {
		Items []invitationEntry `json:"items"`
	}
}

type specCancelInvitationInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string `path:"id" format:"uuid" doc:"Invitation ID"`
}

type specResendInvitationInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string `path:"id" format:"uuid" doc:"Invitation ID"`
}
type specResendInvitationOutput struct {
	Body invitationEntry
}

func registerOrgsSpecOps(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "create-org",
		Method:      http.MethodPost,
		Path:        "/orgs",
		Summary:     "Create an organization",
		Tags:        []string{"Organizations"},
	}, noopHandler[specCreateOrgInput, specCreateOrgOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "get-org",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}",
		Summary:     "Get an organization",
		Tags:        []string{"Organizations"},
	}, noopHandler[specGetOrgInput, specGetOrgOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "update-org",
		Method:      http.MethodPatch,
		Path:        "/orgs/{org_id}",
		Summary:     "Update an organization",
		Tags:        []string{"Organizations"},
	}, noopHandler[specUpdateOrgInput, specUpdateOrgOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "list-members",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/members",
		Summary:     "List organization members",
		Tags:        []string{"Members"},
	}, noopHandler[specListMembersInput, specListMembersOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "update-member-role",
		Method:      http.MethodPatch,
		Path:        "/orgs/{org_id}/members/{user_id}",
		Summary:     "Update a member's role",
		Tags:        []string{"Members"},
	}, noopHandler[specUpdateMemberRoleInput, specUpdateMemberRoleOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "remove-member",
		Method:      http.MethodDelete,
		Path:        "/orgs/{org_id}/members/{user_id}",
		Summary:     "Remove a member from the organization",
		Tags:        []string{"Members"},
	}, noopHandler[specRemoveMemberInput, struct{}]())

	huma.Register(api, huma.Operation{
		OperationID: "create-invitation",
		Method:      http.MethodPost,
		Path:        "/orgs/{org_id}/invitations",
		Summary:     "Create an invitation",
		Tags:        []string{"Invitations"},
	}, noopHandler[specCreateInvitationInput, specCreateInvitationOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "list-invitations",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/invitations",
		Summary:     "List pending invitations",
		Tags:        []string{"Invitations"},
	}, noopHandler[specListInvitationsInput, specListInvitationsOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "cancel-invitation",
		Method:      http.MethodDelete,
		Path:        "/orgs/{org_id}/invitations/{id}",
		Summary:     "Cancel an invitation",
		Tags:        []string{"Invitations"},
	}, noopHandler[specCancelInvitationInput, struct{}]())

	huma.Register(api, huma.Operation{
		OperationID: "resend-invitation",
		Method:      http.MethodPost,
		Path:        "/orgs/{org_id}/invitations/{id}/resend",
		Summary:     "Resend an invitation email",
		Tags:        []string{"Invitations"},
	}, noopHandler[specResendInvitationInput, specResendInvitationOutput]())
}

// ── API Keys spec-only declarations ───────────────────────────────────────

type specCreateAPIKeyInput struct {
	OrgID string           `path:"org_id" format:"uuid" doc:"Organization ID"`
	Body  createAPIKeyBody `json:"body"`
}
type specCreateAPIKeyOutput struct {
	Location string             `header:"Location"`
	Body     createAPIKeyResponse
}

type specListAPIKeysInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
}
type specListAPIKeysOutput struct {
	Body struct {
		Items []apiKeyEntry `json:"items"`
	}
}

type specRevokeAPIKeyInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string `path:"id" format:"uuid" doc:"API Key ID"`
}

func registerAPIKeysSpecOps(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "create-api-key",
		Method:      http.MethodPost,
		Path:        "/orgs/{org_id}/api-keys",
		Summary:     "Create an API key",
		Tags:        []string{"API Keys"},
	}, noopHandler[specCreateAPIKeyInput, specCreateAPIKeyOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "list-api-keys",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/api-keys",
		Summary:     "List API keys",
		Tags:        []string{"API Keys"},
	}, noopHandler[specListAPIKeysInput, specListAPIKeysOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "revoke-api-key",
		Method:      http.MethodDelete,
		Path:        "/orgs/{org_id}/api-keys/{id}",
		Summary:     "Revoke an API key",
		Tags:        []string{"API Keys"},
	}, noopHandler[specRevokeAPIKeyInput, struct{}]())
}
