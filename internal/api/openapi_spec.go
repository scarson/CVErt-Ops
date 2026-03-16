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

	"github.com/scarson/cvert-ops/internal/store"
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
	registerWatchlistsSpecOps(api)
	registerAlertRulesSpecOps(api)
	registerAlertEventsSpecOps(api)
	registerChannelsSpecOps(api)
	registerDeliveriesSpecOps(api)
	registerReportsSpecOps(api)
	registerSavedSearchesSpecOps(api)
	registerSSOSpecOps(api)
	registerAuditLogSpecOps(api)
	registerAISpecOps(api)
	registerIngestSpecOps(api)
	registerOrgTierSpecOps(api)
	registerAdminFeedsSpecOps(api)
	registerAdminSystemSpecOps(api)
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

// ── Watchlists spec-only declarations ────────────────────────────────────────

type specCreateWatchlistInput struct {
	OrgID string             `path:"org_id" format:"uuid" doc:"Organization ID"`
	Body  createWatchlistBody `json:"body"`
}
type specCreateWatchlistOutput struct {
	Location string         `header:"Location"`
	Body     watchlistEntry
}

type specGetWatchlistInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string `path:"id" format:"uuid" doc:"Watchlist ID"`
}
type specGetWatchlistOutput struct {
	Body watchlistEntry
}

type specListWatchlistsInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
	After string `query:"after" doc:"Pagination cursor"`
}
type specListWatchlistsOutput struct {
	Body struct {
		Items      []watchlistEntry `json:"items"`
		NextCursor string           `json:"next_cursor,omitempty"`
	}
}

type specUpdateWatchlistInput struct {
	OrgID string             `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string             `path:"id" format:"uuid" doc:"Watchlist ID"`
	Body  patchWatchlistBody `json:"body"`
}
type specUpdateWatchlistOutput struct {
	Body watchlistEntry
}

type specDeleteWatchlistInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string `path:"id" format:"uuid" doc:"Watchlist ID"`
}

type specCreateWatchlistItemInput struct {
	OrgID       string                 `path:"org_id" format:"uuid" doc:"Organization ID"`
	WatchlistID string                 `path:"id" format:"uuid" doc:"Watchlist ID"`
	Body        createWatchlistItemBody `json:"body"`
}
type specCreateWatchlistItemOutput struct {
	Location string             `header:"Location"`
	Body     watchlistItemEntry
}

type specListWatchlistItemsInput struct {
	OrgID       string `path:"org_id" format:"uuid" doc:"Organization ID"`
	WatchlistID string `path:"id" format:"uuid" doc:"Watchlist ID"`
	ItemType    string `query:"item_type" doc:"Filter by item type"`
	After       string `query:"after" doc:"Pagination cursor"`
}
type specListWatchlistItemsOutput struct {
	Body struct {
		Items      []watchlistItemEntry `json:"items"`
		NextCursor string               `json:"next_cursor,omitempty"`
	}
}

type specDeleteWatchlistItemInput struct {
	OrgID       string `path:"org_id" format:"uuid" doc:"Organization ID"`
	WatchlistID string `path:"id" format:"uuid" doc:"Watchlist ID"`
	ItemID      string `path:"item_id" format:"uuid" doc:"Watchlist Item ID"`
}

func registerWatchlistsSpecOps(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "create-watchlist",
		Method:      http.MethodPost,
		Path:        "/orgs/{org_id}/watchlists",
		Summary:     "Create a watchlist",
		Tags:        []string{"Watchlists"},
	}, noopHandler[specCreateWatchlistInput, specCreateWatchlistOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "get-watchlist",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/watchlists/{id}",
		Summary:     "Get a watchlist",
		Tags:        []string{"Watchlists"},
	}, noopHandler[specGetWatchlistInput, specGetWatchlistOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "list-watchlists",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/watchlists",
		Summary:     "List watchlists",
		Tags:        []string{"Watchlists"},
	}, noopHandler[specListWatchlistsInput, specListWatchlistsOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "update-watchlist",
		Method:      http.MethodPatch,
		Path:        "/orgs/{org_id}/watchlists/{id}",
		Summary:     "Update a watchlist",
		Tags:        []string{"Watchlists"},
	}, noopHandler[specUpdateWatchlistInput, specUpdateWatchlistOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "delete-watchlist",
		Method:      http.MethodDelete,
		Path:        "/orgs/{org_id}/watchlists/{id}",
		Summary:     "Delete a watchlist",
		Tags:        []string{"Watchlists"},
	}, noopHandler[specDeleteWatchlistInput, struct{}]())

	huma.Register(api, huma.Operation{
		OperationID: "create-watchlist-item",
		Method:      http.MethodPost,
		Path:        "/orgs/{org_id}/watchlists/{id}/items",
		Summary:     "Add an item to a watchlist",
		Tags:        []string{"Watchlists"},
	}, noopHandler[specCreateWatchlistItemInput, specCreateWatchlistItemOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "list-watchlist-items",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/watchlists/{id}/items",
		Summary:     "List watchlist items",
		Tags:        []string{"Watchlists"},
	}, noopHandler[specListWatchlistItemsInput, specListWatchlistItemsOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "delete-watchlist-item",
		Method:      http.MethodDelete,
		Path:        "/orgs/{org_id}/watchlists/{id}/items/{item_id}",
		Summary:     "Remove an item from a watchlist",
		Tags:        []string{"Watchlists"},
	}, noopHandler[specDeleteWatchlistItemInput, struct{}]())
}

// ── Alert Rules spec-only declarations ───────────────────────────────────────

type specCreateAlertRuleInput struct {
	OrgID string             `path:"org_id" format:"uuid" doc:"Organization ID"`
	Body  createAlertRuleBody `json:"body"`
}
type specCreateAlertRuleOutput struct {
	Location string         `header:"Location"`
	Body     alertRuleEntry
}

type specListAlertRulesInput struct {
	OrgID  string `path:"org_id" format:"uuid" doc:"Organization ID"`
	Status string `query:"status" doc:"Filter by status"`
	After  string `query:"after" doc:"Pagination cursor"`
}
type specListAlertRulesOutput struct {
	Body struct {
		Items      []alertRuleEntry `json:"items"`
		NextCursor string           `json:"next_cursor,omitempty"`
	}
}

type specGetAlertRuleInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string `path:"id" format:"uuid" doc:"Alert Rule ID"`
}
type specGetAlertRuleOutput struct {
	Body alertRuleEntry
}

type specUpdateAlertRuleInput struct {
	OrgID string             `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string             `path:"id" format:"uuid" doc:"Alert Rule ID"`
	Body  patchAlertRuleBody `json:"body"`
}
type specUpdateAlertRuleOutput struct {
	Body alertRuleEntry
}

type specDeleteAlertRuleInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string `path:"id" format:"uuid" doc:"Alert Rule ID"`
}

type specValidateAlertRuleInput struct {
	OrgID string           `path:"org_id" format:"uuid" doc:"Organization ID"`
	Body  validateRuleBody `json:"body"`
}
type specValidateAlertRuleOutput struct {
	Body validateRuleResponse
}

type specDryRunAlertRuleInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string `path:"id" format:"uuid" doc:"Alert Rule ID"`
}
type specDryRunAlertRuleOutput struct {
	Body dryRunResponse
}

type specListRuleChannelsInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string `path:"id" format:"uuid" doc:"Alert Rule ID"`
}
type specListRuleChannelsOutput struct {
	Body struct {
		Items []channelEntry `json:"items"`
	}
}

type specBindRuleChannelInput struct {
	OrgID     string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID        string `path:"id" format:"uuid" doc:"Alert Rule ID"`
	ChannelID string `path:"channel_id" format:"uuid" doc:"Notification Channel ID"`
}

type specUnbindRuleChannelInput struct {
	OrgID     string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID        string `path:"id" format:"uuid" doc:"Alert Rule ID"`
	ChannelID string `path:"channel_id" format:"uuid" doc:"Notification Channel ID"`
}

func registerAlertRulesSpecOps(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "create-alert-rule",
		Method:      http.MethodPost,
		Path:        "/orgs/{org_id}/alert-rules",
		Summary:     "Create an alert rule",
		Tags:        []string{"Alert Rules"},
	}, noopHandler[specCreateAlertRuleInput, specCreateAlertRuleOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "list-alert-rules",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/alert-rules",
		Summary:     "List alert rules",
		Tags:        []string{"Alert Rules"},
	}, noopHandler[specListAlertRulesInput, specListAlertRulesOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "get-alert-rule",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/alert-rules/{id}",
		Summary:     "Get an alert rule",
		Tags:        []string{"Alert Rules"},
	}, noopHandler[specGetAlertRuleInput, specGetAlertRuleOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "update-alert-rule",
		Method:      http.MethodPatch,
		Path:        "/orgs/{org_id}/alert-rules/{id}",
		Summary:     "Update an alert rule",
		Tags:        []string{"Alert Rules"},
	}, noopHandler[specUpdateAlertRuleInput, specUpdateAlertRuleOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "delete-alert-rule",
		Method:      http.MethodDelete,
		Path:        "/orgs/{org_id}/alert-rules/{id}",
		Summary:     "Delete an alert rule",
		Tags:        []string{"Alert Rules"},
	}, noopHandler[specDeleteAlertRuleInput, struct{}]())

	huma.Register(api, huma.Operation{
		OperationID: "validate-alert-rule",
		Method:      http.MethodPost,
		Path:        "/orgs/{org_id}/alert-rules/validate",
		Summary:     "Validate alert rule DSL",
		Tags:        []string{"Alert Rules"},
	}, noopHandler[specValidateAlertRuleInput, specValidateAlertRuleOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "dry-run-alert-rule",
		Method:      http.MethodPost,
		Path:        "/orgs/{org_id}/alert-rules/{id}/dry-run",
		Summary:     "Dry-run an alert rule",
		Tags:        []string{"Alert Rules"},
	}, noopHandler[specDryRunAlertRuleInput, specDryRunAlertRuleOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "list-rule-channels",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/alert-rules/{id}/channels",
		Summary:     "List channels bound to a rule",
		Tags:        []string{"Alert Rules"},
	}, noopHandler[specListRuleChannelsInput, specListRuleChannelsOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "bind-rule-channel",
		Method:      http.MethodPut,
		Path:        "/orgs/{org_id}/alert-rules/{id}/channels/{channel_id}",
		Summary:     "Bind a channel to a rule",
		Tags:        []string{"Alert Rules"},
	}, noopHandler[specBindRuleChannelInput, struct{}]())

	huma.Register(api, huma.Operation{
		OperationID: "unbind-rule-channel",
		Method:      http.MethodDelete,
		Path:        "/orgs/{org_id}/alert-rules/{id}/channels/{channel_id}",
		Summary:     "Unbind a channel from a rule",
		Tags:        []string{"Alert Rules"},
	}, noopHandler[specUnbindRuleChannelInput, struct{}]())
}

// ── Alert Events spec-only declarations ──────────────────────────────────────

type specListAlertEventsInput struct {
	OrgID          string `path:"org_id" format:"uuid" doc:"Organization ID"`
	RuleID         string `query:"rule_id" doc:"Filter by rule ID"`
	CveID          string `query:"cve_id" doc:"Filter by CVE ID"`
	LastMatchState string `query:"last_match_state" doc:"Filter by last match state"`
	Since          string `query:"since" doc:"Filter events since timestamp (RFC3339)"`
	After          string `query:"after" doc:"Pagination cursor"`
}
type specListAlertEventsOutput struct {
	Body struct {
		Items      []alertEventEntry `json:"items"`
		NextCursor string            `json:"next_cursor,omitempty"`
	}
}

func registerAlertEventsSpecOps(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "list-alert-events",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/alert-events",
		Summary:     "List alert events",
		Tags:        []string{"Alert Events"},
	}, noopHandler[specListAlertEventsInput, specListAlertEventsOutput]())
}

// ── Channels spec-only declarations ──────────────────────────────────────────

type specCreateChannelInput struct {
	OrgID string            `path:"org_id" format:"uuid" doc:"Organization ID"`
	Body  createChannelBody `json:"body"`
}
type specCreateChannelOutput struct {
	Location string `header:"Location"`
	Body     channelCreateEntry
}

type specListChannelsInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
}
type specListChannelsOutput struct {
	Body struct {
		Items []channelEntry `json:"items"`
	}
}

type specGetChannelInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string `path:"id" format:"uuid" doc:"Channel ID"`
}
type specGetChannelOutput struct {
	Body channelEntry
}

type specUpdateChannelInput struct {
	OrgID string           `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string           `path:"id" format:"uuid" doc:"Channel ID"`
	Body  patchChannelBody `json:"body"`
}
type specUpdateChannelOutput struct {
	Body channelEntry
}

type specDeleteChannelInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string `path:"id" format:"uuid" doc:"Channel ID"`
}

type specRotateSecretInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string `path:"id" format:"uuid" doc:"Channel ID"`
}
type specRotateSecretOutput struct {
	Body rotateSecretResponse
}

type specClearSecondaryInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string `path:"id" format:"uuid" doc:"Channel ID"`
}

type specTestChannelInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string `path:"id" format:"uuid" doc:"Channel ID"`
}
type specTestChannelOutput struct {
	Body testChannelResponse
}

func registerChannelsSpecOps(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "create-channel",
		Method:      http.MethodPost,
		Path:        "/orgs/{org_id}/channels",
		Summary:     "Create a notification channel",
		Tags:        []string{"Channels"},
	}, noopHandler[specCreateChannelInput, specCreateChannelOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "list-channels",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/channels",
		Summary:     "List notification channels",
		Tags:        []string{"Channels"},
	}, noopHandler[specListChannelsInput, specListChannelsOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "get-channel",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/channels/{id}",
		Summary:     "Get a notification channel",
		Tags:        []string{"Channels"},
	}, noopHandler[specGetChannelInput, specGetChannelOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "update-channel",
		Method:      http.MethodPatch,
		Path:        "/orgs/{org_id}/channels/{id}",
		Summary:     "Update a notification channel",
		Tags:        []string{"Channels"},
	}, noopHandler[specUpdateChannelInput, specUpdateChannelOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "delete-channel",
		Method:      http.MethodDelete,
		Path:        "/orgs/{org_id}/channels/{id}",
		Summary:     "Delete a notification channel",
		Tags:        []string{"Channels"},
	}, noopHandler[specDeleteChannelInput, struct{}]())

	huma.Register(api, huma.Operation{
		OperationID: "rotate-channel-secret",
		Method:      http.MethodPost,
		Path:        "/orgs/{org_id}/channels/{id}/rotate-secret",
		Summary:     "Rotate signing secret",
		Tags:        []string{"Channels"},
	}, noopHandler[specRotateSecretInput, specRotateSecretOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "clear-channel-secondary-secret",
		Method:      http.MethodPost,
		Path:        "/orgs/{org_id}/channels/{id}/clear-secondary",
		Summary:     "Clear secondary signing secret",
		Tags:        []string{"Channels"},
	}, noopHandler[specClearSecondaryInput, struct{}]())

	huma.Register(api, huma.Operation{
		OperationID: "test-channel",
		Method:      http.MethodPost,
		Path:        "/orgs/{org_id}/channels/{id}/test",
		Summary:     "Test a notification channel",
		Tags:        []string{"Channels"},
	}, noopHandler[specTestChannelInput, specTestChannelOutput]())
}

// ── Deliveries spec-only declarations ────────────────────────────────────────

type specListDeliveriesInput struct {
	OrgID     string `path:"org_id" format:"uuid" doc:"Organization ID"`
	RuleID    string `query:"rule_id" doc:"Filter by rule ID"`
	ChannelID string `query:"channel_id" doc:"Filter by channel ID"`
	Status    string `query:"status" doc:"Filter by status"`
	Cursor    string `query:"cursor" doc:"Pagination cursor"`
	Limit     int    `query:"limit" doc:"Max items per page (1-200, default 50)"`
}
type specListDeliveriesOutput struct {
	Body struct {
		Items      []deliveryEntry `json:"items"`
		NextCursor string          `json:"next_cursor,omitempty"`
	}
}

type specGetDeliveryInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string `path:"id" format:"uuid" doc:"Delivery ID"`
}
type specGetDeliveryOutput struct {
	Body deliveryDetail
}

type specReplayDeliveryInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string `path:"id" format:"uuid" doc:"Delivery ID"`
}

func registerDeliveriesSpecOps(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "list-deliveries",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/deliveries",
		Summary:     "List deliveries",
		Tags:        []string{"Deliveries"},
	}, noopHandler[specListDeliveriesInput, specListDeliveriesOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "get-delivery",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/deliveries/{id}",
		Summary:     "Get a delivery",
		Tags:        []string{"Deliveries"},
	}, noopHandler[specGetDeliveryInput, specGetDeliveryOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "replay-delivery",
		Method:      http.MethodPost,
		Path:        "/orgs/{org_id}/deliveries/{id}/replay",
		Summary:     "Replay a delivery",
		Tags:        []string{"Deliveries"},
	}, noopHandler[specReplayDeliveryInput, struct{}]())
}

// ── Reports spec-only declarations ───────────────────────────────────────────

type specCreateReportInput struct {
	OrgID string           `path:"org_id" format:"uuid" doc:"Organization ID"`
	Body  createReportBody `json:"body"`
}
type specCreateReportOutput struct {
	Location string      `header:"Location"`
	Body     reportEntry
}

type specListReportsInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
}
type specListReportsOutput struct {
	Body struct {
		Items []reportEntry `json:"items"`
	}
}

type specGetReportInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string `path:"id" format:"uuid" doc:"Report ID"`
}
type specGetReportOutput struct {
	Body reportEntry
}

type specUpdateReportInput struct {
	OrgID string          `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string          `path:"id" format:"uuid" doc:"Report ID"`
	Body  patchReportBody `json:"body"`
}
type specUpdateReportOutput struct {
	Body reportEntry
}

type specDeleteReportInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string `path:"id" format:"uuid" doc:"Report ID"`
}

type specListReportChannelsInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string `path:"id" format:"uuid" doc:"Report ID"`
}
type specListReportChannelsOutput struct {
	Body struct {
		Items []channelEntry `json:"items"`
	}
}

type specBindReportChannelInput struct {
	OrgID     string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID        string `path:"id" format:"uuid" doc:"Report ID"`
	ChannelID string `path:"channel_id" format:"uuid" doc:"Notification Channel ID"`
}

type specUnbindReportChannelInput struct {
	OrgID     string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID        string `path:"id" format:"uuid" doc:"Report ID"`
	ChannelID string `path:"channel_id" format:"uuid" doc:"Notification Channel ID"`
}

func registerReportsSpecOps(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "list-reports",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/reports",
		Summary:     "List scheduled reports",
		Tags:        []string{"Reports"},
	}, noopHandler[specListReportsInput, specListReportsOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "create-report",
		Method:      http.MethodPost,
		Path:        "/orgs/{org_id}/reports",
		Summary:     "Create a scheduled report",
		Tags:        []string{"Reports"},
	}, noopHandler[specCreateReportInput, specCreateReportOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "get-report",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/reports/{id}",
		Summary:     "Get a scheduled report",
		Tags:        []string{"Reports"},
	}, noopHandler[specGetReportInput, specGetReportOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "update-report",
		Method:      http.MethodPatch,
		Path:        "/orgs/{org_id}/reports/{id}",
		Summary:     "Update a scheduled report",
		Tags:        []string{"Reports"},
	}, noopHandler[specUpdateReportInput, specUpdateReportOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "delete-report",
		Method:      http.MethodDelete,
		Path:        "/orgs/{org_id}/reports/{id}",
		Summary:     "Delete a scheduled report",
		Tags:        []string{"Reports"},
	}, noopHandler[specDeleteReportInput, struct{}]())

	huma.Register(api, huma.Operation{
		OperationID: "list-report-channels",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/reports/{id}/channels",
		Summary:     "List channels bound to a report",
		Tags:        []string{"Reports"},
	}, noopHandler[specListReportChannelsInput, specListReportChannelsOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "bind-report-channel",
		Method:      http.MethodPut,
		Path:        "/orgs/{org_id}/reports/{id}/channels/{channel_id}",
		Summary:     "Bind a channel to a report",
		Tags:        []string{"Reports"},
	}, noopHandler[specBindReportChannelInput, struct{}]())

	huma.Register(api, huma.Operation{
		OperationID: "unbind-report-channel",
		Method:      http.MethodDelete,
		Path:        "/orgs/{org_id}/reports/{id}/channels/{channel_id}",
		Summary:     "Unbind a channel from a report",
		Tags:        []string{"Reports"},
	}, noopHandler[specUnbindReportChannelInput, struct{}]())
}

// ── Saved Searches spec-only declarations ────────────────────────────────────

type specCreateSavedSearchInput struct {
	OrgID string                 `path:"org_id" format:"uuid" doc:"Organization ID"`
	Body  createSavedSearchRequest `json:"body"`
}
type specCreateSavedSearchOutput struct {
	Location string           `header:"Location"`
	Body     savedSearchEntry
}

type specListSavedSearchesInput struct {
	OrgID      string `path:"org_id" format:"uuid" doc:"Organization ID"`
	Visibility string `query:"visibility" doc:"Filter by visibility (private, shared, all)"`
	Limit      int    `query:"limit" doc:"Max items per page (1-200, default 200)"`
}
type specListSavedSearchesOutput struct {
	Body struct {
		Items []savedSearchEntry `json:"items"`
	}
}

type specGetSavedSearchInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string `path:"id" format:"uuid" doc:"Saved Search ID"`
}
type specGetSavedSearchOutput struct {
	Body savedSearchEntry
}

type specUpdateSavedSearchInput struct {
	OrgID string                 `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string                 `path:"id" format:"uuid" doc:"Saved Search ID"`
	Body  patchSavedSearchRequest `json:"body"`
}
type specUpdateSavedSearchOutput struct {
	Body savedSearchEntry
}

type specDeleteSavedSearchInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID    string `path:"id" format:"uuid" doc:"Saved Search ID"`
}

type specExecuteSavedSearchInput struct {
	OrgID  string `path:"org_id" format:"uuid" doc:"Organization ID"`
	ID     string `path:"id" format:"uuid" doc:"Saved Search ID"`
	Cursor string `query:"cursor" doc:"Pagination cursor"`
	Limit  int    `query:"limit" doc:"Max results per page (1-100, default 25)"`
}
type specExecuteSavedSearchOutput struct {
	Body savedSearchExecuteResponse
}

func registerSavedSearchesSpecOps(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "list-saved-searches",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/saved-searches",
		Summary:     "List saved searches",
		Tags:        []string{"Saved Searches"},
	}, noopHandler[specListSavedSearchesInput, specListSavedSearchesOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "create-saved-search",
		Method:      http.MethodPost,
		Path:        "/orgs/{org_id}/saved-searches",
		Summary:     "Create a saved search",
		Tags:        []string{"Saved Searches"},
	}, noopHandler[specCreateSavedSearchInput, specCreateSavedSearchOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "get-saved-search",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/saved-searches/{id}",
		Summary:     "Get a saved search",
		Tags:        []string{"Saved Searches"},
	}, noopHandler[specGetSavedSearchInput, specGetSavedSearchOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "update-saved-search",
		Method:      http.MethodPatch,
		Path:        "/orgs/{org_id}/saved-searches/{id}",
		Summary:     "Update a saved search",
		Tags:        []string{"Saved Searches"},
	}, noopHandler[specUpdateSavedSearchInput, specUpdateSavedSearchOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "delete-saved-search",
		Method:      http.MethodDelete,
		Path:        "/orgs/{org_id}/saved-searches/{id}",
		Summary:     "Delete a saved search",
		Tags:        []string{"Saved Searches"},
	}, noopHandler[specDeleteSavedSearchInput, struct{}]())

	huma.Register(api, huma.Operation{
		OperationID: "execute-saved-search",
		Method:      http.MethodPost,
		Path:        "/orgs/{org_id}/saved-searches/{id}/execute",
		Summary:     "Execute a saved search",
		Tags:        []string{"Saved Searches"},
	}, noopHandler[specExecuteSavedSearchInput, specExecuteSavedSearchOutput]())
}

// ── SSO spec-only declarations ───────────────────────────────────────────────

type specCreateSSOInput struct {
	OrgID string        `path:"org_id" format:"uuid" doc:"Organization ID"`
	Body  createSSOBody `json:"body"`
}
type specCreateSSOOutput struct {
	Location string `header:"Location"`
	Body     ssoResponse
}

type specGetSSOInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
}
type specGetSSOOutput struct {
	Body ssoResponse
}

type specPatchSSOInput struct {
	OrgID string       `path:"org_id" format:"uuid" doc:"Organization ID"`
	Body  patchSSOBody `json:"body"`
}
type specPatchSSOOutput struct {
	Body ssoResponse
}

type specDeleteSSOInput struct {
	OrgID string `path:"org_id" format:"uuid" doc:"Organization ID"`
}

type specPutSSODomainsInput struct {
	OrgID string            `path:"org_id" format:"uuid" doc:"Organization ID"`
	Body  putSSODomainsBody `json:"body"`
}
type specPutSSODomainsOutput struct {
	Body struct {
		Domains []string `json:"domains"`
	}
}

type specDiscoverInput struct {
	Body discoverBody `json:"body"`
}
type specDiscoverOutput struct {
	Body discoverResponse
}

func registerSSOSpecOps(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "create-sso",
		Method:      http.MethodPost,
		Path:        "/orgs/{org_id}/sso",
		Summary:     "Create an SSO connection",
		Tags:        []string{"SSO"},
	}, noopHandler[specCreateSSOInput, specCreateSSOOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "get-sso",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/sso",
		Summary:     "Get SSO connection",
		Tags:        []string{"SSO"},
	}, noopHandler[specGetSSOInput, specGetSSOOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "patch-sso",
		Method:      http.MethodPatch,
		Path:        "/orgs/{org_id}/sso",
		Summary:     "Update SSO connection",
		Tags:        []string{"SSO"},
	}, noopHandler[specPatchSSOInput, specPatchSSOOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "delete-sso",
		Method:      http.MethodDelete,
		Path:        "/orgs/{org_id}/sso",
		Summary:     "Delete SSO connection",
		Tags:        []string{"SSO"},
	}, noopHandler[specDeleteSSOInput, struct{}]())

	huma.Register(api, huma.Operation{
		OperationID: "put-sso-domains",
		Method:      http.MethodPut,
		Path:        "/orgs/{org_id}/sso/domains",
		Summary:     "Set SSO email domains",
		Tags:        []string{"SSO"},
	}, noopHandler[specPutSSODomainsInput, specPutSSODomainsOutput]())

	huma.Register(api, huma.Operation{
		OperationID: "discover-sso",
		Method:      http.MethodPost,
		Path:        "/auth/discover",
		Summary:     "Discover SSO for email",
		Tags:        []string{"SSO"},
	}, noopHandler[specDiscoverInput, specDiscoverOutput]())
}

// ── Audit Log spec-only declarations ─────────────────────────────────────────

type specListAuditLogInput struct {
	OrgID      string `path:"org_id" format:"uuid" doc:"Organization ID"`
	EntityType string `query:"entity_type" doc:"Filter by entity type"`
	Action     string `query:"action" doc:"Filter by action"`
	ActorID    string `query:"actor_id" doc:"Filter by actor ID"`
	After      string `query:"after" doc:"Filter entries after timestamp (RFC3339)"`
	Before     string `query:"before" doc:"Filter entries before timestamp (RFC3339)"`
	Cursor     string `query:"cursor" doc:"Pagination cursor"`
	Limit      int    `query:"limit" doc:"Max items per page (1-200, default 100)"`
}
type specListAuditLogOutput struct {
	Body struct {
		Items      []auditLogListEntry `json:"items"`
		NextCursor string              `json:"next_cursor,omitempty"`
	}
}

func registerAuditLogSpecOps(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "list-audit-log",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/audit-log",
		Summary:     "List audit log entries",
		Tags:        []string{"Audit Log"},
	}, noopHandler[specListAuditLogInput, specListAuditLogOutput]())
}

// ── AI spec-only declarations ─────────────────────────────────────────────

func registerAISpecOps(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "nl-search",
		Method:      http.MethodPost,
		Path:        "/orgs/{org_id}/ai/nl-search",
		Summary:     "Natural language CVE search",
		Tags:        []string{"AI"},
	}, noopHandler[struct {
		OrgID  string `path:"org_id" format:"uuid"`
		Cursor string `query:"cursor,omitempty" doc:"Pagination cursor"`
		Limit  int    `query:"limit,omitempty" doc:"Results per page (1-100, default 25)"`
		Body   nlSearchRequest
	}, struct {
		Body nlSearchResponse
	}]())

	huma.Register(api, huma.Operation{
		OperationID: "summarize-cve",
		Method:      http.MethodPost,
		Path:        "/orgs/{org_id}/ai/summarize/{cve_id}",
		Summary:     "Summarize a CVE",
		Tags:        []string{"AI"},
	}, noopHandler[struct {
		OrgID string `path:"org_id" format:"uuid"`
		CVEID string `path:"cve_id"`
	}, struct {
		Body summarizeResponse
	}]())
}

// ── Ingest spec-only declarations ─────────────────────────────────────────

func registerIngestSpecOps(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "ingest-cves",
		Method:      http.MethodPost,
		Path:        "/orgs/{org_id}/ingest",
		Summary:     "Ingest CVE patches",
		Tags:        []string{"Ingest"},
	}, noopHandler[struct {
		OrgID string `path:"org_id" format:"uuid"`
		Body  ingestRequest
	}, struct {
		Body ingestResponse
	}]())
}

// ── Org Tier spec-only declarations ───────────────────────────────────────

func registerOrgTierSpecOps(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "get-org-tier",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/tier",
		Summary:     "Get org tier and limits",
		Tags:        []string{"Tier"},
	}, noopHandler[struct {
		OrgID string `path:"org_id" format:"uuid"`
	}, struct {
		Body tierResponse
	}]())
}

// ── Admin Feeds spec ops ────────────────────────────────────────────────────

func registerAdminFeedsSpecOps(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "list-feeds",
		Method:      http.MethodGet,
		Path:        "/admin/feeds",
		Summary:     "List feed sync status",
		Tags:        []string{"Admin Feeds"},
	}, noopHandler[struct{}, struct {
		Body listResponse[FeedStatusEntry]
	}]())

	huma.Register(api, huma.Operation{
		OperationID: "trigger-feed",
		Method:      http.MethodPost,
		Path:        "/admin/feeds/{feed}/run",
		Summary:     "Trigger feed sync",
		Tags:        []string{"Admin Feeds"},
	}, noopHandler[struct {
		Feed string `path:"feed"`
	}, struct {
		Body struct {
			JobID string `json:"job_id"`
		}
	}]())

	huma.Register(api, huma.Operation{
		OperationID: "pause-feed",
		Method:      http.MethodPost,
		Path:        "/admin/feeds/{feed}/pause",
		Summary:     "Pause feed sync",
		Tags:        []string{"Admin Feeds"},
	}, noopHandler[struct {
		Feed string `path:"feed"`
	}, struct {
		Body struct {
			Status string `json:"status"`
			Feed   string `json:"feed"`
		}
	}]())

	huma.Register(api, huma.Operation{
		OperationID: "resume-feed",
		Method:      http.MethodPost,
		Path:        "/admin/feeds/{feed}/resume",
		Summary:     "Resume feed sync",
		Tags:        []string{"Admin Feeds"},
	}, noopHandler[struct {
		Feed string `path:"feed"`
	}, struct {
		Body struct {
			Status string `json:"status"`
			Feed   string `json:"feed"`
		}
	}]())

	huma.Register(api, huma.Operation{
		OperationID: "list-feed-logs",
		Method:      http.MethodGet,
		Path:        "/admin/feeds/{feed}/logs",
		Summary:     "List feed fetch logs",
		Tags:        []string{"Admin Feeds"},
	}, noopHandler[struct {
		Feed   string `path:"feed"`
		Cursor string `query:"cursor,omitempty"`
		Limit  int    `query:"limit,omitempty"`
	}, struct {
		Body listResponse[FeedLogEntry]
	}]())
}

// ── Admin System spec ops ───────────────────────────────────────────────────

func registerAdminSystemSpecOps(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "admin-reindex",
		Method:      http.MethodPost,
		Path:        "/admin/reindex",
		Summary:     "Trigger search reindex",
		Tags:        []string{"Admin System"},
	}, noopHandler[struct{}, struct {
		Body struct {
			JobID string `json:"job_id"`
		}
	}]())

	huma.Register(api, huma.Operation{
		OperationID: "admin-config",
		Method:      http.MethodGet,
		Path:        "/admin/config",
		Summary:     "View runtime configuration",
		Tags:        []string{"Admin System"},
	}, noopHandler[struct{}, struct {
		Body map[string]any
	}]())

	huma.Register(api, huma.Operation{
		OperationID: "admin-audit-log",
		Method:      http.MethodGet,
		Path:        "/admin/audit-log",
		Summary:     "Cross-org audit log",
		Tags:        []string{"Admin System"},
	}, noopHandler[struct {
		Cursor     string `query:"cursor,omitempty"`
		Limit      int    `query:"limit,omitempty"`
		EntityType string `query:"entity_type,omitempty"`
		Action     string `query:"action,omitempty"`
		OrgID      string `query:"org_id,omitempty"`
		ActorID    string `query:"actor_id,omitempty"`
	}, struct {
		Body listResponse[store.AuditRow]
	}]())
}
