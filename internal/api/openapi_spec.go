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
	// Each subsequent task adds its registration call here.
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
