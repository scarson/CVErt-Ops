// ABOUTME: SCIM 2.0 discovery endpoints (ServiceProviderConfig, Schemas, ResourceTypes).
// ABOUTME: Static JSON responses per RFC 7643/7644. Declares supported capabilities to IdPs.
package api

import "net/http"

// scimServiceProviderConfig returns SCIM capabilities (RFC 7644 §4).
func (srv *Server) scimServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	writeSCIMJSON(w, http.StatusOK, map[string]any{
		"schemas":        []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":          map[string]any{"supported": true},
		"bulk":           map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":         map[string]any{"supported": true, "maxResults": 200},
		"changePassword": map[string]any{"supported": false},
		"sort":           map[string]any{"supported": false},
		"etag":           map[string]any{"supported": false},
		"authenticationSchemes": []map[string]any{
			{
				"type":        "oauthbearertoken",
				"name":        "Bearer Token",
				"description": "Authentication via org-scoped SCIM bearer token",
			},
		},
	})
}

// scimSchemas returns User and Group schema definitions (RFC 7643 §7).
func (srv *Server) scimSchemas(w http.ResponseWriter, r *http.Request) {
	userSchema := map[string]any{
		"id":          "urn:ietf:params:scim:schemas:core:2.0:User",
		"name":        "User",
		"description": "User Account",
		"attributes": []map[string]any{
			{"name": "userName", "type": "string", "multiValued": false, "required": true, "mutability": "readWrite", "uniqueness": "server"},
			{"name": "displayName", "type": "string", "multiValued": false, "required": false, "mutability": "readWrite"},
			{"name": "active", "type": "boolean", "multiValued": false, "required": false, "mutability": "readWrite"},
			{"name": "externalId", "type": "string", "multiValued": false, "required": false, "mutability": "readWrite"},
		},
		"meta": map[string]any{
			"resourceType": "Schema",
			"location":     "/Schemas/urn:ietf:params:scim:schemas:core:2.0:User",
		},
	}
	groupSchema := map[string]any{
		"id":          "urn:ietf:params:scim:schemas:core:2.0:Group",
		"name":        "Group",
		"description": "Group",
		"attributes": []map[string]any{
			{"name": "displayName", "type": "string", "multiValued": false, "required": true, "mutability": "readWrite"},
			{"name": "externalId", "type": "string", "multiValued": false, "required": false, "mutability": "readWrite"},
			{"name": "members", "type": "complex", "multiValued": true, "required": false, "mutability": "readWrite",
				"subAttributes": []map[string]any{
					{"name": "value", "type": "string", "mutability": "immutable"},
					{"name": "display", "type": "string", "mutability": "readOnly"},
				},
			},
		},
		"meta": map[string]any{
			"resourceType": "Schema",
			"location":     "/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group",
		},
	}
	writeSCIMJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": 2,
		"Resources":    []any{userSchema, groupSchema},
	})
}

// scimResourceTypes returns metadata for User and Group resources (RFC 7643 §6).
func (srv *Server) scimResourceTypes(w http.ResponseWriter, r *http.Request) {
	writeSCIMJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": 2,
		"Resources": []any{
			map[string]any{
				"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
				"id":       "User",
				"name":     "User",
				"endpoint": "/Users",
				"schema":   "urn:ietf:params:scim:schemas:core:2.0:User",
				"meta":     map[string]any{"resourceType": "ResourceType", "location": "/ResourceTypes/User"},
			},
			map[string]any{
				"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
				"id":       "Group",
				"name":     "Group",
				"endpoint": "/Groups",
				"schema":   "urn:ietf:params:scim:schemas:core:2.0:Group",
				"meta":     map[string]any{"resourceType": "ResourceType", "location": "/ResourceTypes/Group"},
			},
		},
	})
}
