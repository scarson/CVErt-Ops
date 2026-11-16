// ABOUTME: Compares every API response type's v1 encoding/json output with its encoding/json/v2 output.
// ABOUTME: Fails on any field whose presence or value would change, other than nil collections becoming [] or {}.
package api

import (
	"bytes"
	"encoding"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/check"
	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/doctor"
	"github.com/scarson/cvert-ops/internal/store"
)

// schemaRefPrefix is the prefix huma gives every component schema reference.
const schemaRefPrefix = "#/components/schemas/"

// minResolvedResponseTypes is the number of response component schemas that
// resolved to a Go type when this test was written. A drop means schemas
// stopped resolving and the test would silently measure less.
const minResolvedResponseTypes = 129

// maxResponsePointerDepth bounds how many pointer hops the measured values
// follow when they set every pointer to a zero value, so recursive types end.
const maxResponsePointerDepth = 3

// unresolvableResponseSchemas lists response component schemas that resolve to
// no Go type in either registry, each with the reason.
var unresolvableResponseSchemas = map[string]string{}

// arrayIndexPattern matches an array index in a difference's path, which the
// allowlist writes as "[]".
var arrayIndexPattern = regexp.MustCompile(`\[\d+\]`)

// allowedEncodingDifferences lists differences, keyed "Schema.path" with each
// array index written as "[]", that are accepted although they are not a nil
// collection becoming [] or {}.
var allowedEncodingDifferences = map[string]string{
	// huma.ErrorModel.Status is an int tagged omitempty in huma itself and cannot
	// be retagged. v2 writes "status":0 where v1 omits it, but every problem
	// writer in this package and every huma error sets a non-zero status, so a
	// served response never carries a zero status.
	"ErrorModel.status": "huma-owned field; every writer sets a non-zero status",
	// huma.ErrorDetail.Value is an any tagged omitempty in huma itself and
	// cannot be retagged. When it holds "", [] or {}, v1 writes the member and v2
	// omits it; huma echoes [] for example on a minItems failure. The client
	// then loses which empty value it sent, a small loss for a value it already
	// has.
	"ErrorDetail.value": "huma-owned field; an empty echoed value is dropped",
	// The same ErrorDetail.Value, inside a problem's errors list.
	"ErrorModel.errors[].value": "huma-owned field; an empty echoed value is dropped",
}

// encodingDifferenceClass names how a v1 and a v2 output differ at one path.
type encodingDifferenceClass string

const (
	differenceExpected encodingDifferenceClass = "expected" // v1 null, v2 [] or {}
	differencePresence encodingDifferenceClass = "presence" // key in one output only
	differenceError    encodingDifferenceClass = "error"    // a marshal failed
	differenceOther    encodingDifferenceClass = "other"    // any other value change
)

// encodingDifference is one path at which the two encodings differ.
type encodingDifference struct {
	class   encodingDifferenceClass
	key     string // "Schema.path", the allowlist key
	variant string
	goType  string
	v1, v2  string
}

func (d encodingDifference) String() string {
	return fmt.Sprintf("[%s] %s: v1=%s v2=%s (variant %s, type %s)", d.class, d.key, d.v1, d.v2, d.variant, d.goType)
}

// measuredResponse is one response shape to encode both ways.
type measuredResponse struct {
	name string
	typ  reflect.Type
	// build returns a fixed value to encode; nil means build from typ once
	// per responseValueVariants entry.
	build func() any
}

// writeJSONResponseValues lists the values passed to writeJSON, the problem
// writers, readyz and healthz, so the types the OpenAPI components do not
// cover are measured too. A type already measured through its schema is
// skipped. Map literals whose values are all strings, numbers or bools encode
// identically in both versions; they are kept here so the list stays complete.
func writeJSONResponseValues() []measuredResponse {
	typeOf := func(name string, t reflect.Type) measuredResponse { return measuredResponse{name: name, typ: t} }
	literal := func(name string, v any) measuredResponse {
		return measuredResponse{name: name, typ: reflect.TypeOf(v), build: func() any { return v }}
	}
	return []measuredResponse{
		typeOf("huma.ErrorModel", reflect.TypeFor[huma.ErrorModel]()),
		typeOf("huma.ErrorDetail", reflect.TypeFor[huma.ErrorDetail]()),
		literal("adminRetryDeliveryHandler", map[string]any{"status": "", "delivery_id": "", "rows_affected": int64(0)}),
		literal("adminBulkRetryDeliveriesHandler", map[string]any{"status": "", "rows_affected": int64(0)}),
		literal("doctorHandler", map[string]any{"status": "", "checks": []doctor.Result(nil)}),
		typeOf("doctor.Result", reflect.TypeFor[doctor.Result]()),
		literal("adminResetMFAHandler", map[string]string{"status": "", "user_id": ""}),
		literal("adminUpdateOrgMFASettingsHandler", map[string]any{"mfa_required_all": false, "mfa_remember_device_allowed": false, "mfa_remember_device_days": int32(0)}),
		typeOf("adminOrgResponse", reflect.TypeFor[adminOrgResponse]()),
		typeOf("store.AdminOrgUsage", reflect.TypeFor[*store.AdminOrgUsage]()),
		literal("adminConfigHandler", map[string]any{"listen_addr": "", "cookie_secure": false, "db_max_conns": int32(0)}),
		typeOf("nlSearchResult", reflect.TypeFor[nlSearchResult]()),
		typeOf("summarizeResponse", reflect.TypeFor[summarizeResponse]()),
		typeOf("alertRuleEntry", reflect.TypeFor[alertRuleEntry]()),
		typeOf("validateRuleResponse", reflect.TypeFor[validateRuleResponse]()),
		typeOf("dryRunResponse", reflect.TypeFor[dryRunResponse]()),
		typeOf("createAPIKeyResponse", reflect.TypeFor[createAPIKeyResponse]()),
		typeOf("channelCreateEntry", reflect.TypeFor[channelCreateEntry]()),
		typeOf("ChannelEntry", reflect.TypeFor[ChannelEntry]()),
		typeOf("rotateSecretResponse", reflect.TypeFor[rotateSecretResponse]()),
		typeOf("testChannelResult", reflect.TypeFor[testChannelResult]()),
		typeOf("check.Results", reflect.TypeFor[check.Results]()),
		typeOf("deliveryDetail", reflect.TypeFor[deliveryDetail]()),
		typeOf("groupEntry", reflect.TypeFor[groupEntry]()),
		typeOf("ingestResponse", reflect.TypeFor[ingestResponse]()),
		typeOf("tierResponse", reflect.TypeFor[tierResponse]()),
		typeOf("createOrgResponseBody", reflect.TypeFor[createOrgResponseBody]()),
		typeOf("orgResponseBody", reflect.TypeFor[orgResponseBody]()),
		typeOf("patchMemberResponseBody", reflect.TypeFor[patchMemberResponseBody]()),
		typeOf("invitationEntry", reflect.TypeFor[invitationEntry]()),
		typeOf("reportEntry", reflect.TypeFor[reportEntry]()),
		typeOf("savedSearchEntry", reflect.TypeFor[savedSearchEntry]()),
		typeOf("scimConfigResponse", reflect.TypeFor[scimConfigResponse]()),
		typeOf("rotateTokenResponse", reflect.TypeFor[rotateTokenResponse]()),
		typeOf("listSCIMGroupsResponse", reflect.TypeFor[listSCIMGroupsResponse]()),
		typeOf("scimGroupResponse", reflect.TypeFor[scimGroupResponse]()),
		typeOf("ssoResponse", reflect.TypeFor[ssoResponse]()),
		literal("putSSODomainsHandler", map[string]any{"domains": []string(nil)}),
		typeOf("discoverResponse", reflect.TypeFor[discoverResponse]()),
		typeOf("watchlistEntry", reflect.TypeFor[watchlistEntry]()),
		typeOf("watchlistItemEntry", reflect.TypeFor[watchlistItemEntry]()),
		typeOf("watchlistItemsReplaced", reflect.TypeFor[watchlistItemsReplaced]()),
		typeOf("callerIdentity", reflect.TypeFor[callerIdentity]()),
		literal("readyzHandler", map[string]any{
			"status": "",
			"checks": map[string]any{
				"database":        map[string]any{"status": "", "latency_ms": int64(0)},
				"migrations":      map[string]any{"status": "", "version": 0, "dirty": false},
				"worker":          map[string]any{"goroutines": 0},
				"delivery_worker": map[string]any{"status": ""},
			},
		}),
		literal("healthzHandler", map[string]string{"status": ""}),
		// Handlers that write a map[string]string, which both versions encode alike.
		literal("adminForcePasswordResetHandler", map[string]string{"status": "", "user_id": ""}),
		literal("adminRequireMFAHandler", map[string]string{"status": "", "user_id": ""}),
		literal("adminReindexHandler", map[string]string{"job_id": ""}),
		literal("adminReloadConfigHandler", map[string]string{"message": ""}),
		literal("adminDisableUserHandler", map[string]string{"status": "", "user_id": ""}),
		literal("adminEnableUserHandler", map[string]string{"status": "", "user_id": ""}),
		literal("adminUnlockUserHandler", map[string]string{"status": "", "user_id": ""}),
		literal("adminResetPasswordHandler", map[string]string{"status": "", "user_id": ""}),
		literal("versionHandler", map[string]string{"version": ""}),
		literal("triggerFeedHandler", map[string]string{"job_id": ""}),
		literal("pauseFeedHandler", map[string]string{"status": "", "feed": ""}),
		literal("resumeFeedHandler", map[string]string{"status": "", "feed": ""}),
		literal("oidcCallbackHandler", map[string]string{"user_id": ""}),
		literal("oidcLinkCallbackHandler", map[string]string{"status": ""}),
	}
}

// TestResponseEncoding encodes every response type with v1 and with v2 and
// reports each path whose output differs.
func TestResponseEncoding(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:   "test-secret-for-openapi-generation",
		ExternalURL: "http://localhost:8080",
		FrontendURL: "/",
	}
	srv, err := NewServer(nil, cfg, ServerDeps{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Close)
	srv.Handler()
	prodRegistry := srv.humaAPI.OpenAPI().Components.Schemas

	specOnly := newSpecOnlyAPI()
	registerAllSpecOps(specOnly)
	specOnlyRegistry := specOnly.OpenAPI().Components.Schemas

	docs := []map[string]any{specAsMap(t, srv.humaAPI.OpenAPI()), specAsMap(t, specOnly.OpenAPI())}
	names := responseSchemaNames(docs)

	var measured []measuredResponse
	seen := map[reflect.Type]bool{}
	var unresolved []string
	for _, name := range names {
		typ := prodRegistry.TypeFromRef(schemaRefPrefix + name)
		if typ == nil {
			typ = specOnlyRegistry.TypeFromRef(schemaRefPrefix + name)
		}
		if typ == nil {
			if _, ok := unresolvableResponseSchemas[name]; !ok {
				unresolved = append(unresolved, name)
			}
			continue
		}
		seen[typ] = true
		measured = append(measured, measuredResponse{name: name, typ: typ})
	}
	for _, name := range unresolved {
		t.Errorf("response schema %q resolves to no Go type in either registry and is not in unresolvableResponseSchemas", name)
	}
	t.Logf("response schemas: %d collected, %d resolved", len(names), len(measured))
	if len(measured) < minResolvedResponseTypes {
		t.Errorf("only %d response schemas resolved to a Go type, want at least %d", len(measured), minResolvedResponseTypes)
	}

	for _, extra := range writeJSONResponseValues() {
		if extra.build == nil && seen[extra.typ] {
			t.Logf("writeJSON value %s already measured through its schema", extra.name)
			continue
		}
		if extra.build == nil {
			seen[extra.typ] = true
		}
		measured = append(measured, extra)
	}

	checked := map[reflect.Type]bool{}
	for _, m := range measured {
		for _, field := range omitzeroNullablePointers(m.typ, checked) {
			t.Errorf("%s: a pointer to a non-object value tagged omitzero needs nullable:\"false\"; huma documents it as nullable otherwise, and v2 never writes null for it", field)
		}
	}

	var diffs []encodingDifference
	for _, m := range measured {
		if m.build != nil {
			diffs = append(diffs, compareEncodings(m.name, "literal", m.typ.String(), m.build())...)
			continue
		}
		for _, variant := range responseValueVariants {
			v := buildResponseValue(m.typ, variant).Interface()
			diffs = append(diffs, compareEncodings(m.name, variant.name, m.typ.String(), v)...)
		}
	}

	counts := map[encodingDifferenceClass]int{}
	for _, d := range diffs {
		counts[d.class]++
		t.Log(d.String())
		if d.class == differenceExpected {
			continue
		}
		if _, ok := allowedEncodingDifferences[arrayIndexPattern.ReplaceAllString(d.key, "[]")]; ok {
			continue
		}
		t.Errorf("encoding changes and is not allowlisted: %s", d)
	}
	t.Logf("measured %d response shapes; differences: expected=%d presence=%d error=%d other=%d",
		len(measured), counts[differenceExpected], counts[differencePresence], counts[differenceError], counts[differenceOther])
}

// omitzeroNullablePointers returns, as "Type.Field", every struct field
// reachable from t that is a pointer whose element is not a plain struct, is
// tagged omitzero, and lacks nullable:"false". huma documents such a pointer
// as nullable and clears that only for omitempty (huma@v2.37.3
// schema.go:927-931), so the field would appear as "type or null" in
// openapi.json although v2 never writes null for it.
func omitzeroNullablePointers(t reflect.Type, checked map[reflect.Type]bool) []string {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array || t.Kind() == reflect.Map {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || checked[t] {
		return nil
	}
	checked[t] = true
	var out []string
	for i := range t.NumField() {
		f := t.Field(i)
		if f.Type.Kind() == reflect.Pointer && !isPlainStruct(f.Type.Elem()) &&
			strings.Contains(f.Tag.Get("json"), "omitzero") && f.Tag.Get("nullable") != "false" {
			out = append(out, t.String()+"."+f.Name)
		}
		out = append(out, omitzeroNullablePointers(f.Type, checked)...)
	}
	return out
}

// isPlainStruct reports whether huma documents t as an object: a struct that
// is not time.Time or url.URL and has no UnmarshalText method (huma documents
// those, netip.Addr among them, as strings). Anything else, including
// uuid.UUID, net.IP and every scalar, is documented as a value huma makes
// nullable behind a pointer.
func isPlainStruct(t reflect.Type) bool {
	return t.Kind() == reflect.Struct &&
		t != reflect.TypeFor[time.Time]() &&
		t != reflect.TypeFor[url.URL]() &&
		!reflect.PointerTo(t).Implements(reflect.TypeFor[encoding.TextUnmarshaler]())
}

func TestIsPlainStruct(t *testing.T) {
	for _, tc := range []struct {
		typ  reflect.Type
		want bool
	}{
		{reflect.TypeFor[check.Advisory](), true},
		{reflect.TypeFor[huma.ErrorModel](), true},
		{reflect.TypeFor[string](), false},
		{reflect.TypeFor[int64](), false},
		{reflect.TypeFor[time.Time](), false},
		{reflect.TypeFor[url.URL](), false},
		{reflect.TypeFor[netip.Addr](), false},
		{reflect.TypeFor[netip.Prefix](), false},
		{reflect.TypeFor[net.IP](), false},
		{reflect.TypeFor[uuid.UUID](), false},
		{reflect.TypeFor[[]string](), false},
	} {
		if got := isPlainStruct(tc.typ); got != tc.want {
			t.Errorf("isPlainStruct(%s) = %v, want %v", tc.typ, got, tc.want)
		}
	}
}

// TestWriteJSONMapLiteralsListed verifies that every handler in this package
// that passes writeJSON a map, written inline or held in a variable assigned
// from a map literal in the same function, has an entry in
// writeJSONResponseValues, so TestResponseEncoding measures its shape. A
// named type needs no entry: its schema or typeOf entry covers it.
func TestWriteJSONMapLiteralsListed(t *testing.T) {
	listed := map[string]bool{}
	for _, v := range writeJSONResponseValues() {
		if v.build != nil {
			listed[v.name] = true
		}
	}

	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	fset := token.NewFileSet()
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			mapVars := map[string]bool{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if assign, ok := n.(*ast.AssignStmt); ok {
					for i, rhs := range assign.Rhs {
						if isMapLiteral(rhs) && i < len(assign.Lhs) {
							if id, ok := assign.Lhs[i].(*ast.Ident); ok {
								mapVars[id.Name] = true
							}
						}
					}
				}
				return true
			})
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) != 3 {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "writeJSON" {
					return true
				}
				arg := call.Args[2]
				id, isIdent := arg.(*ast.Ident)
				if (isMapLiteral(arg) || (isIdent && mapVars[id.Name])) && !listed[fn.Name.Name] {
					t.Errorf("%s: %s passes writeJSON a map and has no entry in writeJSONResponseValues", fset.Position(call.Pos()), fn.Name.Name)
				}
				return true
			})
		}
	}
}

// isMapLiteral reports whether e is a composite literal of a map type.
func isMapLiteral(e ast.Expr) bool {
	lit, ok := e.(*ast.CompositeLit)
	if !ok {
		return false
	}
	_, isMap := lit.Type.(*ast.MapType)
	return isMap
}

// specAsMap returns an OpenAPI document as generic JSON values.
func specAsMap(t *testing.T, spec *huma.OpenAPI) map[string]any {
	t.Helper()
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal spec: %v", err)
	}
	return m
}

// responseSchemaNames returns, sorted, every component schema reachable from a
// response body of any operation in docs.
func responseSchemaNames(docs []map[string]any) []string {
	components := map[string]any{}
	for _, doc := range docs {
		comps, _ := doc["components"].(map[string]any)
		schemas, _ := comps["schemas"].(map[string]any)
		for name, s := range schemas {
			components[name] = s
		}
	}

	found := map[string]bool{}
	var queue []string
	add := func(node any) {
		collectSchemaRefs(node, func(name string) {
			if !found[name] {
				found[name] = true
				queue = append(queue, name)
			}
		})
	}
	for _, doc := range docs {
		paths, _ := doc["paths"].(map[string]any)
		for _, item := range paths {
			ops, _ := item.(map[string]any)
			for _, op := range ops {
				opMap, ok := op.(map[string]any)
				if !ok {
					continue
				}
				responses, _ := opMap["responses"].(map[string]any)
				for _, resp := range responses {
					respMap, _ := resp.(map[string]any)
					add(respMap["content"])
				}
			}
		}
	}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		add(components[name])
	}

	names := make([]string, 0, len(found))
	for name := range found {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// collectSchemaRefs calls visit with the component name of every schema $ref
// inside node.
func collectSchemaRefs(node any, visit func(string)) {
	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			if s, ok := v.(string); ok && k == "$ref" && strings.HasPrefix(s, schemaRefPrefix) {
				visit(strings.TrimPrefix(s, schemaRefPrefix))
				continue
			}
			collectSchemaRefs(v, visit)
		}
	case []any:
		for _, v := range n {
			collectSchemaRefs(v, visit)
		}
	}
}

// responseValueVariant sets how a measured value fills its json.RawMessage,
// empty-interface, slice and map fields.
type responseValueVariant struct {
	name  string
	raw   json.RawMessage // nil leaves every json.RawMessage nil
	iface any             // nil leaves every empty interface nil
	// elements puts one element, filled the same way, into every slice and
	// one entry with the zero key into every map; otherwise they stay nil.
	elements bool
}

// responseValueVariants are the fills each measured type is encoded with:
// each raw and interface fill, once with nil collections and once with one
// element in each. The raw values are what JSONB columns produce; a
// zero-length non-nil json.RawMessage is left out because no column can
// produce one.
var responseValueVariants = func() []responseValueVariant {
	fills := []responseValueVariant{
		{name: "nil"},
		{name: "empty-string", iface: ""},
		{name: "empty-object", raw: json.RawMessage(`{}`), iface: map[string]any{}},
		{name: "empty-array", raw: json.RawMessage(`[]`), iface: []any{}},
		{name: "null-raw", raw: json.RawMessage(`null`)},
	}
	variants := make([]responseValueVariant, 0, 2*len(fills))
	for _, f := range fills {
		variants = append(variants, f)
		f.name += "+elements"
		f.elements = true
		variants = append(variants, f)
	}
	return variants
}()

// rawMessageType is the type of json.RawMessage fields.
var rawMessageType = reflect.TypeFor[json.RawMessage]()

// buildResponseValue returns a value of type t in which every settable pointer
// points at a zero value, every json.RawMessage and empty interface holds the
// variant's value, and every slice and map is nil or, with the variant's
// elements, holds one element filled the same way. Pointers, slice elements
// and map values together go at most maxResponsePointerDepth levels deep.
func buildResponseValue(t reflect.Type, variant responseValueVariant) reflect.Value {
	v := reflect.New(t).Elem()
	fillResponseValue(v, 0, variant)
	return v
}

func fillResponseValue(v reflect.Value, depth int, variant responseValueVariant) {
	if v.Type() == rawMessageType {
		if variant.raw != nil && v.CanSet() {
			v.Set(reflect.ValueOf(variant.raw))
		}
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		if depth >= maxResponsePointerDepth || !v.CanSet() {
			return
		}
		p := reflect.New(v.Type().Elem())
		fillResponseValue(p.Elem(), depth+1, variant)
		v.Set(p)
	case reflect.Struct:
		for i := range v.NumField() {
			// Exported fields of an unexported embedded struct are settable
			// even when the embedded field itself is not.
			fillResponseValue(v.Field(i), depth, variant)
		}
	case reflect.Array:
		for i := range v.Len() {
			fillResponseValue(v.Index(i), depth, variant)
		}
	case reflect.Slice:
		if !variant.elements || depth >= maxResponsePointerDepth || !v.CanSet() {
			return
		}
		s := reflect.MakeSlice(v.Type(), 1, 1)
		fillResponseValue(s.Index(0), depth+1, variant)
		v.Set(s)
	case reflect.Map:
		if !variant.elements || depth >= maxResponsePointerDepth || !v.CanSet() {
			return
		}
		m := reflect.MakeMapWithSize(v.Type(), 1)
		elem := reflect.New(v.Type().Elem()).Elem()
		fillResponseValue(elem, depth+1, variant)
		m.SetMapIndex(reflect.New(v.Type().Key()).Elem(), elem)
		v.Set(m)
	case reflect.Interface:
		if variant.iface != nil && v.CanSet() && v.NumMethod() == 0 {
			v.Set(reflect.ValueOf(variant.iface))
		}
	default:
	}
}

// compareEncodings encodes v with v1 and with v2 and returns each path at
// which the decoded outputs differ, keyed under name.
func compareEncodings(name, variant, goType string, v any) []encodingDifference {
	diff := func(class encodingDifferenceClass, path, v1, v2 string) encodingDifference {
		return encodingDifference{class: class, key: name + path, variant: variant, goType: goType, v1: v1, v2: v2}
	}
	v1Bytes, v1Err := json.Marshal(v)
	v2Bytes, v2Err := jsonv2.Marshal(v, responseJSONOptions)
	if v1Err != nil || v2Err != nil {
		return []encodingDifference{diff(differenceError, "", fmt.Sprint(v1Err), fmt.Sprint(v2Err))}
	}
	v1Val, err := decodeGeneric(v1Bytes)
	if err != nil {
		return []encodingDifference{diff(differenceError, "", "undecodable: "+err.Error(), string(v2Bytes))}
	}
	v2Val, err := decodeGeneric(v2Bytes)
	if err != nil {
		return []encodingDifference{diff(differenceError, "", string(v1Bytes), "undecodable: "+err.Error())}
	}
	var out []encodingDifference
	walkEncodings("", v1Val, v2Val, func(class encodingDifferenceClass, path, a, b string) {
		out = append(out, diff(class, path, a, b))
	})
	return out
}

func decodeGeneric(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	err := dec.Decode(&v)
	return v, err
}

const absentValue = "<absent>"

func walkEncodings(path string, a, b any, report func(class encodingDifferenceClass, path, a, b string)) {
	if reflect.DeepEqual(a, b) {
		return
	}
	if a == nil {
		if bs, ok := b.([]any); ok && len(bs) == 0 {
			report(differenceExpected, path, "null", "[]")
			return
		}
		if bm, ok := b.(map[string]any); ok && len(bm) == 0 {
			report(differenceExpected, path, "null", "{}")
			return
		}
	}
	am, aIsMap := a.(map[string]any)
	bm, bIsMap := b.(map[string]any)
	if aIsMap && bIsMap {
		keys := map[string]bool{}
		for k := range am {
			keys[k] = true
		}
		for k := range bm {
			keys[k] = true
		}
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			av, aok := am[k]
			bv, bok := bm[k]
			switch {
			case aok && bok:
				walkEncodings(path+"."+k, av, bv, report)
			case aok:
				report(differencePresence, path+"."+k, renderJSON(av), absentValue)
			default:
				report(differencePresence, path+"."+k, absentValue, renderJSON(bv))
			}
		}
		return
	}
	as, aIsSlice := a.([]any)
	bs, bIsSlice := b.([]any)
	if aIsSlice && bIsSlice && len(as) == len(bs) {
		for i := range as {
			walkEncodings(fmt.Sprintf("%s[%d]", path, i), as[i], bs[i], report)
		}
		return
	}
	report(differenceOther, path, renderJSON(a), renderJSON(b))
}

func renderJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}
