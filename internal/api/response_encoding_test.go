// ABOUTME: Compares every API response type's v1 encoding/json output with its encoding/json/v2 output.
// ABOUTME: Fails on any field whose presence or value would change, other than nil collections becoming [] or {}.
package api

import (
	"bytes"
	"encoding"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"

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

// allowedEncodingDifferences lists differences, keyed "Schema.path", that are
// accepted although they are not a nil collection becoming [] or {}.
var allowedEncodingDifferences = map[string]string{
	// huma.ErrorModel.Status is an int tagged omitempty in huma itself and cannot
	// be retagged. v2 writes "status":0 where v1 omits it, but every problem
	// writer in this package and every huma error sets a non-zero status, so a
	// served response never carries a zero status.
	"ErrorModel.status": "huma-owned field; every writer sets a non-zero status",
	// huma.ErrorDetail.Value is an any tagged omitempty in huma itself and
	// cannot be retagged. When it holds "", v1 writes "value":"" and v2 omits
	// the member. An empty echoed value tells a client nothing, so its absence
	// loses no information.
	"ErrorDetail.value": "huma-owned field; an empty echoed value carries no information",
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
		literal("admin_deliveries.go:107", map[string]any{"status": "", "delivery_id": "", "rows_affected": int64(0)}),
		literal("admin_deliveries.go:139", map[string]any{"status": "", "rows_affected": int64(0)}),
		literal("admin_doctor.go:54", map[string]any{"status": "", "checks": []doctor.Result(nil)}),
		typeOf("doctor.Result", reflect.TypeFor[doctor.Result]()),
		literal("admin_mfa.go:105", map[string]string{"status": "", "user_id": ""}),
		literal("admin_mfa.go:396", map[string]any{"mfa_required_all": false, "mfa_remember_device_allowed": false, "mfa_remember_device_days": int32(0)}),
		typeOf("adminOrgResponse", reflect.TypeFor[adminOrgResponse]()),
		typeOf("store.AdminOrgUsage", reflect.TypeFor[*store.AdminOrgUsage]()),
		literal("admin_system.go:39", map[string]any{"listen_addr": "", "cookie_secure": false, "db_max_conns": int32(0)}),
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
		literal("sso.go:546", map[string]any{"domains": []string(nil)}),
		typeOf("discoverResponse", reflect.TypeFor[discoverResponse]()),
		typeOf("watchlistEntry", reflect.TypeFor[watchlistEntry]()),
		typeOf("watchlistItemEntry", reflect.TypeFor[watchlistItemEntry]()),
		typeOf("watchlistItemsReplaced", reflect.TypeFor[watchlistItemsReplaced]()),
		typeOf("callerIdentity", reflect.TypeFor[callerIdentity]()),
		literal("readyz.go:86", map[string]any{
			"status": "",
			"checks": map[string]any{
				"database":        map[string]any{"status": "", "latency_ms": int64(0)},
				"migrations":      map[string]any{"status": "", "version": 0, "dirty": false},
				"worker":          map[string]any{"goroutines": 0},
				"delivery_worker": map[string]any{"status": ""},
			},
		}),
		literal("server.go:583", map[string]string{"status": ""}),
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

	// The measured values leave every slice and map nil, so a struct type that
	// appears only as an element of one is measured on its own. Schema types
	// reach theirs through component references; the writeJSON values do not.
	for i := 0; i < len(measured); i++ {
		for _, elem := range collectionElementTypes(measured[i].typ) {
			if !seen[elem] {
				seen[elem] = true
				t.Logf("element type %s of %s measured on its own", elem, measured[i].name)
				measured = append(measured, measuredResponse{name: elem.String(), typ: elem})
			}
		}
	}

	checked := map[reflect.Type]bool{}
	for _, m := range measured {
		for _, field := range omitzeroNullablePointers(m.typ, checked) {
			t.Errorf("%s: a pointer to a scalar tagged omitzero needs nullable:\"false\"; huma documents it as nullable otherwise, and v2 never writes null for it", field)
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
		if _, ok := allowedEncodingDifferences[d.key]; ok {
			continue
		}
		t.Errorf("encoding changes and is not allowlisted: %s", d)
	}
	t.Logf("measured %d response shapes; differences: expected=%d presence=%d error=%d other=%d",
		len(measured), counts[differenceExpected], counts[differencePresence], counts[differenceError], counts[differenceOther])
}

// omitzeroNullablePointers returns, as "Type.Field", every struct field
// reachable from t that is a pointer to a string, bool or number, is tagged
// omitzero, and lacks nullable:"false". huma clears the nullable flag of a
// scalar pointer only for omitempty (huma@v2.37.3 schema.go:927-931), so such a
// field would appear as "type or null" in openapi.json.
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
		if f.Type.Kind() == reflect.Pointer && isScalarKind(f.Type.Elem().Kind()) &&
			strings.Contains(f.Tag.Get("json"), "omitzero") && f.Tag.Get("nullable") != "false" {
			out = append(out, t.String()+"."+f.Name)
		}
		out = append(out, omitzeroNullablePointers(f.Type, checked)...)
	}
	return out
}

func isScalarKind(k reflect.Kind) bool {
	switch k {
	case reflect.String, reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	default:
		return false
	}
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

// responseValueVariant sets how a measured value fills its json.RawMessage
// and empty-interface fields; every other slice and map stays nil.
type responseValueVariant struct {
	name  string
	raw   json.RawMessage // nil leaves every json.RawMessage nil
	iface any             // nil leaves every empty interface nil
}

// responseValueVariants are the fills each measured type is encoded with. The
// raw values are what JSONB columns produce; a zero-length non-nil
// json.RawMessage is left out because no column can produce one.
var responseValueVariants = []responseValueVariant{
	{name: "nil"},
	{name: "empty-string", iface: ""},
	{name: "empty-object", raw: json.RawMessage(`{}`), iface: map[string]any{}},
	{name: "empty-array", raw: json.RawMessage(`[]`), iface: []any{}},
	{name: "null-raw", raw: json.RawMessage(`null`)},
}

// rawMessageType is the type of json.RawMessage fields.
var rawMessageType = reflect.TypeFor[json.RawMessage]()

// buildResponseValue returns a value of type t in which every settable pointer,
// to maxResponsePointerDepth hops, points at a zero value, every slice and map
// is nil, and every json.RawMessage and empty interface holds the variant's
// value.
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
	case reflect.Interface:
		if variant.iface != nil && v.CanSet() && v.NumMethod() == 0 {
			v.Set(reflect.ValueOf(variant.iface))
		}
	default:
	}
}

// collectionElementTypes returns the struct types that t holds as elements of
// a slice, array or map, directly or through struct fields and pointers.
func collectionElementTypes(t reflect.Type) []reflect.Type {
	var out []reflect.Type
	visited := map[reflect.Type]bool{}
	var walk func(t reflect.Type, inCollection bool)
	walk = func(t reflect.Type, inCollection bool) {
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		switch t.Kind() {
		case reflect.Slice, reflect.Array, reflect.Map:
			walk(t.Elem(), true)
		case reflect.Struct:
			// A type with its own encoding, such as time.Time, has no fields
			// for the encoders to differ on.
			if reflect.PointerTo(t).Implements(reflect.TypeFor[json.Marshaler]()) ||
				reflect.PointerTo(t).Implements(reflect.TypeFor[encoding.TextMarshaler]()) {
				return
			}
			if inCollection {
				out = append(out, t)
				return
			}
			if visited[t] {
				return
			}
			visited[t] = true
			for i := range t.NumField() {
				if f := t.Field(i); f.IsExported() || f.Anonymous {
					walk(f.Type, false)
				}
			}
		default:
		}
	}
	walk(t, false)
	return out
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
