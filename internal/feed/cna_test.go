// ABOUTME: Tests ParseCNAAffected's package identity: the CNA packageURL mapped to a stored package key.
// ABOUTME: A refused, missing or NUL-bearing packageURL must give no key.
package feed

import (
	"encoding/json"
	"testing"
)

func TestParseCNAAffectedPackageKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, packageURL, want string
	}{
		{"npm package", `"packageURL":"pkg:npm/fastify",`, "npm/fastify"},
		{"PyPI name folded", `"packageURL":"pkg:pypi/Friendly_Bard",`, "PyPI/friendly-bard"},
		{"private repository", `"packageURL":"pkg:npm/foo?repository_url=https://r.example",`, ""},
		{"no packageURL", ``, ""},
		{"NUL in packageURL", `"packageURL":"pkg:npm/fast\u0000ify",`, ""},
		{"distro package", `"packageURL":"pkg:deb/debian/curl?distro=debian-13",`, ""},
		{"not a purl", `"packageURL":"https://www.npmjs.com/package/fastify",`, ""},
	}
	for _, tt := range tests {
		raw := json.RawMessage(`[{"vendor":"fastify","product":"fastify",` + tt.packageURL +
			`"versions":[{"version":"5.12.2","lessThan":"5.12.6","status":"affected","versionType":"semver"}]}]`)
		got := ParseCNAAffected(raw, "CVE-2026-107832")
		if len(got) != 1 {
			t.Fatalf("%s: got %d entries, want 1", tt.name, len(got))
		}
		if got[0].PackageKey != tt.want {
			t.Errorf("%s: PackageKey = %q, want %q", tt.name, got[0].PackageKey, tt.want)
		}
	}
}

// The key is computed from the URL as the CNA sent it. Removing a NUL first could turn
// a refused URL into another package's valid identity.
func TestParseCNAAffectedDoesNotCleanPackageURLBeforeMapping(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`[{"vendor":"acme","product":"widget","packageURL":"pkg:npm/wid\u0000get"}]`)
	got := ParseCNAAffected(raw, "CVE-2024-0001")
	if len(got) != 1 || got[0].PackageKey != "" {
		t.Fatalf("got %+v, want one entry with no package key", got)
	}
}

// An entry whose only identity is its packageURL is still a package lookup's
// evidence that the CVE names that package, so it must not be dropped as empty.
func TestParseCNAAffectedKeepsEntryWithOnlyAPackageKey(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`[{"packageURL":"pkg:npm/fastify","collectionURL":"https://registry.npmjs.org"}]`)
	got := ParseCNAAffected(raw, "CVE-2024-0002")
	if len(got) != 1 || got[0].PackageKey != "npm/fastify" {
		t.Fatalf("got %+v, want one entry with package key npm/fastify", got)
	}
}

func TestCNAAffectedPackageKeyJSONField(t *testing.T) {
	t.Parallel()
	b, err := json.Marshal(CNAAffected{Vendor: "fastify", PackageKey: "npm/fastify"})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b); got != `{"vendor":"fastify","package_key":"npm/fastify"}` {
		t.Errorf("JSON = %s", got)
	}
	b, err = json.Marshal(CNAAffected{Vendor: "fastify"})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b); got != `{"vendor":"fastify"}` {
		t.Errorf("JSON without a key = %s, want the field omitted", got)
	}
}
