// ABOUTME: Tests for advisory lock key generation functions.
// ABOUTME: Covers determinism, uniqueness, and domain prefix isolation.
package merge

import (
	"testing"
)

func TestAdvisoryKeyDeterminism(t *testing.T) {
	t.Parallel()

	k1 := advisoryKey("cve", "CVE-2024-1234")
	k2 := advisoryKey("cve", "CVE-2024-1234")
	if k1 != k2 {
		t.Errorf("advisoryKey not deterministic: %d != %d", k1, k2)
	}
}

func TestAdvisoryKeyUniqueness(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		domain1 string
		id1     string
		domain2 string
		id2     string
	}{
		{
			name:    "different CVE IDs same domain",
			domain1: "cve", id1: "CVE-2024-1234",
			domain2: "cve", id2: "CVE-2024-5678",
		},
		{
			name:    "different domains same ID",
			domain1: "cve", id1: "CVE-2024-1234",
			domain2: "org", id2: "CVE-2024-1234",
		},
		{
			name:    "completely different inputs",
			domain1: "cve", id1: "CVE-2024-0001",
			domain2: "epss", id2: "CVE-2025-9999",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			k1 := advisoryKey(tc.domain1, tc.id1)
			k2 := advisoryKey(tc.domain2, tc.id2)
			if k1 == k2 {
				t.Errorf("advisoryKey(%q,%q) == advisoryKey(%q,%q) = %d; expected different keys",
					tc.domain1, tc.id1, tc.domain2, tc.id2, k1)
			}
		})
	}
}

func TestAdvisoryKeyDomainPrefixIsolation(t *testing.T) {
	t.Parallel()

	// "cve:X" and "org:X" must not collide — the domain prefix
	// ensures separate lock namespaces for unrelated lock users.
	cveKey := advisoryKey("cve", "shared-id")
	orgKey := advisoryKey("org", "shared-id")
	if cveKey == orgKey {
		t.Errorf("different domain prefixes should produce different keys: cve=%d, org=%d", cveKey, orgKey)
	}
}

func TestCVEAdvisoryKeyDeterminism(t *testing.T) {
	t.Parallel()

	k1 := CVEAdvisoryKey("CVE-2024-1234")
	k2 := CVEAdvisoryKey("CVE-2024-1234")
	if k1 != k2 {
		t.Errorf("CVEAdvisoryKey not deterministic: %d != %d", k1, k2)
	}
}

func TestCVEAdvisoryKeyMatchesAdvisoryKey(t *testing.T) {
	t.Parallel()

	// CVEAdvisoryKey is a convenience wrapper over advisoryKey with domain "cve".
	cveID := "CVE-2024-9999"
	if CVEAdvisoryKey(cveID) != advisoryKey("cve", cveID) {
		t.Error("CVEAdvisoryKey should delegate to advisoryKey with domain \"cve\"")
	}
}

func TestCVEAdvisoryKeyDifferentIDs(t *testing.T) {
	t.Parallel()

	k1 := CVEAdvisoryKey("CVE-2024-0001")
	k2 := CVEAdvisoryKey("CVE-2024-0002")
	if k1 == k2 {
		t.Errorf("different CVE IDs should produce different keys: %d == %d", k1, k2)
	}
}
