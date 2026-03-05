// ABOUTME: Regression test for MITRE adapter CVSS 0.0 rejection bug.
// ABOUTME: Validates that a CVSS base score of 0.0 is accepted, not silently dropped.
package mitre

import (
	"testing"

	"github.com/scarson/cvert-ops/internal/feed"
)

func TestApplyCVSS_ZeroScore(t *testing.T) {
	t.Parallel()

	// A CVSS base score of 0.0 is valid (e.g., CVEs with no impact).
	// The adapter must not reject it.
	patch := &feed.CanonicalPatch{}
	metrics := []cve5MetricEntry{
		{
			CVSSV31: &cve5CVSSv3{
				BaseScore:    0.0,
				BaseSeverity: "NONE",
				VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
			},
		},
	}

	applyCVSS(patch, metrics)

	if patch.CVSSv3Score == nil {
		t.Fatal("applyCVSS rejected CVSS 3.1 score of 0.0")
	}
	if *patch.CVSSv3Score != 0.0 {
		t.Errorf("CVSSv3Score = %v, want 0.0", *patch.CVSSv3Score)
	}
}

func TestApplyCVSS_ZeroScoreV4(t *testing.T) {
	t.Parallel()

	patch := &feed.CanonicalPatch{}
	metrics := []cve5MetricEntry{
		{
			CVSSV40: &cve5CVSSv4{
				BaseScore:    0.0,
				BaseSeverity: "NONE",
				VectorString: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
			},
		},
	}

	applyCVSS(patch, metrics)

	if patch.CVSSv4Score == nil {
		t.Fatal("applyCVSS rejected CVSS 4.0 score of 0.0")
	}
	if *patch.CVSSv4Score != 0.0 {
		t.Errorf("CVSSv4Score = %v, want 0.0", *patch.CVSSv4Score)
	}
}

func TestApplyCVSS_ZeroScoreV30(t *testing.T) {
	t.Parallel()

	patch := &feed.CanonicalPatch{}
	metrics := []cve5MetricEntry{
		{
			CVSSV30: &cve5CVSSv3{
				BaseScore:    0.0,
				BaseSeverity: "NONE",
				VectorString: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
			},
		},
	}

	applyCVSS(patch, metrics)

	if patch.CVSSv3Score == nil {
		t.Fatal("applyCVSS rejected CVSS 3.0 score of 0.0")
	}
	if *patch.CVSSv3Score != 0.0 {
		t.Errorf("CVSSv3Score = %v, want 0.0", *patch.CVSSv3Score)
	}
}
