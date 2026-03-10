// ABOUTME: Tests for feed name helpers in the ingest package.
// ABOUTME: Covers IsKnownFeed and IsReservedSourceName validation.
package ingest

import "testing"

func TestIsReservedSourceName(t *testing.T) {
	t.Parallel()
	for _, name := range KnownFeeds {
		if !IsReservedSourceName(name) {
			t.Errorf("expected %q to be reserved", name)
		}
	}
	if IsReservedSourceName("internal-scanner") {
		t.Error("expected 'internal-scanner' to NOT be reserved")
	}
}
