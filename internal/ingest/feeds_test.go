// ABOUTME: Tests for feed name helpers in the ingest package.
// ABOUTME: Covers IsKnownFeed, IsReservedSourceName, and feed registry functions.
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

func TestRegisterFeed(t *testing.T) {
	t.Cleanup(func() { ResetRegistry() })

	RegisterFeed("custom-vendor")

	if !IsKnownFeed("custom-vendor") {
		t.Error("expected IsKnownFeed('custom-vendor') to return true after RegisterFeed")
	}
}

func TestIsReservedSourceName_DoesNotIncludeRegistered(t *testing.T) {
	t.Cleanup(func() { ResetRegistry() })

	RegisterFeed("custom-vendor")

	if IsReservedSourceName("custom-vendor") {
		t.Error("IsReservedSourceName must NOT return true for registered (non-built-in) feeds")
	}
}

func TestAllFeedNames(t *testing.T) {
	t.Cleanup(func() { ResetRegistry() })

	RegisterFeed("acme-scanner")
	RegisterFeed("internal-vuln")

	all := AllFeedNames()
	if len(all) != len(KnownFeeds)+2 {
		t.Fatalf("AllFeedNames: got %d, want %d", len(all), len(KnownFeeds)+2)
	}

	nameSet := make(map[string]bool, len(all))
	for _, n := range all {
		nameSet[n] = true
	}
	for _, builtin := range KnownFeeds {
		if !nameSet[builtin] {
			t.Errorf("AllFeedNames missing built-in feed %q", builtin)
		}
	}
	if !nameSet["acme-scanner"] {
		t.Error("AllFeedNames missing registered feed 'acme-scanner'")
	}
	if !nameSet["internal-vuln"] {
		t.Error("AllFeedNames missing registered feed 'internal-vuln'")
	}
}

func TestResetRegistry(t *testing.T) {
	t.Cleanup(func() { ResetRegistry() })

	RegisterFeed("temp-feed")
	ResetRegistry()

	if IsKnownFeed("temp-feed") {
		t.Error("expected IsKnownFeed('temp-feed') to return false after ResetRegistry")
	}

	all := AllFeedNames()
	if len(all) != len(KnownFeeds) {
		t.Fatalf("AllFeedNames after reset: got %d, want %d", len(all), len(KnownFeeds))
	}
}
