// ABOUTME: Shared feed name constants and adapter factory for feed ingestion.
// ABOUTME: Maps feed names to their concrete adapter constructors.
package ingest

import (
	"fmt"
	"net/http"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/feed/ghsa"
	"github.com/scarson/cvert-ops/internal/feed/kev"
	"github.com/scarson/cvert-ops/internal/feed/mitre"
	"github.com/scarson/cvert-ops/internal/feed/msrc"
	"github.com/scarson/cvert-ops/internal/feed/nvd"
	"github.com/scarson/cvert-ops/internal/feed/osv"
	"github.com/scarson/cvert-ops/internal/feed/redhat"
)

// KnownFeeds is the canonical set of feed names. Used for validation in both
// the ingest handler and admin API.
var KnownFeeds = []string{"nvd", "mitre", "kev", "ghsa", "osv", "epss", "msrc", "redhat"}

// IsKnownFeed returns true if feedName is a recognized feed.
func IsKnownFeed(feedName string) bool {
	for _, f := range KnownFeeds {
		if f == feedName {
			return true
		}
	}
	return false
}

// IsReservedSourceName returns true if the given name collides with a
// built-in feed name. Used by generic feed config validation and the
// inbound webhook handler to reject reserved names.
func IsReservedSourceName(name string) bool {
	return IsKnownFeed(name)
}

// QueueForFeed returns "epss_ingest" for EPSS, "feed_ingest" for all others.
func QueueForFeed(feedName string) string {
	if feedName == "epss" {
		return "epss_ingest"
	}
	return "feed_ingest"
}

// AdapterFactory creates a feed.Adapter for a given feed name and HTTP client.
type AdapterFactory func(feedName string, client *http.Client) (feed.Adapter, error)

// NewAdapter returns the right feed.Adapter for a given feed name.
// Returns an error for unknown feeds or "epss" (which has a separate handler).
func NewAdapter(feedName string, client *http.Client) (feed.Adapter, error) {
	switch feedName {
	case "nvd":
		return nvd.New(client), nil
	case "mitre":
		return mitre.New(client), nil
	case "kev":
		return kev.New(client), nil
	case "ghsa":
		return ghsa.New(client), nil
	case "osv":
		return osv.New(client), nil
	case "msrc":
		return msrc.New(client), nil
	case "redhat":
		return redhat.New(client), nil
	case "epss":
		return nil, fmt.Errorf("epss uses a separate handler; use the epss_ingest queue")
	default:
		return nil, fmt.Errorf("unknown feed: %q", feedName)
	}
}
