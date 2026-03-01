// ABOUTME: Constructs the production SSRF-safe HTTP client for webhook delivery.
// ABOUTME: Uses doyensec/safeurl with redirect following disabled and 10s timeout.
package notify

import (
	"net/http"
	"time"

	"github.com/doyensec/safeurl"
)

// BuildSafeClient returns an SSRF-safe *http.Client for production webhook delivery.
// Redirect following is disabled per PLAN.md §11.3; timeout is 10 seconds.
// MaxConnsPerHost is capped at 50 to prevent ephemeral port exhaustion under alert load.
func BuildSafeClient() (*http.Client, error) {
	cfg := safeurl.GetConfigBuilder().
		SetTimeout(10 * time.Second).
		SetCheckRedirect(func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}).
		Build()
	client := safeurl.Client(cfg).Client
	if t, ok := client.Transport.(*http.Transport); ok {
		t.MaxConnsPerHost = 50
	}
	return client, nil
}
