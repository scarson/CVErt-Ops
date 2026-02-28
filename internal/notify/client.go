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
func BuildSafeClient() (*http.Client, error) {
	cfg := safeurl.GetConfigBuilder().
		SetTimeout(10 * time.Second).
		SetCheckRedirect(func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}).
		Build()
	return safeurl.Client(cfg).Client, nil
}
