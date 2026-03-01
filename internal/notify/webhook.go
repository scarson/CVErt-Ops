// ABOUTME: Outbound webhook delivery: HMAC signing, safeurl client, response body discard.
// ABOUTME: Send is a pure function; the http.Client is injected (constructed once at worker startup).
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// WebhookConfig holds the delivery-time view of a notification_channels row for a webhook channel.
type WebhookConfig struct {
	URL                    string
	SigningSecret          string
	SigningSecretSecondary string            // non-empty during rotation grace period
	CustomHeaders          map[string]string // applied after denylist filtering
}

// deniedHeaders are custom header keys that callers must not override.
var deniedHeaders = map[string]bool{
	"host":                          true,
	"content-type":                  true,
	"content-length":                true,
	"transfer-encoding":             true,
	"connection":                    true,
	"x-cvert-timestamp":             true,
	"x-cvertops-signature":          true,
	"x-cvertops-signature-secondary": true,
}

// Send posts payload to the webhook URL, signs with HMAC-SHA256, and discards the response body.
// The caller constructs client once at startup (safeurl-wrapped, redirect-disabled, 10s timeout).
func Send(ctx context.Context, client *http.Client, cfg WebhookConfig, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Apply custom headers, skipping denied keys.
	for k, v := range cfg.CustomHeaders {
		if !deniedHeaders[strings.ToLower(k)] {
			req.Header.Set(k, v)
		}
	}

	// HMAC-SHA256 over "timestamp.body" with primary signing secret.
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(cfg.SigningSecret))
	mac.Write([]byte(ts + "." + string(payload)))
	req.Header.Set("X-CVErt-Timestamp", ts)
	req.Header.Set("X-CVErtOps-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	// If a secondary secret is set (rotation grace period), emit an additional signature.
	// Recipients can verify against either secret during the transition window.
	if cfg.SigningSecretSecondary != "" {
		mac2 := hmac.New(sha256.New, []byte(cfg.SigningSecretSecondary))
		mac2.Write([]byte(ts + "." + string(payload)))
		req.Header.Set("X-CVErtOps-Signature-Secondary", "sha256="+hex.EncodeToString(mac2.Sum(nil)))
	}

	resp, err := client.Do(req) //nolint:gosec // G107: SSRF is enforced architecturally by the safeurl-wrapped client injected at startup
	if err != nil {
		return fmt.Errorf("webhook POST: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	// Discard response body to allow connection reuse; cap at 4 KiB.
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck,gosec // G104: discard errors are irrelevant for io.Discard writes

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook POST: unexpected status %d", resp.StatusCode)
	}
	return nil
}
