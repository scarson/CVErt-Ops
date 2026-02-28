// ABOUTME: Tests for outbound webhook delivery: HMAC signing, body discard, redirect rejection.
package notify_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scarson/cvert-ops/internal/notify"
)

func buildTestClient() *http.Client {
	// In tests use a plain http.Client (safeurl blocks private IPs used by httptest).
	return &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func TestSend_HMACHeadersCorrect(t *testing.T) {
	var gotTS, gotSig string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTS = r.Header.Get("X-CVErt-Timestamp")
		gotSig = r.Header.Get("X-CVErtOps-Signature")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	payload := []byte(`[{"cve_id":"CVE-2024-1234","severity":"CRITICAL"}]`)
	secret := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 64 hex chars = 32 bytes

	err := notify.Send(context.Background(), buildTestClient(), notify.WebhookConfig{
		URL:           srv.URL,
		SigningSecret: secret,
	}, payload)
	require.NoError(t, err)

	require.NotEmpty(t, gotTS)
	tsInt, err := strconv.ParseInt(gotTS, 10, 64)
	require.NoError(t, err)
	assert.InDelta(t, time.Now().Unix(), tsInt, 5)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(gotTS + "." + string(gotBody)))
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	assert.Equal(t, expected, gotSig)
}

func TestSend_Non2xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	err := notify.Send(context.Background(), buildTestClient(), notify.WebhookConfig{
		URL: srv.URL, SigningSecret: "x",
	}, []byte(`[]`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestSend_DeniedHeaderStripped(t *testing.T) {
	var gotContentType, gotTS, gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		gotTS = r.Header.Get("X-CVErt-Timestamp")
		gotSig = r.Header.Get("X-CVErtOps-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	secret := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	payload := []byte(`[]`)
	_ = notify.Send(context.Background(), buildTestClient(), notify.WebhookConfig{
		URL:           srv.URL,
		SigningSecret: secret,
		CustomHeaders: map[string]string{
			"Content-Type":       "text/plain",         // denylist: must stay application/json
			"X-CVErt-Timestamp":  "0",                  // denylist: must be real timestamp
			"X-CVErtOps-Signature": "sha256=forged",    // denylist: must be real HMAC
		},
	}, payload)

	// Denied headers must not override Send's computed values.
	assert.Equal(t, "application/json", gotContentType)
	assert.NotEqual(t, "0", gotTS, "timestamp must not be overridden by custom header")
	assert.NotEqual(t, "sha256=forged", gotSig, "signature must not be overridden by custom header")
	assert.True(t, strings.HasPrefix(gotSig, "sha256="), "signature must have sha256= prefix")
}

func TestSend_RedirectRejected(t *testing.T) {
	inner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer inner.Close()

	outer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, inner.URL, http.StatusFound)
	}))
	defer outer.Close()

	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	err := notify.Send(context.Background(), client, notify.WebhookConfig{
		URL: outer.URL, SigningSecret: "x",
	}, []byte(`[]`))
	// Non-2xx (302) → error
	require.Error(t, err)
	assert.Contains(t, err.Error(), "302")
}

