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
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Header.Get("Host")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_ = notify.Send(context.Background(), buildTestClient(), notify.WebhookConfig{
		URL:           srv.URL,
		SigningSecret: "x",
		CustomHeaders: map[string]string{"Host": "evil.internal", "X-Custom": "ok"},
	}, []byte(`[]`))
	// The Host header must match the server URL, not the injected value.
	assert.NotEqual(t, "evil.internal", gotHost)
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

