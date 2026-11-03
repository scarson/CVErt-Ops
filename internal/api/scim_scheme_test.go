// ABOUTME: Tests that SCIM resource URLs honour X-Forwarded-Proto only from a
// ABOUTME: TRUSTED_PROXIES peer, and otherwise follow the connection's TLS state.
package api

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSCIMScheme_ForwardedProtoTrust(t *testing.T) {
	t.Parallel()
	trusted := []string{"10.0.0.0/8", "fd00::/8"}
	tests := []struct {
		name       string
		trusted    []string
		remoteAddr string
		tls        bool
		proto      string // X-Forwarded-Proto; empty means not sent
		want       string
	}{
		{name: "no trusted proxies ignores header", remoteAddr: "203.0.113.7:40000", proto: "https", want: "http"},
		{name: "no trusted proxies keeps TLS", remoteAddr: "203.0.113.7:40000", tls: true, proto: "http", want: "https"},
		{name: "untrusted peer ignores header", trusted: trusted, remoteAddr: "203.0.113.7:40000", proto: "https", want: "http"},
		{name: "untrusted peer cannot downgrade TLS", trusted: trusted, remoteAddr: "203.0.113.7:40000", tls: true, proto: "http", want: "https"},
		{name: "trusted peer header https", trusted: trusted, remoteAddr: "10.0.0.5:40000", proto: "https", want: "https"},
		{name: "trusted peer header http", trusted: trusted, remoteAddr: "10.0.0.5:40000", tls: true, proto: "http", want: "http"},
		{name: "trusted v4-mapped peer", trusted: trusted, remoteAddr: "[::ffff:10.0.0.5]:40000", proto: "https", want: "https"},
		{name: "trusted IPv6 peer", trusted: trusted, remoteAddr: "[fd00::5]:40000", proto: "https", want: "https"},
		{name: "trusted peer without header uses TLS state", trusted: trusted, remoteAddr: "10.0.0.5:40000", want: "http"},
		{name: "trusted peer invalid header uses TLS state", trusted: trusted, remoteAddr: "10.0.0.5:40000", tls: true, proto: "javascript", want: "https"},
		{name: "unparseable peer ignores header", trusted: trusted, remoteAddr: "not-an-ip", proto: "https", want: "http"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got, gotBase string
			handler := clientIPMiddleware(tt.trusted)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				got = scimScheme(r)
				gotBase = scimBaseURL(r)
			}))
			req := httptest.NewRequest(http.MethodGet, "http://cvert.example/api/v1/orgs/o/scim/v2/Users", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.tls {
				req.TLS = &tls.ConnectionState{} //nolint:exhaustruct // test: only non-nil TLS state matters
			}
			if tt.proto != "" {
				req.Header.Set("X-Forwarded-Proto", tt.proto)
			}
			handler.ServeHTTP(httptest.NewRecorder(), req)
			if got != tt.want {
				t.Errorf("scimScheme = %q, want %q", got, tt.want)
			}
			if wantBase := tt.want + "://cvert.example/api/v1/orgs/o/scim/v2"; gotBase != wantBase {
				t.Errorf("scimBaseURL = %q, want %q", gotBase, wantBase)
			}
		})
	}
}
