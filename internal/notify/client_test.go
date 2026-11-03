// ABOUTME: Tests for the webhook delivery client's private-destination allowlist.
// ABOUTME: Covers settings parsing and that only listed hosts may reach listed private networks.
package notify_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scarson/cvert-ops/internal/notify"
)

func TestParsePrivateDestinations_Empty(t *testing.T) {
	dests, err := notify.ParsePrivateDestinations("", "", "")
	require.NoError(t, err)
	assert.False(t, dests.Allows("ntfy.example.test"))
}

func TestParsePrivateDestinations_NormalizesHosts(t *testing.T) {
	dests, err := notify.ParsePrivateDestinations(" NTFY.Example.test ,hooks.example.test, 10.0.0.5,::ffff:10.0.0.7", "10.0.0.0/8", "")
	require.NoError(t, err)
	assert.True(t, dests.Allows("ntfy.example.test"))
	assert.True(t, dests.Allows("NTFY.EXAMPLE.TEST"))
	assert.True(t, dests.Allows("hooks.example.test"))
	assert.True(t, dests.Allows("10.0.0.5"))
	assert.True(t, dests.Allows("10.0.0.7"), "IP literals compare in canonical form")
	assert.False(t, dests.Allows("other.example.test"))
	assert.False(t, dests.Allows("example.test"))
	assert.False(t, dests.Allows("10.0.0.6"))
}

func TestParsePrivateDestinations_Invalid(t *testing.T) {
	cases := []struct{ name, hosts, cidrs, ports string }{
		{"hosts without networks", "ntfy.example.test", "", ""},
		{"networks without hosts", "", "10.0.0.0/8", ""},
		{"ports without hosts", "", "", "8080"},
		{"bad network", "ntfy.example.test", "10.0.0.0/33", ""},
		{"bare address as network", "ntfy.example.test", "10.0.0.5", ""},
		{"host with port", "ntfy.example.test:8443", "10.0.0.0/8", ""},
		{"host with scheme", "https://ntfy.example.test", "10.0.0.0/8", ""},
		// Webhook delivery never dials IPv6, so IPv6 entries could never be used.
		{"IPv6 host", "fd00::5", "10.0.0.0/8", ""},
		{"IPv6 network", "ntfy.example.test", "fd00::/8", ""},
		{"non-numeric port", "ntfy.example.test", "10.0.0.0/8", "https"},
		{"port out of range", "ntfy.example.test", "10.0.0.0/8", "70000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := notify.ParsePrivateDestinations(tc.hosts, tc.cidrs, tc.ports)
			assert.Error(t, err)
		})
	}
}

// loopbackReceiver starts a receiver on 127.0.0.1 and returns its port.
func loopbackReceiver(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	return u.Port()
}

func clientFor(t *testing.T, hosts, cidrs, ports string) *http.Client {
	t.Helper()
	dests, err := notify.ParsePrivateDestinations(hosts, cidrs, ports)
	require.NoError(t, err)
	client, err := notify.BuildSafeClient(dests)
	require.NoError(t, err)
	return client
}

func send(t *testing.T, client *http.Client, rawURL string) error {
	t.Helper()
	return notify.Send(context.Background(), client, notify.WebhookConfig{URL: rawURL, SigningSecret: "x"}, []byte(`[]`))
}

func TestBuildSafeClient_ListedHostNameReachesListedNetwork(t *testing.T) {
	port := loopbackReceiver(t)
	// localhost resolves to ::1 and 127.0.0.1; ::1 is refused (IPv6 is disabled)
	// and the dialer falls back to 127.0.0.1, inside the listed network.
	client := clientFor(t, "localhost", "127.0.0.0/8", port)
	require.NoError(t, send(t, client, "http://localhost:"+port+"/hook"))
}

func TestBuildSafeClient_OnlyListedHostReachesPrivateNetwork(t *testing.T) {
	port := loopbackReceiver(t)
	target := "http://127.0.0.1:" + port + "/hook"

	listed := clientFor(t, "127.0.0.1", "127.0.0.0/8", port)
	require.NoError(t, send(t, listed, target), "listed host in a listed network must be delivered")

	unlisted := clientFor(t, "ntfy.example.test", "127.0.0.0/8", port)
	assert.ErrorContains(t, send(t, unlisted, target), "not found in allowlist",
		"a host not on the list keeps the default policy")
}

func TestBuildSafeClient_ListedHostOutsideListedNetworkBlocked(t *testing.T) {
	// The listed host's address is outside the listed network: the same outcome
	// as a DNS answer for a listed name that changed after registration.
	port := loopbackReceiver(t)
	client := clientFor(t, "127.0.0.1", "10.0.0.0/8", port)
	assert.ErrorContains(t, send(t, client, "http://127.0.0.1:"+port+"/hook"), "ip: 127.0.0.1 not found in allowlist")
}

func TestBuildSafeClient_ListedHostOnUnlistedPortBlocked(t *testing.T) {
	port := loopbackReceiver(t)
	client := clientFor(t, "127.0.0.1", "127.0.0.0/8", "")
	assert.ErrorContains(t, send(t, client, "http://127.0.0.1:"+port+"/hook"), "port: "+port+" not found in allowlist")
}
