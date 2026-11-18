// ABOUTME: Constructs the production SSRF-safe HTTP client for webhook delivery.
// ABOUTME: Uses doyensec/safeurl with redirect following disabled and 10s timeout.
package notify

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/doyensec/safeurl"
)

// PrivateDestinations names the webhook hosts an operator allows on private
// networks, the networks those hosts may resolve into, and any ports beyond
// 80 and 443 they may use. The zero value allows no private destinations.
type PrivateDestinations struct {
	hosts map[string]struct{}
	cidrs []string
	ports []int
}

// ParsePrivateDestinations parses the comma-separated WEBHOOK_PRIVATE_HOSTS,
// WEBHOOK_PRIVATE_CIDRS and WEBHOOK_PRIVATE_PORTS settings. Hosts are exact DNS
// names or IPv4 literals, matched against the URL's host. Hosts and networks must
// be set together. IPv6 entries are rejected because safeurl's IPv6 dialing is
// disabled, so they could never be delivered to.
func ParsePrivateDestinations(hosts, cidrs, ports string) (PrivateDestinations, error) {
	var d PrivateDestinations
	for _, h := range splitList(hosts) {
		h = canonicalHost(h)
		if ip := net.ParseIP(h); ip != nil {
			if ip.To4() == nil {
				return PrivateDestinations{}, fmt.Errorf("WEBHOOK_PRIVATE_HOSTS: %q is IPv6, which webhook delivery does not dial", h)
			}
		} else if strings.ContainsAny(h, ":/@ []") {
			return PrivateDestinations{}, fmt.Errorf("WEBHOOK_PRIVATE_HOSTS: %q is not a bare host name or IP address", h)
		}
		if d.hosts == nil {
			d.hosts = make(map[string]struct{})
		}
		d.hosts[h] = struct{}{}
	}
	for _, c := range splitList(cidrs) {
		_, network, err := net.ParseCIDR(c)
		if err != nil {
			return PrivateDestinations{}, fmt.Errorf("WEBHOOK_PRIVATE_CIDRS: %q is not a CIDR network", c)
		}
		if network.IP.To4() == nil {
			return PrivateDestinations{}, fmt.Errorf("WEBHOOK_PRIVATE_CIDRS: %q is IPv6, which webhook delivery does not dial", c)
		}
		d.cidrs = append(d.cidrs, c)
	}
	for _, p := range splitList(ports) {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return PrivateDestinations{}, fmt.Errorf("WEBHOOK_PRIVATE_PORTS: %q is not a port number", p)
		}
		d.ports = append(d.ports, n)
	}
	if len(d.hosts) == 0 && (len(d.cidrs) > 0 || len(d.ports) > 0) {
		return PrivateDestinations{}, errors.New("WEBHOOK_PRIVATE_CIDRS and WEBHOOK_PRIVATE_PORTS require WEBHOOK_PRIVATE_HOSTS")
	}
	if len(d.hosts) > 0 && len(d.cidrs) == 0 {
		return PrivateDestinations{}, errors.New("WEBHOOK_PRIVATE_HOSTS requires WEBHOOK_PRIVATE_CIDRS")
	}
	return d, nil
}

// Allows reports whether host (as url.URL.Hostname returns it) is a listed private destination.
func (d PrivateDestinations) Allows(host string) bool {
	_, ok := d.hosts[canonicalHost(host)]
	return ok
}

// canonicalHost lowercases a host name and rewrites an IP literal in its
// canonical form, so "0:0:0:0:0:0:0:1" and "::1" compare equal.
func canonicalHost(h string) string {
	if ip := net.ParseIP(h); ip != nil {
		return ip.String()
	}
	return strings.ToLower(h)
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// BuildSafeClient returns an SSRF-safe *http.Client for production webhook delivery.
// Redirect following is disabled per PLAN.md §11.3; timeout is 10 seconds.
// MaxConnsPerHost is capped at 50 to prevent ephemeral port exhaustion under alert load.
//
// Requests to a listed private destination dial through a second safeurl client
// whose IP allowlist is exactly the listed networks (and whose ports add the
// listed ports), so a listed host that resolves anywhere else is refused. All
// other requests use the default policy, which blocks private addresses and
// allows only ports 80 and 443. Redirects are disabled, so the host a request
// is routed by cannot change mid-request.
func BuildSafeClient(private PrivateDestinations) (*http.Client, error) {
	public := buildSafeurlClient(safeurl.GetConfigBuilder().
		SetTimeout(10 * time.Second).
		SetCheckRedirect(rejectRedirect).
		Build())
	if len(private.hosts) == 0 {
		return public, nil
	}

	// SetAllowedPorts replaces safeurl's default of 80 and 443, so restate them.
	privateClient := buildSafeurlClient(safeurl.GetConfigBuilder().
		SetTimeout(10 * time.Second).
		SetCheckRedirect(rejectRedirect).
		SetAllowedIPsCIDR(private.cidrs...).
		SetAllowedPorts(append([]int{80, 443}, private.ports...)...).
		Build())

	return &http.Client{
		Timeout:       public.Timeout,
		CheckRedirect: public.CheckRedirect,
		Transport: &destinationTransport{
			public:  public.Transport,
			private: privateClient.Transport,
			dests:   private,
		},
	}, nil
}

func rejectRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func buildSafeurlClient(cfg *safeurl.Config) *http.Client {
	client := safeurl.Client(cfg).Client
	if t, ok := client.Transport.(*http.Transport); ok {
		t.MaxConnsPerHost = 50
	}
	return client
}

// destinationTransport sends requests for listed private hosts through the
// private transport and everything else through the public one.
type destinationTransport struct {
	public, private http.RoundTripper
	dests           PrivateDestinations
}

func (t *destinationTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.dests.Allows(r.URL.Hostname()) {
		return t.private.RoundTrip(r)
	}
	return t.public.RoundTrip(r)
}
