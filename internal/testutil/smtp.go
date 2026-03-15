// ABOUTME: Test helper that starts an Inbucket SMTP testcontainer for email integration tests.
// ABOUTME: Use NewTestSMTP(t) to get an SMTP host and port for tests that send email.
package testutil

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/testcontainers/testcontainers-go/modules/inbucket"
)

// TestSMTP holds connection details for an Inbucket SMTP test server.
type TestSMTP struct {
	Host   string
	Port   int
	WebURL string
}

// NewTestSMTP starts an Inbucket container and returns the SMTP connection details.
// The container is cleaned up via t.Cleanup.
func NewTestSMTP(t *testing.T) *TestSMTP {
	t.Helper()
	ctx := context.Background()

	ctr, err := inbucket.Run(ctx, "inbucket/inbucket:sha-2d409bb")
	if err != nil {
		t.Fatalf("start inbucket container: %v", err)
	}
	t.Cleanup(func() {
		if err := ctr.Terminate(ctx); err != nil {
			t.Logf("terminate inbucket container: %v", err)
		}
	})

	smtpURL, err := ctr.SmtpConnection(ctx)
	if err != nil {
		t.Fatalf("get inbucket SMTP connection: %v", err)
	}

	host, portStr, err := net.SplitHostPort(smtpURL)
	if err != nil {
		t.Fatalf("parse SMTP connection %q: %v", smtpURL, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse SMTP port %q: %v", portStr, err)
	}

	webURL, err := ctr.WebInterface(ctx)
	if err != nil {
		t.Fatalf("get inbucket web interface: %v", err)
	}

	return &TestSMTP{Host: host, Port: port, WebURL: webURL}
}
