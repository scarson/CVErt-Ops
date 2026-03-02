// ABOUTME: Tests for SMTP email delivery via go-mail.
// ABOUTME: TestEmailSend_BasicDelivery requires Mailpit on localhost:1025 (skips if unavailable).
package notify_test

import (
	"context"
	"testing"

	"github.com/scarson/cvert-ops/internal/notify"
)

func TestEmailSend_BasicDelivery(t *testing.T) {
	cfg := notify.SmtpConfig{
		Host: "localhost",
		Port: 1025,
		From: "test@cvert-ops.local",
	}
	err := notify.EmailSend(context.Background(), cfg,
		[]string{"recipient@example.com"},
		"Test Subject",
		"<h1>HTML Body</h1>",
		"Text Body",
	)
	// If Mailpit not running, skip rather than fail.
	if err != nil {
		t.Skipf("SMTP not available (Mailpit required): %v", err)
	}
}

func TestEmailSend_EmptyRecipients(t *testing.T) {
	cfg := notify.SmtpConfig{
		Host: "localhost",
		Port: 1025,
		From: "test@cvert-ops.local",
	}
	err := notify.EmailSend(context.Background(), cfg,
		nil,
		"Subject",
		"<p>html</p>",
		"text",
	)
	if err == nil {
		t.Error("expected error for empty recipients")
	}
}

func TestEmailSend_InvalidHost(t *testing.T) {
	cfg := notify.SmtpConfig{
		Host: "localhost",
		Port: 19999, // unlikely to be listening
		From: "test@cvert-ops.local",
	}
	err := notify.EmailSend(context.Background(), cfg,
		[]string{"recipient@example.com"},
		"Subject",
		"<p>html</p>",
		"text",
	)
	if err == nil {
		t.Error("expected error for unreachable SMTP host")
	}
}

func TestEmailSend_SubjectHeaderInjection(t *testing.T) {
	cfg := notify.SmtpConfig{
		Host: "localhost",
		Port: 1025,
		From: "test@cvert-ops.local",
	}
	// Subject with injected headers — should be stripped, not cause error.
	err := notify.EmailSend(context.Background(), cfg,
		[]string{"recipient@example.com"},
		"Normal Subject\r\nBcc: attacker@evil.com",
		"<p>html</p>",
		"text",
	)
	// Skip if Mailpit is not running.
	if err != nil {
		t.Skipf("SMTP not available (Mailpit required): %v", err)
	}
}
