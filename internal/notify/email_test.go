// ABOUTME: Integration tests for SMTP email delivery via go-mail.
// ABOUTME: Uses an Inbucket testcontainer; includes header injection verification.
package notify_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/notify"
	"github.com/scarson/cvert-ops/internal/testutil"
	"github.com/stretchr/testify/require"
)

func TestEmailSend_BasicDelivery(t *testing.T) {
	smtp := testutil.NewTestSMTP(t)
	cfg := notify.SmtpConfig{
		Host: smtp.Host,
		Port: smtp.Port,
		From: "test@cvert-ops.local",
	}
	err := notify.EmailSend(context.Background(), cfg,
		[]string{"recipient@example.com"},
		"Test Subject",
		"<h1>HTML Body</h1>",
		"Text Body",
	)
	require.NoError(t, err)

	msgs := waitForMessages(t, smtp.WebURL, "recipient", 1)
	require.Len(t, msgs, 1)
	require.Equal(t, "Test Subject", msgs[0].Subject)
}

func TestEmailSend_EmptyRecipients(t *testing.T) {
	cfg := notify.SmtpConfig{
		Host: "localhost",
		Port: 19999,
		From: "test@cvert-ops.local",
	}
	err := notify.EmailSend(context.Background(), cfg,
		nil,
		"Subject",
		"<p>html</p>",
		"text",
	)
	require.Error(t, err)
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
	require.Error(t, err)
}

func TestEmailSend_SubjectHeaderInjection(t *testing.T) {
	smtp := testutil.NewTestSMTP(t)
	cfg := notify.SmtpConfig{
		Host: smtp.Host,
		Port: smtp.Port,
		From: "test@cvert-ops.local",
	}
	// Subject with injected headers — should be stripped, not cause error.
	err := notify.EmailSend(context.Background(), cfg,
		[]string{"victim@example.com"},
		"Normal Subject\r\nBcc: attacker@evil.com",
		"<p>html</p>",
		"text",
	)
	require.NoError(t, err)

	// Verify the message arrived at the intended recipient.
	msgs := waitForMessages(t, smtp.WebURL, "victim", 1)
	require.Len(t, msgs, 1)

	// Fetch the full message and verify no Bcc header was injected.
	msg := fetchMessage(t, smtp.WebURL, "victim", msgs[0].ID)
	for headerName := range msg.Headers {
		require.NotEqualf(t, "bcc", strings.ToLower(headerName),
			"Bcc header must not appear — header injection should be prevented")
	}
	// The sanitizer strips CR/LF characters, collapsing the injected line
	// into the subject rather than creating a separate header.
	require.NotContains(t, msg.Subject, "\r",
		"subject must not contain CR")
	require.NotContains(t, msg.Subject, "\n",
		"subject must not contain LF")

	// Verify the attacker mailbox is empty — no message was delivered there.
	attackerMsgs := listMessages(t, smtp.WebURL, "attacker")
	require.Empty(t, attackerMsgs,
		"attacker mailbox must be empty — header injection must not create a Bcc delivery")
}

// inbucketMessage is the summary returned by the Inbucket list-messages API.
type inbucketMessage struct {
	ID      string `json:"id"`
	Subject string `json:"subject"`
}

// inbucketFullMessage is the detail returned by the Inbucket get-message API.
type inbucketFullMessage struct {
	ID      string              `json:"id"`
	Subject string              `json:"subject"`
	Headers map[string][]string `json:"headers"`
}

// waitForMessages polls the Inbucket API until at least wantCount messages
// appear in the given mailbox, or the timeout (3s) is reached.
func waitForMessages(t *testing.T, webURL, mailbox string, wantCount int) []inbucketMessage {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		msgs := listMessages(t, webURL, mailbox)
		if len(msgs) >= wantCount {
			return msgs
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d message(s) in mailbox %q (got %d)", wantCount, mailbox, len(msgs))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func listMessages(t *testing.T, webURL, mailbox string) []inbucketMessage {
	t.Helper()
	url := fmt.Sprintf("%s/api/v1/mailbox/%s", webURL, mailbox)
	resp, err := http.Get(url) //nolint:gosec,noctx // test helper, URL is from testcontainer
	require.NoError(t, err)
	defer resp.Body.Close()

	// Inbucket returns 200 with an empty array for empty mailboxes.
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var msgs []inbucketMessage
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&msgs))
	return msgs
}

func fetchMessage(t *testing.T, webURL, mailbox, msgID string) inbucketFullMessage {
	t.Helper()
	url := fmt.Sprintf("%s/api/v1/mailbox/%s/%s", webURL, mailbox, msgID)
	resp, err := http.Get(url) //nolint:gosec,noctx // test helper, URL is from testcontainer
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"expected 200 fetching message %s from mailbox %s", msgID, mailbox)

	var msg inbucketFullMessage
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&msg))
	return msg
}
