// ABOUTME: SMTP email delivery using go-mail. Dial-per-send for sporadic alert traffic.
// ABOUTME: BCC all recipients in a single email. Retry = retry all recipients.
package notify

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/wneessen/go-mail"
)

// SmtpConfig holds SMTP connection parameters sourced from global env vars.
type SmtpConfig struct {
	Host     string
	Port     int
	From     string
	Username string
	Password string
	TLS      bool
}

// EmailSend sends an HTML+plaintext multipart email to all recipients via BCC.
// Uses DialAndSend (dial-per-send) — no persistent SMTP connection.
func EmailSend(ctx context.Context, cfg SmtpConfig, recipients []string, subject, htmlBody, textBody string) error {
	if len(recipients) == 0 {
		return errors.New("email send: no recipients")
	}

	// Strip CR/LF from subject to prevent header injection.
	subject = strings.NewReplacer("\r", "", "\n", "").Replace(subject)

	m := mail.NewMsg()
	if err := m.FromFormat("CVErt Ops", cfg.From); err != nil {
		return fmt.Errorf("email send: set from: %w", err)
	}
	if err := m.Bcc(recipients...); err != nil {
		return fmt.Errorf("email send: set bcc: %w", err)
	}
	m.Subject(subject)
	m.SetBodyString(mail.TypeTextPlain, textBody)
	m.AddAlternativeString(mail.TypeTextHTML, htmlBody)

	opts := []mail.Option{
		mail.WithPort(cfg.Port),
	}
	if cfg.Username != "" {
		opts = append(opts, mail.WithSMTPAuth(mail.SMTPAuthPlain))
		opts = append(opts, mail.WithUsername(cfg.Username))
		opts = append(opts, mail.WithPassword(cfg.Password))
	}
	if cfg.TLS {
		opts = append(opts, mail.WithTLSPortPolicy(mail.TLSMandatory))
	} else {
		opts = append(opts, mail.WithTLSPortPolicy(mail.TLSOpportunistic))
	}

	c, err := mail.NewClient(cfg.Host, opts...)
	if err != nil {
		return fmt.Errorf("email send: create client: %w", err)
	}
	if err := c.DialAndSendWithContext(ctx, m); err != nil {
		return fmt.Errorf("email send: %w", err)
	}
	return nil
}
