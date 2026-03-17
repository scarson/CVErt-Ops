// ABOUTME: Cross-platform syslog writer for forwarding security events to SIEM systems.
// ABOUTME: Supports JSON and CEF output formats over UDP or TCP connections.
package secure

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// SyslogWriter sends security events to a remote syslog endpoint via UDP or TCP.
// It supports JSON and CEF (Common Event Format) output formats.
type SyslogWriter struct {
	conn   net.Conn
	format string // "json" or "cef"
	mu     sync.Mutex
}

// NewSyslogWriter creates a SyslogWriter connected to the given address.
// The addr format is "udp://host:port" or "tcp://host:port".
// An empty addr returns (nil, nil), indicating syslog is disabled.
// The format must be "json" or "cef".
func NewSyslogWriter(addr, format string) (*SyslogWriter, error) {
	if addr == "" {
		return nil, nil
	}

	if format != "json" && format != "cef" {
		return nil, fmt.Errorf("unsupported syslog format %q: must be \"json\" or \"cef\"", format)
	}

	parsed, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("parse syslog addr: %w", err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "udp" && scheme != "tcp" {
		return nil, fmt.Errorf("unsupported syslog scheme %q: must be \"udp\" or \"tcp\"", scheme)
	}

	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.Dial(scheme, parsed.Host)
	if err != nil {
		return nil, fmt.Errorf("dial syslog %s: %w", addr, err)
	}

	return &SyslogWriter{
		conn:   conn,
		format: format,
	}, nil
}

// Send formats the event and writes it to the syslog endpoint.
// It is safe for concurrent use. Returns nil if the writer is nil (disabled).
func (sw *SyslogWriter) Send(event Event) error {
	if sw == nil {
		return nil
	}

	msg, err := sw.formatMessage(event)
	if err != nil {
		return fmt.Errorf("format syslog message: %w", err)
	}

	sw.mu.Lock()
	defer sw.mu.Unlock()

	_, err = sw.conn.Write(msg)
	if err != nil {
		return fmt.Errorf("write syslog: %w", err)
	}
	return nil
}

// Close closes the underlying network connection.
// Returns nil if the writer is nil (disabled).
func (sw *SyslogWriter) Close() error {
	if sw == nil {
		return nil
	}
	return sw.conn.Close()
}

// syslogPriority returns the syslog priority value (facility * 8 + severity).
// Uses facility 10 (security/authorization, LOG_AUTHPRIV).
func syslogPriority(severity string) int {
	// Facility 10 = security/authorization messages (LOG_AUTHPRIV = 80)
	facility := 80
	var sev int
	switch severity {
	case SeverityCritical:
		sev = 2 // Critical
	case SeverityWarning:
		sev = 4 // Warning
	default:
		sev = 6 // Informational
	}
	return facility + sev
}

// formatMessage produces the syslog-formatted message bytes for the given event.
func (sw *SyslogWriter) formatMessage(event Event) ([]byte, error) {
	pri := syslogPriority(event.Severity)
	timestamp := time.Now().UTC().Format(time.RFC3339)
	hostname := "cvert-ops"

	var payload string
	switch sw.format {
	case "cef":
		payload = formatCEF(event)
	default:
		b, err := formatJSON(event)
		if err != nil {
			return nil, err
		}
		payload = string(b)
	}

	// RFC 3164-style syslog header: <priority>timestamp hostname: message
	msg := fmt.Sprintf("<%d>%s %s: %s", pri, timestamp, hostname, payload)
	return []byte(msg), nil
}

// syslogEvent is the JSON structure emitted for JSON-format syslog messages.
type syslogEvent struct {
	Timestamp  string         `json:"timestamp"`
	EventType  string         `json:"event_type"`
	Severity   string         `json:"severity"`
	ActorIP    string         `json:"actor_ip,omitempty"`
	ActorEmail string         `json:"actor_email,omitempty"`
	UserID     string         `json:"user_id,omitempty"`
	OrgID      string         `json:"org_id,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
}

func formatJSON(event Event) ([]byte, error) {
	se := syslogEvent{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		EventType:  event.Type,
		Severity:   event.Severity,
		ActorIP:    event.ActorIP,
		ActorEmail: event.ActorEmail,
		Details:    event.Details,
	}
	if event.UserID != nil {
		se.UserID = event.UserID.String()
	}
	if event.OrgID != nil {
		se.OrgID = event.OrgID.String()
	}
	return json.Marshal(se)
}

// cefSeverity maps internal severity to CEF numeric severity (0-10).
func cefSeverity(severity string) int {
	switch severity {
	case SeverityCritical:
		return 9
	case SeverityWarning:
		return 6
	default:
		return 3
	}
}

func formatCEF(event Event) string {
	// CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extensions
	sevNum := cefSeverity(event.Severity)

	var ext strings.Builder
	if event.ActorIP != "" {
		ext.WriteString("src=")
		ext.WriteString(cefEscape(event.ActorIP))
	}
	if event.ActorEmail != "" {
		if ext.Len() > 0 {
			ext.WriteByte(' ')
		}
		ext.WriteString("suser=")
		ext.WriteString(cefEscape(event.ActorEmail))
	}
	if event.UserID != nil {
		if ext.Len() > 0 {
			ext.WriteByte(' ')
		}
		ext.WriteString("duid=")
		ext.WriteString(event.UserID.String())
	}
	if event.OrgID != nil {
		if ext.Len() > 0 {
			ext.WriteByte(' ')
		}
		ext.WriteString("cs1Label=org_id cs1=")
		ext.WriteString(event.OrgID.String())
	}

	return fmt.Sprintf("CEF:0|CVErt-Ops|Security|1.0|%s|%s|%d|%s",
		cefEscape(event.Type),
		cefEscape(event.Type),
		sevNum,
		ext.String(),
	)
}

// cefEscape escapes special characters in CEF header and extension values.
func cefEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	s = strings.ReplaceAll(s, `=`, `\=`)
	return s
}
