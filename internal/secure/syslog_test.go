// ABOUTME: Tests for SyslogWriter — verifies JSON and CEF syslog output over UDP/TCP.
// ABOUTME: Uses local UDP/TCP listeners to capture and validate emitted syslog messages.
package secure

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSyslogWriter_Disabled(t *testing.T) {
	sw, err := NewSyslogWriter("", "json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sw != nil {
		t.Fatal("expected nil SyslogWriter for empty addr")
	}
}

func TestSyslogWriter_InvalidScheme(t *testing.T) {
	_, err := NewSyslogWriter("http://localhost:514", "json")
	if err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
}

func TestSyslogWriter_InvalidFormat(t *testing.T) {
	_, err := NewSyslogWriter("udp://localhost:514", "xml")
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

func TestSyslogWriter_SendsEvent_JSON(t *testing.T) {
	// Start a UDP listener.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0") //nolint:noctx // test listener, not user-controlled
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()

	addr := conn.LocalAddr().String()
	sw, err := NewSyslogWriter(fmt.Sprintf("udp://%s", addr), "json")
	if err != nil {
		t.Fatalf("new syslog writer: %v", err)
	}
	defer sw.Close()

	userID := uuid.New()
	orgID := uuid.New()
	event := Event{
		Type:       EventAuthLoginFailed,
		Severity:   SeverityWarning,
		ActorIP:    "10.0.0.1",
		ActorEmail: "user@example.com",
		UserID:     &userID,
		OrgID:      &orgID,
		Details:    map[string]any{"reason": "bad password"},
	}

	if err := sw.Send(event); err != nil {
		t.Fatalf("send: %v", err)
	}

	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:gosec // G104: test helper, error is not critical
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read from udp: %v", err)
	}

	payload := string(buf[:n])

	// The payload should contain a syslog header followed by JSON.
	// Find the JSON portion (starts with '{').
	jsonIdx := strings.Index(payload, "{")
	if jsonIdx < 0 {
		t.Fatalf("no JSON found in syslog message: %q", payload)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(payload[jsonIdx:]), &parsed); err != nil {
		t.Fatalf("unmarshal JSON payload: %v (raw: %q)", err, payload[jsonIdx:])
	}

	if parsed["event_type"] != EventAuthLoginFailed {
		t.Errorf("event_type = %v, want %v", parsed["event_type"], EventAuthLoginFailed)
	}
	if parsed["severity"] != SeverityWarning {
		t.Errorf("severity = %v, want %v", parsed["severity"], SeverityWarning)
	}
	if parsed["actor_ip"] != "10.0.0.1" {
		t.Errorf("actor_ip = %v, want 10.0.0.1", parsed["actor_ip"])
	}
	if parsed["actor_email"] != "user@example.com" {
		t.Errorf("actor_email = %v, want user@example.com", parsed["actor_email"])
	}
}

func TestSyslogWriter_CEFFormat(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0") //nolint:noctx // test listener, not user-controlled
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()

	addr := conn.LocalAddr().String()
	sw, err := NewSyslogWriter(fmt.Sprintf("udp://%s", addr), "cef")
	if err != nil {
		t.Fatalf("new syslog writer: %v", err)
	}
	defer sw.Close()

	event := Event{
		Type:       EventAuthLoginFailed,
		Severity:   SeverityWarning,
		ActorIP:    "10.0.0.5",
		ActorEmail: "attacker@evil.com",
		Details:    map[string]any{"reason": "brute force"},
	}

	if err := sw.Send(event); err != nil {
		t.Fatalf("send: %v", err)
	}

	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:gosec // G104: test helper, error is not critical
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read from udp: %v", err)
	}

	payload := string(buf[:n])

	// CEF format: CEF:0|CVErt-Ops|Security|1.0|<event_type>|<event_type>|<severity_num>|...
	if !strings.Contains(payload, "CEF:0|CVErt-Ops|Security|1.0|") {
		t.Errorf("missing CEF header in payload: %q", payload)
	}
	if !strings.Contains(payload, EventAuthLoginFailed) {
		t.Errorf("missing event type in CEF payload: %q", payload)
	}
	if !strings.Contains(payload, "src=10.0.0.5") {
		t.Errorf("missing src IP in CEF payload: %q", payload)
	}
	if !strings.Contains(payload, "suser=attacker@evil.com") {
		t.Errorf("missing suser in CEF payload: %q", payload)
	}
}

func TestSyslogWriter_TCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test listener, not user-controlled
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	// Accept connections in a goroutine.
	resultCh := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		c.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:gosec // G104: test helper, error is not critical
		n, _ := c.Read(buf)
		resultCh <- string(buf[:n])
	}()

	sw, err := NewSyslogWriter(fmt.Sprintf("tcp://%s", addr), "json")
	if err != nil {
		t.Fatalf("new syslog writer: %v", err)
	}
	defer sw.Close()

	event := Event{
		Type:     EventAuthLoginSuccess,
		Severity: SeverityInfo,
		ActorIP:  "192.168.1.1",
	}

	if err := sw.Send(event); err != nil {
		t.Fatalf("send: %v", err)
	}

	select {
	case payload := <-resultCh:
		if !strings.Contains(payload, EventAuthLoginSuccess) {
			t.Errorf("TCP payload missing event type: %q", payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for TCP syslog message")
	}
}

func TestSyslogWriter_SendOnNil(t *testing.T) {
	// Calling Send on a nil writer should be a no-op.
	var sw *SyslogWriter
	err := sw.Send(Event{Type: "test"})
	if err != nil {
		t.Fatalf("expected nil send to return nil, got: %v", err)
	}
}

func TestSyslogWriter_CloseOnNil(t *testing.T) {
	var sw *SyslogWriter
	err := sw.Close()
	if err != nil {
		t.Fatalf("expected nil close to return nil, got: %v", err)
	}
}
