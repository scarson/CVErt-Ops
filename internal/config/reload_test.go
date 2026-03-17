// ABOUTME: Tests for the ReloadConfig function used by SIGHUP and admin API.
// ABOUTME: Cross-platform — not build-tagged since ReloadConfig compiles everywhere.
package config

import (
	"strings"
	"testing"
)

func TestReloadConfig_UpdatesHolder(t *testing.T) {
	initial := &ReloadableConfig{LogLevel: "info", SMTPHost: "old.example.com"}
	holder := NewHolder(initial)

	content := strings.Join([]string{
		"JWT_SECRET=this-is-a-secret-that-is-at-least-32-bytes-long",
		"LOG_LEVEL=debug",
		"SMTP_HOST=new.example.com",
	}, "\n")
	path := writeTemp(t, content)

	ReloadConfig(holder, path, nil)

	got := holder.Load()
	if got.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", got.LogLevel, "debug")
	}
	if got.SMTPHost != "new.example.com" {
		t.Errorf("SMTPHost = %q, want %q", got.SMTPHost, "new.example.com")
	}
	if string(got.JWTSecret) != "this-is-a-secret-that-is-at-least-32-bytes-long" {
		t.Errorf("JWTSecret = %q", got.JWTSecret)
	}
}

func TestReloadConfig_InvalidConfig_KeepsOld(t *testing.T) {
	initial := &ReloadableConfig{LogLevel: "info", SMTPHost: "keep.example.com"}
	holder := NewHolder(initial)

	// JWT_SECRET too short — LoadFromSecretsFile should fail.
	content := "JWT_SECRET=short"
	path := writeTemp(t, content)

	ReloadConfig(holder, path, nil)

	got := holder.Load()
	if got.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q (should keep old config)", got.LogLevel, "info")
	}
	if got.SMTPHost != "keep.example.com" {
		t.Errorf("SMTPHost = %q, want %q (should keep old config)", got.SMTPHost, "keep.example.com")
	}
}

func TestReloadConfig_PanicRecovery(t *testing.T) {
	// Pass a nil holder — dereferencing it inside ReloadConfig would panic.
	// ReloadConfig should recover and not propagate the panic.
	content := strings.Join([]string{
		"JWT_SECRET=this-is-a-secret-that-is-at-least-32-bytes-long",
		"LOG_LEVEL=debug",
	}, "\n")
	path := writeTemp(t, content)

	// Should not panic — recovered internally.
	ReloadConfig(nil, path, nil)
}

func TestReloadConfig_NoSecretsFile_NoOp(t *testing.T) {
	initial := &ReloadableConfig{LogLevel: "info"}
	holder := NewHolder(initial)

	ReloadConfig(holder, "", nil)

	got := holder.Load()
	if got.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q (should be unchanged)", got.LogLevel, "info")
	}
}

func TestReloadConfig_CallsRescan(t *testing.T) {
	initial := &ReloadableConfig{LogLevel: "info"}
	holder := NewHolder(initial)

	content := strings.Join([]string{
		"JWT_SECRET=this-is-a-secret-that-is-at-least-32-bytes-long",
		"LOG_LEVEL=debug",
	}, "\n")
	path := writeTemp(t, content)

	called := false
	rescan := func() { called = true }

	ReloadConfig(holder, path, rescan)

	if !called {
		t.Error("rescan function was not called after successful reload")
	}
}

func TestReloadConfig_RescanNotCalledOnFailure(t *testing.T) {
	initial := &ReloadableConfig{LogLevel: "info"}
	holder := NewHolder(initial)

	// Invalid secrets file — reload should fail.
	content := "JWT_SECRET=short"
	path := writeTemp(t, content)

	called := false
	rescan := func() { called = true }

	ReloadConfig(holder, path, rescan)

	if called {
		t.Error("rescan function should not be called when reload fails")
	}
}

func TestReloadConfig_MissingFile_KeepsOld(t *testing.T) {
	initial := &ReloadableConfig{LogLevel: "info"}
	holder := NewHolder(initial)

	ReloadConfig(holder, "/nonexistent/secrets.env", nil)

	got := holder.Load()
	if got.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q (should keep old config)", got.LogLevel, "info")
	}
}
