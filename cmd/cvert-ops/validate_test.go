// ABOUTME: Tests for the validate-feeds CLI subcommand.
// ABOUTME: Verifies exit codes and output for valid, invalid, and missing feed configs.
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateFeeds_ValidDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "good.yaml"), []byte(`
name: my-scanner
url: http://example.com/api
format: json
mapping:
  root: items
  fields:
    cve_id: id
`), 0o600); err != nil {
		t.Fatal(err)
	}

	err := runValidateFeeds(dir, false)
	if err != nil {
		t.Fatalf("expected no error for valid config, got: %v", err)
	}
}

func TestValidateFeeds_InvalidConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Missing required fields.
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(`
name: bad-feed
`), 0o600); err != nil {
		t.Fatal(err)
	}

	err := runValidateFeeds(dir, false)
	if err == nil {
		t.Fatal("expected error for invalid config, got nil")
	}
}

func TestValidateFeeds_EmptyDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	err := runValidateFeeds(dir, false)
	if err == nil {
		t.Fatal("expected error for empty directory, got nil")
	}
}

func TestValidateFeeds_MixedConfigs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "good.yaml"), []byte(`
name: good-feed
url: http://example.com/api
format: json
mapping:
  root: items
  fields:
    cve_id: id
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(`
name: bad-feed
`), 0o600); err != nil {
		t.Fatal(err)
	}

	err := runValidateFeeds(dir, false)
	if err == nil {
		t.Fatal("expected error when any config is invalid, got nil")
	}
}

func TestValidateFeeds_ReservedName(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "reserved.yaml"), []byte(`
name: nvd
url: http://example.com/api
format: json
mapping:
  root: items
  fields:
    cve_id: id
`), 0o600); err != nil {
		t.Fatal(err)
	}

	err := runValidateFeeds(dir, false)
	if err == nil {
		t.Fatal("expected error for reserved feed name, got nil")
	}
}

func TestValidateFeeds_NonexistentDir(t *testing.T) {
	t.Parallel()
	err := runValidateFeeds("/nonexistent/path", false)
	if err == nil {
		t.Fatal("expected error for nonexistent directory, got nil")
	}
}
