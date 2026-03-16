// ABOUTME: Verifies that Ryuk (testcontainers reaper) cleans up containers when the test process crashes.
// ABOUTME: Launches a subprocess that starts a container and exits without cleanup; asserts the container is reaped.
package testutil_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	dockerclient "github.com/docker/docker/client"
)

// TestRyuk_ReapsOrphanedContainers verifies that when a test process exits
// without calling t.Cleanup (simulating a crash), Ryuk detects the broken
// connection and removes the container automatically.
//
// Flow:
//  1. Build a helper binary that starts a Postgres testcontainer and os.Exit(1)
//  2. Run the binary — capture the container ID from stdout
//  3. Wait up to 30s for Docker to report the container as removed
//  4. Assert the container no longer exists
func TestRyuk_ReapsOrphanedContainers(t *testing.T) {
	if os.Getenv("TESTCONTAINERS_RYUK_DISABLED") == "true" {
		t.Skip("Ryuk is disabled via TESTCONTAINERS_RYUK_DISABLED env var")
	}

	ctx := context.Background()

	// Build the crash helper as a standalone binary.
	helperBin := t.TempDir() + "/ryuk_crash_helper.exe"
	build := exec.CommandContext(ctx, "go", "build", "-o", helperBin, "./internal/testutil/testdata/ryuk_crash_helper") //nolint:gosec // test helper, args are hardcoded
	build.Dir = findProjectRoot(t)
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build crash helper: %v", err)
	}

	// Run the crash helper — it prints the container ID to stdout and exits.
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, helperBin) //nolint:gosec // test helper, path from t.TempDir()
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Dir = findProjectRoot(t)

	// The helper exits non-zero on purpose — we expect an error.
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected crash helper to exit non-zero")
	}

	containerID := strings.TrimSpace(stdout.String())
	if containerID == "" {
		t.Fatalf("crash helper produced no container ID; stderr:\n%s", stderr.String())
	}
	t.Logf("crash helper started container %s and exited", containerID)

	// Connect to Docker and poll until the container is gone.
	cli, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("docker client: %v", err)
	}
	defer cli.Close()

	start := time.Now()
	deadline := start.Add(30 * time.Second)
	for time.Now().Before(deadline) {
		info, inspectErr := cli.ContainerInspect(ctx, containerID)
		if inspectErr != nil {
			// Container not found — Ryuk reaped it successfully.
			t.Logf("container %s reaped by Ryuk after %s", containerID, time.Since(start).Round(time.Second))
			return
		}
		// ContainerJSON embeds *ContainerJSONBase — guard against nil before
		// accessing State (zero value has nil embedded pointer).
		if info.ContainerJSONBase != nil && info.State != nil && !info.State.Running {
			t.Logf("container %s stopped, waiting for removal...", containerID)
		}
		time.Sleep(1 * time.Second)
	}

	// Last check — maybe it was removed right at the deadline.
	_, inspectErr := cli.ContainerInspect(ctx, containerID)
	if inspectErr != nil {
		t.Logf("container %s reaped by Ryuk (at deadline)", containerID)
		return
	}

	// Clean up the orphan ourselves, then fail.
	_ = cli.ContainerStop(ctx, containerID, container.StopOptions{})
	_ = cli.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true})
	t.Fatalf("Ryuk did NOT reap container %s within 30s — container was orphaned.\n"+
		"Check that ryuk.disabled is not set in ~/.testcontainers.properties\n"+
		"Crash helper stderr:\n%s", containerID, stderr.String())
}

// findProjectRoot walks up from CWD to find go.mod.
func findProjectRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(dir + "/go.mod"); err == nil {
			return dir
		}
		parent := dir[:strings.LastIndex(dir, string(os.PathSeparator))]
		if parent == dir {
			t.Fatal("could not find project root (go.mod)")
		}
		dir = parent
	}
}

