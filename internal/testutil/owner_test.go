// ABOUTME: Tests for labelling test containers with their owning process and removing
// ABOUTME: containers whose owner has exited, such as those left by a timed-out test binary.
package testutil

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"
	"github.com/testcontainers/testcontainers-go"
)

// exitedPID starts a short-lived process, waits for it to exit, and returns
// its PID.
func exitedPID(t *testing.T) int32 {
	t.Helper()
	// The test binary with a run pattern that matches nothing exits at once.
	cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^$") //nolint:gosec // runs this test binary
	if err := cmd.Run(); err != nil {
		t.Fatalf("run short-lived process: %v", err)
	}
	return int32(cmd.Process.Pid) //nolint:gosec // PIDs fit in int32
}

func TestOwnerAlive(t *testing.T) {
	self := int32(os.Getpid()) //nolint:gosec // PIDs fit in int32
	start, err := processStartTime(self)
	if err != nil {
		t.Fatalf("own start time: %v", err)
	}

	if !ownerAlive(self, start) {
		t.Error("this process should count as alive")
	}
	if ownerAlive(self, start-1) {
		t.Error("a PID whose process started at a different time should count as exited (PID reused)")
	}
	if ownerAlive(exitedPID(t), start) {
		t.Error("a PID with no process should count as exited")
	}
}

func TestOrphaned(t *testing.T) {
	alive := func(pid int32, start int64) bool { return pid == 10 && start == 1000 }
	tests := []struct {
		name   string
		labels map[string]string
		want   bool
	}{
		{"no owner labels", map[string]string{}, false},
		{"pid without start", map[string]string{ownerPIDLabel: "11"}, false},
		{"start without pid", map[string]string{ownerStartLabel: "1000"}, false},
		{"malformed pid", map[string]string{ownerPIDLabel: "x", ownerStartLabel: "1000"}, false},
		{"malformed start", map[string]string{ownerPIDLabel: "11", ownerStartLabel: "x"}, false},
		{"owner alive", map[string]string{ownerPIDLabel: "10", ownerStartLabel: "1000"}, false},
		{"owner exited", map[string]string{ownerPIDLabel: "11", ownerStartLabel: "1000"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := orphaned(tt.labels, alive); got != tt.want {
				t.Errorf("orphaned(%v) = %v, want %v", tt.labels, got, tt.want)
			}
		})
	}
}

// createLabelled creates, without starting, a container carrying labels.
func createLabelled(t *testing.T, labels map[string]string) testcontainers.Container {
	t.Helper()
	ctr, err := testcontainers.GenericContainer(context.Background(), testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{Image: "postgres:18-alpine", Labels: labels},
	})
	testcontainers.CleanupContainer(t, ctr)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	return ctr
}

func containerExists(t *testing.T, id string) bool {
	t.Helper()
	ctx := context.Background()
	cli, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		t.Fatalf("docker client: %v", err)
	}
	defer cli.Close() //nolint:errcheck
	_, err = cli.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	return err == nil
}

// TestAlreadyRemoved_RecognisesGoneAndInProgress verifies that removing a
// container that is already gone, or that another sweep is already removing,
// is treated as removed. Every test binary sweeps when it starts, so
// concurrent sweeps race for the same orphans.
func TestAlreadyRemoved_RecognisesGoneAndInProgress(t *testing.T) {
	ctx := context.Background()
	cli, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		t.Fatalf("docker client: %v", err)
	}
	defer cli.Close() //nolint:errcheck

	_, err = cli.ContainerRemove(ctx, "cvert-ops-test-no-such-container", client.ContainerRemoveOptions{Force: true})
	if err == nil {
		t.Fatal("removing a nonexistent container succeeded; want a not-found error")
	}
	if !alreadyRemoved(err) {
		t.Errorf("alreadyRemoved(%v) = false; want true for the daemon's not-found error", err)
	}
	// The loser of a concurrent removal gets 409 "removal of container ... is
	// already in progress", which the client classifies as a conflict.
	inProgress := fmt.Errorf("removal of container abc is already in progress: %w", cerrdefs.ErrConflict)
	if !alreadyRemoved(inProgress) {
		t.Errorf("alreadyRemoved(%v) = false; want true for a removal already in progress", inProgress)
	}
	if alreadyRemoved(errors.New("permission denied")) {
		t.Error("alreadyRemoved(permission denied) = true; want false")
	}
}

func TestRemoveOrphanedContainers(t *testing.T) {
	ctx := context.Background()
	live, err := ownerLabels()
	if err != nil {
		t.Fatalf("owner labels: %v", err)
	}
	dead := map[string]string{
		ownerPIDLabel:   strconv.Itoa(int(exitedPID(t))),
		ownerStartLabel: live[ownerStartLabel],
	}

	liveCtr := createLabelled(t, live)
	deadCtr := createLabelled(t, dead)
	unlabelledCtr := createLabelled(t, nil)

	// The sweep also meets other test binaries' orphans, whose removal this
	// test does not control; the checks below cover its own containers.
	if err := removeOrphanedContainers(ctx); err != nil {
		t.Logf("remove orphaned containers: %v", err)
	}

	if containerExists(t, deadCtr.GetContainerID()) {
		t.Error("container whose owner exited should be removed")
	}
	if !containerExists(t, liveCtr.GetContainerID()) {
		t.Error("container whose owner is running should be kept")
	}
	if !containerExists(t, unlabelledCtr.GetContainerID()) {
		t.Error("container without owner labels should be kept")
	}
}
