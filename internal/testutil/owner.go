// ABOUTME: Labels test containers with the test process that owns them, and removes
// ABOUTME: containers whose owner has exited, such as those left by a timed-out test binary.
package testutil

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"testing"

	"github.com/moby/moby/client"
	"github.com/shirou/gopsutil/v4/process"
	"github.com/testcontainers/testcontainers-go"
)

// Labels naming the test process that started a container. A test binary
// killed by `go test -timeout` never runs the t.Cleanup that terminates its
// containers, and with Ryuk disabled nothing else removes them; these labels
// let a later test binary recognise and remove them.
const (
	ownerPIDLabel = "cvert-ops.test.owner-pid"
	// ownerStartLabel holds the owner's start time in milliseconds since the
	// Unix epoch, which tells a reused PID apart from the original process.
	ownerStartLabel = "cvert-ops.test.owner-start"
)

var (
	ownerOnce   sync.Once
	ownLabels map[string]string
	ownerErr    error
)

// ownedContainer returns a request option that labels a container with this
// test process as its owner. The first call in a test binary also removes
// containers whose owner has exited.
func ownedContainer(t testing.TB) testcontainers.CustomizeRequestOption {
	t.Helper()
	ownerOnce.Do(func() {
		ownLabels, ownerErr = ownerLabels()
		if err := removeOrphanedContainers(context.Background()); err != nil {
			t.Logf("remove containers left by exited test processes: %v", err)
		}
	})
	if ownerErr != nil {
		t.Fatalf("owner labels: %v", ownerErr)
	}
	return testcontainers.WithLabels(ownLabels)
}

// ownerLabels returns the owner labels for this test process.
func ownerLabels() (map[string]string, error) {
	pid := int32(os.Getpid()) //nolint:gosec // PIDs fit in int32
	start, err := processStartTime(pid)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		ownerPIDLabel:   strconv.Itoa(int(pid)),
		ownerStartLabel: strconv.FormatInt(start, 10),
	}, nil
}

// processStartTime returns when the process with the given PID started, in
// milliseconds since the Unix epoch.
func processStartTime(pid int32) (int64, error) {
	p, err := process.NewProcess(pid)
	if err != nil {
		return 0, fmt.Errorf("process %d: %w", pid, err)
	}
	start, err := p.CreateTime()
	if err != nil {
		return 0, fmt.Errorf("process %d start time: %w", pid, err)
	}
	return start, nil
}

// ownerAlive reports whether the process that started at start with the given
// PID is still running. It reports true when that cannot be determined, so a
// container is never removed on a lookup failure.
func ownerAlive(pid int32, start int64) bool {
	got, err := processStartTime(pid)
	if errors.Is(err, process.ErrorProcessNotRunning) {
		return false
	}
	if err != nil {
		return true
	}
	return got == start
}

// orphaned reports whether a container's owner labels name a process that has
// exited. A container without valid owner labels is never orphaned.
func orphaned(labels map[string]string, alive func(pid int32, start int64) bool) bool {
	pid, err := strconv.ParseInt(labels[ownerPIDLabel], 10, 32)
	if err != nil {
		return false
	}
	start, err := strconv.ParseInt(labels[ownerStartLabel], 10, 64)
	if err != nil {
		return false
	}
	return !alive(int32(pid), start)
}

// removeOrphanedContainers force-removes every container whose owner has
// exited. Containers of running test processes, including other packages'
// and other checkouts', are left alone.
func removeOrphanedContainers(ctx context.Context) error {
	cli, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		return fmt.Errorf("docker client: %w", err)
	}
	defer cli.Close() //nolint:errcheck

	list, err := cli.ContainerList(ctx, client.ContainerListOptions{
		All:     true,
		Filters: make(client.Filters).Add("label", ownerPIDLabel),
	})
	if err != nil {
		return fmt.Errorf("list containers: %w", err)
	}

	var errs []error
	for _, c := range list.Items {
		if !orphaned(c.Labels, ownerAlive) {
			continue
		}
		// Another test binary sweeping at the same time may remove it first;
		// that error is reported but harmless.
		if _, err := cli.ContainerRemove(ctx, c.ID, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true}); err != nil {
			errs = append(errs, fmt.Errorf("remove container %s: %w", c.ID, err))
		}
	}
	return errors.Join(errs...)
}
