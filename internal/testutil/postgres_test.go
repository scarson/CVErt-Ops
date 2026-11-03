// ABOUTME: Tests for starting the Postgres test container, including removal of a
// ABOUTME: container that was created but failed to become ready.
package testutil

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/moby/moby/client"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// fatalRecorder is a testing.TB whose Fatalf records the failure and ends the
// calling goroutine instead of failing the test. Everything else, including
// Cleanup, goes to the wrapped test.
type fatalRecorder struct {
	testing.TB
	fatal string
}

func (r *fatalRecorder) Fatalf(format string, args ...any) {
	r.fatal = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

func TestStartPostgres_RemovesContainerThatFailsToStart(t *testing.T) {
	marker := map[string]string{"cvert-ops.test.case": uuid.NewString()}

	t.Run("start", func(t *testing.T) {
		rec := &fatalRecorder{TB: t}
		done := make(chan struct{})
		go func() {
			defer close(done)
			startPostgres(rec,
				testcontainers.WithLabels(marker),
				testcontainers.WithWaitStrategy(wait.ForLog("a line postgres never prints").WithStartupTimeout(5*time.Second)),
			)
		}()
		<-done
		if rec.fatal == "" {
			t.Fatal("startPostgres should fail when the container never becomes ready")
		}
	})

	// The subtest's cleanups have run.
	ctx := context.Background()
	cli, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		t.Fatalf("docker client: %v", err)
	}
	defer cli.Close() //nolint:errcheck
	list, err := cli.ContainerList(ctx, client.ContainerListOptions{
		All:     true,
		Filters: make(client.Filters).Add("label", "cvert-ops.test.case="+marker["cvert-ops.test.case"]),
	})
	if err != nil {
		t.Fatalf("list containers: %v", err)
	}
	if len(list.Items) != 0 {
		t.Errorf("container that failed to start is still present: %s", list.Items[0].ID)
	}
}
