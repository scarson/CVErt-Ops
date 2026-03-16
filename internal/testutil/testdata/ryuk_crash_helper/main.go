// ABOUTME: Crash helper for Ryuk reaper verification test.
// ABOUTME: Starts a Postgres testcontainer, prints its ID, and exits without cleanup.
package main

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/docker/docker/client"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

func init() {
	// Same workaround as testutil.init() for Windows named pipe discovery.
	if runtime.GOOS == "windows" && os.Getenv("DOCKER_HOST") == "" {
		os.Setenv("DOCKER_HOST", client.DefaultDockerHost) //nolint:errcheck,gosec
	}
}

func main() {
	ctx := context.Background()

	pgCtr, err := tcpostgres.Run(ctx,
		"postgres:18-alpine",
		tcpostgres.WithDatabase("ryuk_test"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start postgres container: %v\n", err)
		os.Exit(2)
	}

	// Print the container ID so the test can track it.
	fmt.Println(pgCtr.GetContainerID())

	// Exit abruptly WITHOUT calling pgCtr.Terminate().
	// This simulates a crash — t.Cleanup never fires.
	// Ryuk should detect the broken connection and reap the container.
	os.Exit(1)
}
