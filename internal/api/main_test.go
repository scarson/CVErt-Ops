// ABOUTME: TestMain for this package's tests; testutil.Run owns the shared Postgres container.
// ABOUTME: testutil.NewTestDB clones a per-test database from it; Run terminates it after the tests.
package api

import (
	"os"
	"testing"

	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestMain(m *testing.M) {
	os.Exit(testutil.Run(m))
}
