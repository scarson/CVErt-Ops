// ABOUTME: TestMain for the testutil package's own tests.
// ABOUTME: testutil.Run terminates the package's shared Postgres container after the tests finish.
package testutil

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	os.Exit(Run(m))
}
