// ABOUTME: Integration test stubs for EPSS Apply — requires a live Postgres database.
// ABOUTME: These tests verify the two-statement EPSS write pattern with advisory locking.
package epss

import "testing"

// TODO(test): EPSS Apply integration tests require a live Postgres database with
// the cves and epss_staging tables. These tests should verify:
//
// 1. Apply with a synthetic gzip CSV served via httptest:
//    - Scores applied to existing CVEs (Statement 1: UPDATE cves SET epss_score)
//    - Scores staged for non-existent CVEs (Statement 2: INSERT INTO epss_staging)
//    - Advisory lock coordination with merge pipeline
//    - IS DISTINCT FROM guard prevents dead tuples on unchanged scores
//
// 2. Apply short-circuit when cursor score_date matches today
//
// 3. Apply with invalid gzip → error
//
// 4. Apply model version change warning logged
//
// 5. Apply with unparseable score row → warning logged, row skipped
//
// The httptest server pattern from other adapter tests can provide the HTTP layer.
// The database setup should use testutil.SetupTestDB() from internal/testutil/.
// See internal/store/org_tx_test.go for the established integration test pattern.

func TestApply_TODO(t *testing.T) {
	t.Skip("TODO: EPSS Apply integration tests require live Postgres — see comments above")
}

func TestApply_ShortCircuitSameDay_TODO(t *testing.T) {
	t.Skip("TODO: EPSS Apply short-circuit test requires live Postgres")
}

func TestApply_InvalidGzip_TODO(t *testing.T) {
	t.Skip("TODO: EPSS Apply invalid gzip test requires httptest + live Postgres")
}
