//go:build keptingest

// ABOUTME: Measures compiled rule statements on a kept full ingest, read-only (design section 13).
// ABOUTME: Runs only with -tags keptingest and KEPT_INGEST_DATABASE_URL; never writes.
package alert

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/scarson/cvert-ops/internal/alert/dsl"
	"github.com/scarson/cvert-ops/internal/check"
	"github.com/scarson/cvert-ops/internal/ecosystem"
	"github.com/scarson/cvert-ops/internal/store"
)

// keptIngestRealtimeCVE is design Appendix A's realtime CVE, a linux:linux_kernel CVE.
const keptIngestRealtimeCVE = "CVE-2024-26581"

// openMeasuredDB opens urlEnv's database as production does (store.DefaultQueryExecMode),
// with the user and password read from their own variables so they never sit in a URL
// that a parse or connect error would echo. A failure reports only the error class and
// the host and port.
func openMeasuredDB(t *testing.T, urlEnv, userEnv, passwordEnv string) *sql.DB {
	t.Helper()
	raw := os.Getenv(urlEnv)
	if raw == "" {
		t.Skipf("%s not set", urlEnv)
	}
	cfg, err := pgx.ParseConfig(raw)
	if err != nil {
		t.Fatalf("%s does not parse (%T)", urlEnv, err)
	}
	cfg.User = os.Getenv(userEnv)
	cfg.Password = os.Getenv(passwordEnv)
	cfg.DefaultQueryExecMode = store.DefaultQueryExecMode
	db := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("connect to %s failed (%s)", net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))), errorClass(err))
	}
	return db
}

// errorClass names an error's type chain without its text, which can hold connection details.
func errorClass(err error) string {
	var classes []string
	for e := err; e != nil; e = errors.Unwrap(e) {
		classes = append(classes, fmt.Sprintf("%T", e))
	}
	return strings.Join(classes, " <- ")
}

// TestKeptIngestConnectErrorRedacted checks once that a failing connect with credentials
// holding "/" and "@" reports neither, and no part of the password.
func TestKeptIngestConnectErrorRedacted(t *testing.T) {
	const sentinelUser, sentinelPassword = "us/er@x", "pa/ss@word-sentinel" //nolint:gosec // G101: a fake credential the redaction check looks for

	t.Setenv("KEPT_SENTINEL_URL", "postgres://127.0.0.1:1/none?sslmode=disable&connect_timeout=2")
	t.Setenv("KEPT_SENTINEL_USER", sentinelUser)
	t.Setenv("KEPT_SENTINEL_PASSWORD", sentinelPassword)
	cfg, err := pgx.ParseConfig(os.Getenv("KEPT_SENTINEL_URL"))
	if err != nil {
		t.Fatalf("parse sentinel URL: %v", err)
	}
	cfg.User, cfg.Password = sentinelUser, sentinelPassword
	db := stdlib.OpenDB(*cfg)
	defer db.Close() //nolint:errcheck
	pingErr := db.PingContext(context.Background())
	if pingErr == nil {
		t.Fatal("sentinel connect unexpectedly succeeded")
	}
	msg := fmt.Sprintf("connect to %s failed (%s)", net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))), errorClass(pingErr))
	for _, secret := range []string{sentinelPassword, "pa/ss", "ss@word", sentinelUser} {
		if strings.Contains(msg, secret) {
			t.Fatalf("redacted message holds %q: %s", secret, msg)
		}
	}
	t.Logf("redacted connect failure reads: %s", msg)
}

// explainRun is one EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) of a statement.
type explainRun struct {
	planMS, execMS float64
	rows           float64
	hashedSubPlan  bool
	seqScans       []string
	err            error
}

func (r explainRun) totalMS() float64 { return r.planMS + r.execMS }

// explainOnce runs EXPLAIN ANALYZE on query inside a read-only transaction with a 60 s
// statement timeout, so a slow statement is measured instead of cut at production's 14 s.
// settings are extra SET LOCAL statements for this transaction only.
func explainOnce(ctx context.Context, db *sql.DB, query string, args []any, settings ...string) explainRun {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return explainRun{err: err}
	}
	defer tx.Rollback() //nolint:errcheck
	for _, s := range append([]string{"SET LOCAL statement_timeout = '60s'"}, settings...) {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return explainRun{err: err}
		}
	}
	var out string
	if err := tx.QueryRowContext(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+query, args...).Scan(&out); err != nil {
		return explainRun{err: err}
	}
	var doc []struct {
		Plan          map[string]any `json:"Plan"`
		PlanningTime  float64        `json:"Planning Time"`
		ExecutionTime float64        `json:"Execution Time"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || len(doc) != 1 {
		return explainRun{err: fmt.Errorf("explain output: %v", err)}
	}
	r := explainRun{planMS: doc[0].PlanningTime, execMS: doc[0].ExecutionTime, hashedSubPlan: strings.Contains(out, "hashed SubPlan")}
	if rows, ok := doc[0].Plan["Actual Rows"].(float64); ok {
		r.rows = rows
	}
	walkPlan(doc[0].Plan, func(n map[string]any) {
		if n["Node Type"] == "Seq Scan" {
			if rel, ok := n["Relation Name"].(string); ok && !slices.Contains(r.seqScans, rel) {
				r.seqScans = append(r.seqScans, rel)
			}
		}
	})
	return r
}

func walkPlan(n map[string]any, visit func(map[string]any)) {
	visit(n)
	if kids, ok := n["Plans"].([]any); ok {
		for _, k := range kids {
			if m, ok := k.(map[string]any); ok {
				walkPlan(m, visit)
			}
		}
	}
}

// measured is one row of the results table: the first run and the median of runs 2 and 3.
type measured struct {
	id, name, shape string
	first, warm     explainRun
	thresholdMS     float64
	// firstRunCounts compares the first run with the threshold instead of the warm figure.
	firstRunCounts bool
	// compareTo, when set, fails the row if its warm figure exceeds compareTo's.
	compareTo  *measured
	needHashed bool
	statement  string
	argCount   int
}

func measure(ctx context.Context, t *testing.T, db *sql.DB, query string, args []any, settings ...string) (first, warm explainRun) {
	t.Helper()
	runs := make([]explainRun, 3)
	for i := range runs {
		runs[i] = explainOnce(ctx, db, query, args, settings...)
		if runs[i].err != nil {
			return runs[i], runs[i]
		}
	}
	warm = runs[1]
	warm.planMS = (runs[1].planMS + runs[2].planMS) / 2
	warm.execMS = (runs[1].execMS + runs[2].execMS) / 2
	return runs[0], warm
}

func (m *measured) passed() (bool, string) {
	if m.first.err != nil || m.warm.err != nil {
		return false, "error"
	}
	if m.compareTo != nil {
		if m.warm.totalMS() > m.compareTo.warm.totalMS() {
			return false, fmt.Sprintf("slower than %s", m.compareTo.id)
		}
		return true, fmt.Sprintf("not slower than %s", m.compareTo.id)
	}
	if m.needHashed && !m.warm.hashedSubPlan {
		// Not hashed: recorded; the dry-run threshold still decides the row.
		if m.warm.totalMS() > m.thresholdMS {
			return false, "not hashed; over threshold"
		}
		return true, "not hashed; within threshold"
	}
	figure := m.warm.totalMS()
	if m.firstRunCounts {
		figure = m.first.totalMS()
	}
	return figure <= m.thresholdMS, ""
}

func condition(t *testing.T, field, op string, value any) dsl.Condition {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal value: %v", err)
	}
	return dsl.Condition{Field: field, Op: op, Value: raw}
}

// compileMeasured validates and compiles a rule as the API and evaluator do.
func compileMeasured(t *testing.T, logic dsl.Logic, conds ...dsl.Condition) *dsl.CompiledRule {
	t.Helper()
	rule := dsl.Rule{Logic: logic, Conditions: conds}
	errs, _, _ := dsl.Validate(rule, false)
	for _, e := range errs {
		if e.Severity == "error" {
			t.Fatalf("rule refused by Validate: index %d %s: %s", e.Index, e.Field, e.Message)
		}
	}
	compiled, err := dsl.Compile(rule, uuid.New(), 1, uuid.New(), nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return compiled
}

// savedSearchQuery rebuilds store.ExecuteDSLQuery's first-page statement for a page of
// 50: the same columns (store's cveColumns), Where(nil), status filter, order and limit.
// Keep it identical to internal/store/dsl_executor.go.
func savedSearchQuery(t *testing.T, compiled *dsl.CompiledRule) (string, []any) {
	t.Helper()
	cols := []string{
		"cves.cve_id", "cves.status", "cves.date_published", "cves.date_modified_source_max",
		"cves.date_modified_canonical", "cves.date_first_seen", "cves.description_primary",
		"cves.severity", "cves.cvss_v3_score", "cves.cvss_v3_vector", "cves.cvss_v3_source",
		"cves.cvss_v4_score", "cves.cvss_v4_vector", "cves.cvss_v4_source", "cves.cvss_score_diverges",
		"cves.cwe_ids", "cves.exploit_available", "cves.in_cisa_kev", "cves.epss_score",
		"cves.date_epss_updated", "cves.material_hash",
	}
	sb := sq.StatementBuilder.PlaceholderFormat(sq.Dollar).Select(cols...).From("cves")
	for _, j := range compiled.Joins {
		sb = sb.Join(j)
	}
	if where := compiled.Where(nil); where != nil {
		sb = sb.Where(where)
	}
	q, args, err := sb.
		Where("COALESCE(lower(cves.status), '') NOT IN ('rejected', 'withdrawn')").
		OrderBy("cves.date_modified_canonical DESC, cves.cve_id DESC").
		Limit(51).
		ToSql()
	if err != nil {
		t.Fatalf("saved-search statement: %v", err)
	}
	return q, args
}

// keptInputs are the measurement inputs, chosen by read-only queries.
type keptInputs struct {
	Recent   []string `json:"recent_5000"`
	Products []string `json:"products"`
	Packages []string `json:"packages"`
}

func readInputs(ctx context.Context, t *testing.T, db *sql.DB) keptInputs {
	t.Helper()
	var in keptInputs
	rows, err := db.QueryContext(ctx, `SELECT cve_id FROM cves ORDER BY date_modified_canonical DESC LIMIT 5000`)
	in.Recent = mustScanStrings(t, rows, err)

	rows, err = db.QueryContext(ctx, `SELECT split_part(cpe_normalized, ':', 4) || ':' || split_part(cpe_normalized, ':', 5) AS vp, count(*)
		FROM cve_cpe_matches WHERE vulnerable GROUP BY 1 ORDER BY 2 DESC LIMIT 80`)
	var skipped []string
	for _, vp := range mustScanStrings(t, rows, err) {
		if len(in.Products) == 50 {
			break
		}
		if _, perr := check.ParseProductValue(vp); perr != nil {
			skipped = append(skipped, vp)
			continue
		}
		in.Products = append(in.Products, vp)
	}
	if len(skipped) > 0 {
		t.Logf("product candidates the parser refuses (skipped): %v", skipped)
	}
	if len(in.Products) != 50 || in.Products[0] != "linux:linux_kernel" {
		t.Fatalf("expected 50 products starting with linux:linux_kernel, got %d: %v", len(in.Products), in.Products)
	}

	folded := ecosystem.FoldedNameSQL("ecosystem", "package_name")
	topPackages := `SELECT ` + folded + ` AS n, count(*) FROM cve_affected_packages GROUP BY 1 ORDER BY 2 DESC LIMIT 50` //nolint:gosec // G202: FoldedNameSQL returns fixed SQL over constant column names
	rows, err = db.QueryContext(ctx, topPackages)
	in.Packages = mustScanStrings(t, rows, err)
	return in
}

// mustScanStrings reads the first column of rows as strings; other columns are ignored.
func mustScanStrings(t *testing.T, rows *sql.Rows, err error) []string {
	t.Helper()
	if err != nil {
		t.Fatalf("query inputs: %v", err)
	}
	defer rows.Close() //nolint:errcheck
	cols, err := rows.Columns()
	if err != nil {
		t.Fatalf("columns: %v", err)
	}
	var out []string
	for rows.Next() {
		dest := make([]any, len(cols))
		var s string
		dest[0] = &s
		for i := 1; i < len(cols); i++ {
			dest[i] = new(any)
		}
		if err := rows.Scan(dest...); err != nil {
			t.Fatalf("scan inputs: %v", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

// limitRule is design section 13's limit rule: 50 one-value product conditions and 50
// one-value package eq conditions with no ecosystem.
func limitRule(t *testing.T, logic dsl.Logic, in keptInputs) *dsl.CompiledRule {
	t.Helper()
	var conds []dsl.Condition
	for _, p := range in.Products {
		conds = append(conds, condition(t, "affected.cpe_product", "eq", p))
	}
	for _, n := range in.Packages {
		conds = append(conds, condition(t, "affected.package", "eq", n))
	}
	return compileMeasured(t, logic, conds...)
}

func resultsDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("KEPT_INGEST_RESULTS_DIR")
	if dir == "" {
		t.Fatal("KEPT_INGEST_RESULTS_DIR not set")
	}
	return dir
}

// TestKeptIngestMeasure runs measurements M1 to M7 and M8's read-only estimate.
func TestKeptIngestMeasure(t *testing.T) {
	ctx := context.Background()
	db := openMeasuredDB(t, "KEPT_INGEST_DATABASE_URL", "KEPT_INGEST_USER", "KEPT_INGEST_PASSWORD")
	var ro string
	if err := db.QueryRowContext(ctx, "SHOW default_transaction_read_only").Scan(&ro); err != nil || ro != "on" {
		t.Fatalf("connection is not read-only (default_transaction_read_only=%q, err %v)", ro, err)
	}
	dir := resultsDir(t)

	in := readInputs(ctx, t, db)
	inputsJSON, _ := json.MarshalIndent(in, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "inputs.json"), inputsJSON, 0o600); err != nil {
		t.Fatalf("write inputs: %v", err)
	}
	t.Logf("products: %v", in.Products)
	t.Logf("packages: %v", in.Packages)

	one := []string{keptIngestRealtimeCVE}
	linux := condition(t, "affected.cpe_product", "eq", "linux:linux_kernel")
	node := condition(t, "affected.cpe_product", "eq", "nodejs:node.js")
	kev := condition(t, "in_cisa_kev", "eq", true)
	critHigh := condition(t, "severity", "in", []string{"critical", "high"})

	var rows []*measured
	add := func(id, name, shape string, compiled *dsl.CompiledRule, ids []string, thresholdMS float64) *measured {
		q, args, err := candidateQuery(compiled, ids)
		if err != nil {
			t.Fatalf("%s: candidateQuery: %v", id, err)
		}
		m := &measured{id: id, name: name, shape: shape, thresholdMS: thresholdMS, statement: q, argCount: len(args)}
		m.first, m.warm = measure(ctx, t, db, q, args, candidateJITOff) // as queryCandidates runs it
		rows = append(rows, m)
		return m
	}

	// M1: realtime, one CVE.
	add("M1a", "linux:linux_kernel, and", "realtime", compileMeasured(t, dsl.LogicAnd, linux), one, 5)
	add("M1b", "linux:linux_kernel or in_cisa_kev", "realtime", compileMeasured(t, dsl.LogicOr, linux, kev), one, 5)

	// M2: batch, 5,000 IDs.
	add("M2a", "linux:linux_kernel, and", "batch 5,000", compileMeasured(t, dsl.LogicAnd, linux), in.Recent, 3000)
	add("M2b", "linux:linux_kernel or in_cisa_kev", "batch 5,000", compileMeasured(t, dsl.LogicOr, linux, kev), in.Recent, 3000)
	add("M2c", "nodejs:node.js, and", "batch 5,000", compileMeasured(t, dsl.LogicAnd, node), in.Recent, 3000)

	// M3: dry-run, no candidate IDs.
	add("M3a", "nodejs:node.js and severity critical/high", "dry-run", compileMeasured(t, dsl.LogicAnd, node, critHigh), nil, 5000)
	add("M3b", "nodejs:node.js alone", "dry-run", compileMeasured(t, dsl.LogicAnd, node), nil, 5000)
	add("M3c", "nodejs:node.js or in_cisa_kev", "dry-run", compileMeasured(t, dsl.LogicOr, node, kev), nil, 5000)
	add("M3d", "linux:linux_kernel alone", "dry-run", compileMeasured(t, dsl.LogicAnd, linux), nil, 5000)
	add("M3e", "linux:linux_kernel or in_cisa_kev", "dry-run", compileMeasured(t, dsl.LogicOr, linux, kev), nil, 5000)

	// M4: saved-search shape.
	{
		q, args := savedSearchQuery(t, compileMeasured(t, dsl.LogicAnd, linux))
		m := &measured{id: "M4", name: "linux:linux_kernel", shape: "saved search, page of 50", thresholdMS: 5000, statement: q, argCount: len(args)}
		m.first, m.warm = measure(ctx, t, db, q, args)
		rows = append(rows, m)
	}

	// M5: the limit rule. Thresholds apply under or; and is for information.
	limitOr, limitAnd := limitRule(t, dsl.LogicOr, in), limitRule(t, dsl.LogicAnd, in)
	add("M5a", "limit rule, or", "realtime", limitOr, one, 5)
	add("M5b", "limit rule, or", "dry-run", limitOr, nil, 5000)
	add("M5c", "limit rule, or", "batch 5,000", limitOr, in.Recent, 3000)
	add("M5d", "limit rule, and (information)", "realtime", limitAnd, one, 0).thresholdMS = -1
	add("M5e", "limit rule, and (information)", "dry-run", limitAnd, nil, 0).thresholdMS = -1
	add("M5f", "limit rule, and (information)", "batch 5,000", limitAnd, in.Recent, 0).thresholdMS = -1

	// M6: or rule of the 50 products, dry-run; the set SubPlan should stay hashed.
	{
		var conds []dsl.Condition
		for _, p := range in.Products {
			conds = append(conds, condition(t, "affected.cpe_product", "eq", p))
		}
		add("M6", "50 products, or", "dry-run", compileMeasured(t, dsl.LogicOr, conds...), nil, 5000).needHashed = true
	}

	// M7: package array forms, dry-run.
	add("M7a", "npm, package in 50 names", "dry-run",
		compileMeasured(t, dsl.LogicAnd, condition(t, "affected.ecosystem", "eq", "npm"), condition(t, "affected.package", "in", in.Packages)), nil, 5000)
	add("M7b", "Debian, package eq openssl", "dry-run",
		compileMeasured(t, dsl.LogicAnd, condition(t, "affected.ecosystem", "eq", "Debian"), condition(t, "affected.package", "eq", "openssl")), nil, 5000)
	add("M7c", "package eq openssl, no ecosystem", "dry-run",
		compileMeasured(t, dsl.LogicAnd, condition(t, "affected.package", "eq", "openssl")), nil, 5000).firstRunCounts = true
	{
		// The form before this work (affectedPackageSQL): one correlated EXISTS per row,
		// written out here for comparison only, in candidateQuery's outer statement.
		old, oldArgs, err := sq.StatementBuilder.PlaceholderFormat(sq.Dollar).
			Select("cves.cve_id", "COALESCE(cves.material_hash, '')", "COALESCE(lower(cves.description_primary), '')").
			From("cves").
			Where(sq.And{
				sq.Expr(`EXISTS (SELECT 1 FROM cve_affected_packages cap WHERE cap.cve_id = cves.cve_id AND lower(cap.package_name) ILIKE ?)`, "%lodash%"),
				sq.Expr("COALESCE(lower(cves.status), '') NOT IN ('rejected', 'withdrawn')"),
			}).
			Limit(uint64(candidateCap + 1)). //nolint:gosec // G115: constant, not user input
			ToSql()
		if err != nil {
			t.Fatalf("old contains form: %v", err)
		}
		oldRow := &measured{id: "M7d-old", name: "package contains lodash, no ecosystem, per-row EXISTS (before)", shape: "dry-run", thresholdMS: -1, statement: old, argCount: len(oldArgs)}
		oldRow.first, oldRow.warm = measure(ctx, t, db, old, oldArgs, candidateJITOff)
		rows = append(rows, oldRow)
		add("M7d", "package contains lodash, no ecosystem, set form", "dry-run",
			compileMeasured(t, dsl.LogicAnd, condition(t, "affected.package", "contains", "lodash")), nil, 0).compareTo = oldRow
	}

	m8 := m8Estimate(ctx, t, db, limitOr)

	writeResults(t, filepath.Join(dir, "measurements.md"), rows, m8)
	for _, m := range rows {
		if m.thresholdMS < 0 && m.compareTo == nil {
			continue
		}
		if ok, why := m.passed(); !ok {
			t.Errorf("%s (%s, %s) fails its threshold: %s", m.id, m.name, m.shape, why)
		}
	}
}

// m8Result is M8's read-only estimate: the activation scan's reads on the kept ingest.
type m8Result struct {
	pages, matches int
	elapsed        time.Duration
	err            error
}

// m8Estimate walks the corpus as EvaluateActivation does (getCVEsBatch pages of
// activationBatch, queryCandidates in a bypass transaction with the long statement
// timeout, cveExists per match) and times the reads. Nothing is written.
func m8Estimate(ctx context.Context, t *testing.T, db *sql.DB, compiled *dsl.CompiledRule) m8Result {
	t.Helper()
	e := New(db, nil, NewRuleCache(), slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), 120000)
	var res m8Result
	start := time.Now()
	var lastID string
	for {
		batch, err := e.getCVEsBatch(ctx, lastID, activationBatch)
		if err != nil {
			res.err = err
			break
		}
		if len(batch) == 0 {
			break
		}
		res.pages++
		var candidates []cveSummary
		if err := e.bypassTx(ctx, e.longStatementTimeoutMS, func(tx *sql.Tx) error {
			var qerr error
			candidates, _, qerr = e.queryCandidates(ctx, tx, compiled, batch)
			return qerr
		}); err != nil {
			res.err = err
			break
		}
		for _, c := range candidates {
			if _, err := e.cveExists(ctx, c.CVEID); err != nil {
				res.err = err
				break
			}
			res.matches++
		}
		if res.err != nil {
			break
		}
		lastID = batch[len(batch)-1]
	}
	res.elapsed = time.Since(start)
	t.Logf("M8 estimate: %d pages, %d matches, %s, err %v", res.pages, res.matches, res.elapsed, res.err)
	return res
}

func writeResults(t *testing.T, path string, rows []*measured, m8 m8Result) {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "| # | Measurement | Statement shape | Args | First run plan / exec (ms) | Warm plan / exec (ms) | Rows | Plan notes | Threshold | Result |\n")
	fmt.Fprintf(&b, "|---|---|---|---|---|---|---|---|---|---|\n")
	for _, m := range rows {
		notes := []string{}
		if m.warm.hashedSubPlan {
			notes = append(notes, "hashed SubPlan")
		} else if m.needHashed {
			notes = append(notes, "SubPlan NOT hashed")
		}
		if len(m.warm.seqScans) > 0 {
			notes = append(notes, "seq scan: "+strings.Join(m.warm.seqScans, ", "))
		}
		threshold, result := "information only", "-"
		switch {
		case m.compareTo != nil:
			threshold = "not slower than " + m.compareTo.id
		case m.thresholdMS >= 0 && m.firstRunCounts:
			threshold = fmt.Sprintf("first run <= %s ms", trimFloat(m.thresholdMS))
		case m.thresholdMS >= 0:
			threshold = fmt.Sprintf("warm <= %s ms", trimFloat(m.thresholdMS))
		}
		if m.thresholdMS >= 0 || m.compareTo != nil {
			ok, why := m.passed()
			result = map[bool]string{true: "pass", false: "FAIL"}[ok]
			if why != "" {
				result += " (" + why + ")"
			}
			if ok && !m.firstRunCounts && m.compareTo == nil && m.first.totalMS() > m.thresholdMS {
				result += "; first run over threshold"
			}
		}
		if m.first.err != nil {
			notes = append(notes, "error: "+errorClass(m.first.err))
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %.2f / %.2f | %.2f / %.2f | %.0f | %s | %s | %s |\n",
			m.id, m.name, m.shape, m.argCount, m.first.planMS, m.first.execMS, m.warm.planMS, m.warm.execMS,
			m.warm.rows, strings.Join(notes, "; "), threshold, result)
	}
	if m8.pages > 0 || m8.err != nil {
		fmt.Fprintf(&b, "\nM8 read-only estimate (kept ingest): %d pages of %d IDs, %d matches, %s read time",
			m8.pages, activationBatch, m8.matches, m8.elapsed.Round(time.Second))
		if m8.err != nil {
			fmt.Fprintf(&b, ", stopped by error (%s)", errorClass(m8.err))
		}
		b.WriteString(".\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write results: %v", err)
	}
}

func trimFloat(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

// TestKeptIngestLimitSweep measures the limit rule's shape at smaller limits, for the
// gate decision in design section 13: the K largest products and the K most common
// packages under "or". It also runs the full limit rule with parallel query off, to
// separate the statement's own cost from a parallel hash's shared memory. It reuses
// the inputs TestKeptIngestMeasure wrote, so the rows compare with its table.
func TestKeptIngestLimitSweep(t *testing.T) {
	ctx := context.Background()
	db := openMeasuredDB(t, "KEPT_INGEST_DATABASE_URL", "KEPT_INGEST_USER", "KEPT_INGEST_PASSWORD")
	var ro string
	if err := db.QueryRowContext(ctx, "SHOW default_transaction_read_only").Scan(&ro); err != nil || ro != "on" {
		t.Fatalf("connection is not read-only (default_transaction_read_only=%q, err %v)", ro, err)
	}
	dir := resultsDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "inputs.json"))
	if err != nil {
		t.Fatalf("read inputs: %v", err)
	}
	var in keptInputs
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatalf("parse inputs: %v", err)
	}
	one := []string{keptIngestRealtimeCVE}
	var rows []*measured
	run := func(id, name, shape string, compiled *dsl.CompiledRule, ids []string, thresholdMS float64, settings ...string) {
		q, args, err := candidateQuery(compiled, ids)
		if err != nil {
			t.Fatalf("%s: candidateQuery: %v", id, err)
		}
		m := &measured{id: id, name: name, shape: shape, thresholdMS: thresholdMS, statement: q, argCount: len(args)}
		m.first, m.warm = measure(ctx, t, db, q, args, append([]string{candidateJITOff}, settings...)...) // as queryCandidates runs it
		rows = append(rows, m)
	}
	for _, k := range []int{5, 10, 15, 25} {
		sub := keptInputs{Products: in.Products[:k], Packages: in.Packages[:k]}
		r := limitRule(t, dsl.LogicOr, sub)
		name := fmt.Sprintf("%d products + %d packages, or", k, k)
		run(fmt.Sprintf("S%d-rt", k), name, "realtime", r, one, 5)
		run(fmt.Sprintf("S%d-dry", k), name, "dry-run", r, nil, 5000)
		run(fmt.Sprintf("S%d-batch", k), name, "batch 5,000", r, in.Recent, 3000)
	}
	for _, k := range []int{10, 25} {
		var conds []dsl.Condition
		for _, p := range in.Products[:k] {
			conds = append(conds, condition(t, "affected.cpe_product", "eq", p))
		}
		run(fmt.Sprintf("S%d-products", k), fmt.Sprintf("%d products, or", k), "dry-run", compileMeasured(t, dsl.LogicOr, conds...), nil, 5000)
	}
	noParallel := "SET LOCAL max_parallel_workers_per_gather = 0"
	full := limitRule(t, dsl.LogicOr, in)
	run("S50-dry-serial", "limit rule, or, parallel query off", "dry-run", full, nil, 5000, noParallel)
	run("S50-batch-serial", "limit rule, or, parallel query off", "batch 5,000", full, in.Recent, 3000, noParallel)
	writeResults(t, filepath.Join(dir, "sweep.md"), rows, m8Result{})
}

// TestKeptIngestMergedForms measures the limit rule's content as two set conditions,
// one product "in" of the 50 products and one package "in" of the 50 names, under
// "or": the form the compiler already emits for a list, against the 100 one-value
// conditions of M5 and M6. JIT is measured on (the server default) and off.
func TestKeptIngestMergedForms(t *testing.T) {
	ctx := context.Background()
	db := openMeasuredDB(t, "KEPT_INGEST_DATABASE_URL", "KEPT_INGEST_USER", "KEPT_INGEST_PASSWORD")
	var ro string
	if err := db.QueryRowContext(ctx, "SHOW default_transaction_read_only").Scan(&ro); err != nil || ro != "on" {
		t.Fatalf("connection is not read-only (default_transaction_read_only=%q, err %v)", ro, err)
	}
	dir := resultsDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "inputs.json"))
	if err != nil {
		t.Fatalf("read inputs: %v", err)
	}
	var in keptInputs
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatalf("parse inputs: %v", err)
	}
	one := []string{keptIngestRealtimeCVE}
	merged := compileMeasured(t, dsl.LogicOr,
		condition(t, "affected.cpe_product", "in", in.Products),
		condition(t, "affected.package", "in", in.Packages))
	productsOnly := compileMeasured(t, dsl.LogicOr, condition(t, "affected.cpe_product", "in", in.Products))
	var rows []*measured
	run := func(id, name, shape string, compiled *dsl.CompiledRule, ids []string, thresholdMS float64, settings ...string) {
		q, args, err := candidateQuery(compiled, ids)
		if err != nil {
			t.Fatalf("%s: candidateQuery: %v", id, err)
		}
		m := &measured{id: id, name: name, shape: shape, thresholdMS: thresholdMS, statement: q, argCount: len(args)}
		m.first, m.warm = measure(ctx, t, db, q, args, settings...)
		rows = append(rows, m)
	}
	jitOff := candidateJITOff
	for _, jit := range []struct {
		suffix   string
		settings []string
	}{{"", nil}, {"-nojit", []string{jitOff}}} {
		label := "product in 50 or package in 50"
		if jit.suffix != "" {
			label += ", jit off"
		}
		run("G-rt"+jit.suffix, label, "realtime", merged, one, 5, jit.settings...)
		run("G-dry"+jit.suffix, label, "dry-run", merged, nil, 5000, jit.settings...)
		run("G-batch"+jit.suffix, label, "batch 5,000", merged, in.Recent, 3000, jit.settings...)
	}
	run("G-products-dry", "product in 50 (one condition)", "dry-run", productsOnly, nil, 5000)
	run("G-products-dry-nojit", "product in 50 (one condition), jit off", "dry-run", productsOnly, nil, 5000, jitOff)
	writeResults(t, filepath.Join(dir, "merged.md"), rows, m8Result{})
}

// TestKeptIngestExplainPlans writes the text plans of the limit rule's realtime
// and batch statements under "or", for reading why a row fails. Batch runs with
// parallel query off so it completes inside the container's shared memory.
func TestKeptIngestExplainPlans(t *testing.T) {
	ctx := context.Background()
	db := openMeasuredDB(t, "KEPT_INGEST_DATABASE_URL", "KEPT_INGEST_USER", "KEPT_INGEST_PASSWORD")
	dir := resultsDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "inputs.json"))
	if err != nil {
		t.Fatalf("read inputs: %v", err)
	}
	var in keptInputs
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatalf("parse inputs: %v", err)
	}
	limitOr := limitRule(t, dsl.LogicOr, in)
	node := compileMeasured(t, dsl.LogicAnd, condition(t, "affected.cpe_product", "eq", "nodejs:node.js"))
	var b strings.Builder
	for _, c := range []struct {
		name     string
		rule     *dsl.CompiledRule
		ids      []string
		settings []string
	}{
		{"limit rule, or, realtime", limitOr, []string{keptIngestRealtimeCVE}, []string{candidateJITOff}},
		{"limit rule, or, batch 5,000", limitOr, in.Recent, []string{candidateJITOff}},
		{"nodejs:node.js, and, batch 5,000", node, in.Recent, []string{candidateJITOff}},
	} {
		q, args, err := candidateQuery(c.rule, c.ids)
		if err != nil {
			t.Fatalf("candidateQuery: %v", err)
		}
		tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		for _, s := range append([]string{"SET LOCAL statement_timeout = '120s'"}, c.settings...) {
			if _, err := tx.ExecContext(ctx, s); err != nil {
				t.Fatalf("%s: %v", s, err)
			}
		}
		rows, err := tx.QueryContext(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) "+q, args...)
		if err != nil {
			_ = tx.Rollback()
			t.Fatalf("explain %s: %s", c.name, errorClass(err))
		}
		fmt.Fprintf(&b, "==== %s\n", c.name)
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				t.Fatalf("scan: %v", err)
			}
			b.WriteString(line + "\n")
		}
		_ = rows.Close()
		_ = tx.Rollback()
	}
	if err := os.WriteFile(filepath.Join(dir, "plans.txt"), []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write plans: %v", err)
	}
}

// TestKeptIngestLimitSerial measures the limit rule under "or" with JIT off and
// parallel query off, as evidence for the gate decision.
func TestKeptIngestLimitSerial(t *testing.T) {
	ctx := context.Background()
	db := openMeasuredDB(t, "KEPT_INGEST_DATABASE_URL", "KEPT_INGEST_USER", "KEPT_INGEST_PASSWORD")
	dir := resultsDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "inputs.json"))
	if err != nil {
		t.Fatalf("read inputs: %v", err)
	}
	var in keptInputs
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatalf("parse inputs: %v", err)
	}
	limitOr := limitRule(t, dsl.LogicOr, in)
	serial := []string{candidateJITOff, "SET LOCAL max_parallel_workers_per_gather = 0"}
	var rows []*measured
	for _, c := range []struct {
		id, shape   string
		ids         []string
		thresholdMS float64
	}{
		{"P5a", "realtime", []string{keptIngestRealtimeCVE}, 5},
		{"P5b", "dry-run", nil, 5000},
		{"P5c", "batch 5,000", in.Recent, 3000},
	} {
		q, args, err := candidateQuery(limitOr, c.ids)
		if err != nil {
			t.Fatalf("candidateQuery: %v", err)
		}
		m := &measured{id: c.id, name: "limit rule, or, JIT and parallel query off", shape: c.shape, thresholdMS: c.thresholdMS, statement: q, argCount: len(args)}
		m.first, m.warm = measure(ctx, t, db, q, args, serial...)
		rows = append(rows, m)
	}
	writeResults(t, filepath.Join(dir, "serial.md"), rows, m8Result{})
}
