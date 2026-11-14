// ABOUTME: Checks that one compiled rule gives the same SQL and arguments when many goroutines call Where at once.
// ABOUTME: The rule cache shares a CompiledRule across goroutines, so Where must only read what Compile built.
package dsl_test

import (
	"database/sql/driver"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/alert/dsl"
)

func TestWhere_ConcurrentCallsMatchSerialResult(t *testing.T) {
	t.Parallel()
	conds := []string{
		`{"field":"affected.cpe_product","operator":"eq","value":"nodejs:node.js"}`,
		`{"field":"affected.cpe_product","operator":"in","value":["microsoft:.net","microsoft:.net_framework"]}`,
		`{"field":"affected.ecosystem","operator":"in","value":["npm","PyPI"]}`,
		`{"field":"affected.ecosystem","operator":"neq","value":"Debian"}`,
		`{"field":"affected.package","operator":"in","value":["lodash","Foo_Bar"]}`,
		`{"field":"affected.package","operator":"eq","value":"express"}`,
		`{"field":"severity","operator":"in","value":["critical","high"]}`,
	}
	candidateLists := [][]string{nil, {"CVE-2026-1"}, {"CVE-2026-1", "CVE-2026-2", "CVE-2026-3"}}

	for _, logic := range []string{"and", "or"} {
		compiled, err := dsl.Compile(mustParse(t, ruleJSON(logic, conds...)), testRuleID, 1, testOrgID, []uuid.UUID{uuid.New()})
		if err != nil {
			t.Fatalf("%s: Compile: %v", logic, err)
		}
		type result struct {
			sql  string
			args string
		}
		// Arguments are compared by their driver values: pq.Array returns a new
		// pointer on every call, so the pointers themselves always differ.
		render := func(ids []string) (result, error) {
			q, args, err := compiled.Where(ids).ToSql()
			if err != nil {
				return result{}, err
			}
			vals := make([]any, len(args))
			for i, a := range args {
				vals[i] = a
				if v, ok := a.(driver.Valuer); ok {
					if vals[i], err = v.Value(); err != nil {
						return result{}, err
					}
				}
			}
			return result{q, fmt.Sprintf("%#v", vals)}, nil
		}
		want := make([]result, len(candidateLists))
		for i, ids := range candidateLists {
			if want[i], err = render(ids); err != nil {
				t.Fatalf("%s: serial Where: %v", logic, err)
			}
		}

		const goroutines, calls = 32, 50
		var wg sync.WaitGroup
		errs := make(chan string, goroutines*calls)
		for g := range goroutines {
			wg.Go(func() {
				for c := range calls {
					i := (g + c) % len(candidateLists)
					got, err := render(candidateLists[i])
					if err != nil {
						errs <- fmt.Sprintf("%s: Where(%v): %v", logic, candidateLists[i], err)
						continue
					}
					if !reflect.DeepEqual(got, want[i]) {
						errs <- fmt.Sprintf("%s: Where(%v) differs from the serial result", logic, candidateLists[i])
					}
				}
			})
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			t.Error(e)
		}
	}
}
