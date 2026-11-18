// Package shop is a Go fixture for the performance-audit evals: a small HTTP
// service exercising the core Go lanes + the net-http-servers and database-sql
// modules + Runtime notes. Illustrative (not built). See expected-findings.md
// (do NOT read it as the agent under test).
package shop

import (
	"database/sql"
	"encoding/json"
	"net/http"
)

type Server struct {
	db *sql.DB
}

// HandleOrder enriches an order's line items and returns them.
func (s *Server) HandleOrder(w http.ResponseWriter, r *http.Request) {
	ids := r.URL.Query()["item"]

	// PLANTED #1 (data-access / N+1, module: database-sql): one query per item in
	// a loop instead of one `WHERE id = ANY($1)` batch. Reached per request.
	var items []Item
	for _, id := range ids {
		row := s.db.QueryRow("SELECT id, name, price FROM items WHERE id = $1", id)
		var it Item
		if err := row.Scan(&it.ID, &it.Name, &it.Price); err == nil {
			items = append(items, it)
		}
	}

	// PLANTED #2 (data-access, module: net-http-servers): a fresh http.Client per
	// request — no connection reuse / keep-alive; should be a shared client built
	// once. Also the body is never drained+closed.
	client := &http.Client{}
	resp, _ := client.Get("http://pricing/quote?order=" + r.URL.Query().Get("order"))
	var quote Quote
	json.NewDecoder(resp.Body).Decode(&quote)

	json.NewEncoder(w).Encode(map[string]any{"items": items, "quote": quote})
}

// Totals fetches three independent aggregates. PLANTED #3 (concurrency): the three
// calls are independent but awaited sequentially — latency is the sum. They could
// run concurrently (errgroup / goroutines + a WaitGroup). Independence holds: no
// shared mutable state, no ordering dependency.
func (s *Server) Totals(orderID string) (Totals, error) {
	revenue, err := s.fetchRevenue(orderID)
	if err != nil {
		return Totals{}, err
	}
	tax, err := s.fetchTax(orderID)
	if err != nil {
		return Totals{}, err
	}
	ship, err := s.fetchShipping(orderID)
	if err != nil {
		return Totals{}, err
	}
	return Totals{revenue, tax, ship}, nil
}
