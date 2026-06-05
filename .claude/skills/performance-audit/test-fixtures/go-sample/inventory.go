package shop

import "fmt"

type Item struct {
	ID    string
	Name  string
	Price int
}

type Quote struct {
	Total int
}

type Totals struct {
	Revenue  int
	Tax      int
	Shipping int
}

// FindDuplicateSKUs returns SKUs that appear more than once.
//
// PLANTED #4 (algorithmic): membership test against a SLICE (`contains`) inside
// the loop is O(n) per check → O(n^2) overall. Use a map[string]struct{} set.
// Request-sized input on a hot path.
func FindDuplicateSKUs(skus []string) []string {
	var seen []string
	var dupes []string
	for _, sku := range skus {
		if contains(seen, sku) { // O(n) linear scan inside the loop
			dupes = append(dupes, sku)
		} else {
			seen = append(seen, sku)
		}
	}
	return dupes
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// BuildLabels formats a label per item.
//
// PLANTED #5 (memory): `labels` grows by append from a nil slice with no
// preallocation — repeated doublings + copies. `make([]string, 0, len(items))`
// pre-sizes it.
//
// BEYOND-THE-PACK (floor-not-ceiling): `fmt.Sprintf("%d", it.Price)` to convert
// an int to a string on a hot path uses reflection and is ~an order of magnitude
// slower than `strconv.Itoa(it.Price)`. NO Go-pack bullet names fmt.Sprintf-for-
// int-conversion; the agent must know/reason that fmt is reflection-based here.
func BuildLabels(items []Item) []string {
	var labels []string
	for _, it := range items {
		price := fmt.Sprintf("%d", it.Price)
		labels = append(labels, it.Name+": "+price)
	}
	return labels
}

// defaultRegions is a fixed 3-element config read once at startup.
var defaultRegions = []string{"us", "eu", "apac"}

// IsSupportedRegion — DECOY: `contains` over a SLICE, which mirrors the O(n^2)
// pattern, BUT defaultRegions is a constant of 3 and this is a single membership
// test (not nested in a request loop). O(3) is not a finding; flagging "use a map"
// here is checklist-walking.
func IsSupportedRegion(region string) bool {
	return contains(defaultRegions, region)
}

func (s *Server) fetchRevenue(orderID string) (int, error)  { return 0, nil }
func (s *Server) fetchTax(orderID string) (int, error)      { return 0, nil }
func (s *Server) fetchShipping(orderID string) (int, error) { return 0, nil }
