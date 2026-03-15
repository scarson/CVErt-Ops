// ABOUTME: Generic post-filter logic for regex-based candidate filtering.
// ABOUTME: Shared by the alert evaluator and DSL executor to eliminate duplication.
package dsl

// PostFilterTarget provides field values for post-filter matching.
type PostFilterTarget interface {
	PostFilterField(field string) string
}

// ApplyPostFilters filters candidates using regex post-filters with AND/OR logic.
// Returns all candidates unchanged when filters is empty.
func ApplyPostFilters[T PostFilterTarget](candidates []T, filters []PostFilter, logic Logic) []T {
	if len(filters) == 0 {
		return candidates
	}
	var matched []T
	for _, c := range candidates {
		if matchesPostFilters(c, filters, logic) {
			matched = append(matched, c)
		}
	}
	return matched
}

func matchesPostFilters[T PostFilterTarget](c T, filters []PostFilter, logic Logic) bool {
	for _, f := range filters {
		ok := f.Pattern.MatchString(c.PostFilterField(f.Field))
		if f.Negate {
			ok = !ok
		}
		if logic == LogicOr && ok {
			return true
		}
		if logic == LogicAnd && !ok {
			return false
		}
	}
	return logic == LogicAnd
}
