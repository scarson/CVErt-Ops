package merge

import "strings"

// JoinForFTS joins a slice of terms with spaces for use as a Postgres
// to_tsvector input string. Returns an empty string for nil/empty input.
func JoinForFTS(terms []string) string {
	return strings.Join(terms, " ")
}
