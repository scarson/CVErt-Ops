// ABOUTME: Sanitizes CVE text before sending to the LLM to prevent prompt injection.
// ABOUTME: Strips markdown links, HTML tags, and control characters.
package ai

import (
	"regexp"
	"strings"
	"unicode"
)

var (
	markdownLinkRe = regexp.MustCompile(`!?\[([^\]]*)\]\([^)]*\)`)
	htmlTagRe      = regexp.MustCompile(`<[^>]*>`)
)

// Sanitize strips markdown link syntax, HTML tags, and control characters
// from text. Newlines and tabs are preserved.
func Sanitize(s string) string {
	// Replace [text](url) with just text.
	s = markdownLinkRe.ReplaceAllString(s, "$1")
	// Strip HTML tags.
	s = htmlTagRe.ReplaceAllString(s, "")
	// Remove control characters (Cc) and format characters (Cf: bidi overrides,
	// zero-width spaces, BOM) except newline (\n) and tab (\t).
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\n' || r == '\t' {
			b.WriteRune(r)
			continue
		}
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
