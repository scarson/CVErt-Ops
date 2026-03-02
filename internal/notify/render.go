// ABOUTME: Template rendering for alert and digest notification emails.
// ABOUTME: Templates parsed once at init from embedded FS; rendered per delivery.
package notify

import (
	"bytes"
	"embed"
	"fmt"
	htmltpl "html/template"
	"strings"
	texttpl "text/template"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

// Template function maps shared by both HTML and text templates.
var funcMap = map[string]any{
	// deref dereferences a *float64 for use in printf. Returns 0 if nil.
	"deref": func(v *float64) float64 {
		if v == nil {
			return 0
		}
		return *v
	},
	// pct converts a 0-1 float to 0-100 for percentage display.
	"pct": func(v float64) float64 {
		return v * 100
	},
	// sevColor returns a CSS background color for a severity level.
	"sevColor": func(sev string) string {
		switch strings.ToLower(sev) {
		case "critical":
			return "#7b2d8b"
		case "high":
			return "#dc3545"
		case "medium":
			return "#fd7e14"
		case "low":
			return "#ffc107"
		default:
			return "#6c757d"
		}
	},
}

// Parsed templates — one per file to avoid {{define}} namespace collisions.
var (
	alertHTML  *htmltpl.Template
	alertText  *texttpl.Template
	digestHTML *htmltpl.Template
	digestText *texttpl.Template
)

func init() {
	alertHTML = htmltpl.Must(htmltpl.New("").Funcs(htmltpl.FuncMap(funcMap)).ParseFS(templateFS, "templates/email_alert.html.tmpl"))
	alertText = texttpl.Must(texttpl.New("").Funcs(texttpl.FuncMap(funcMap)).ParseFS(templateFS, "templates/email_alert.txt.tmpl"))
	digestHTML = htmltpl.Must(htmltpl.New("").Funcs(htmltpl.FuncMap(funcMap)).ParseFS(templateFS, "templates/email_digest.html.tmpl"))
	digestText = texttpl.Must(texttpl.New("").Funcs(texttpl.FuncMap(funcMap)).ParseFS(templateFS, "templates/email_digest.txt.tmpl"))
}

// RenderAlert renders an alert notification email. Returns subject, HTML body, and plaintext body.
func RenderAlert(data AlertTemplateData) (string, string, string, error) {
	return renderPair(alertHTML, alertText, data)
}

// RenderDigest renders a digest email. Returns subject, HTML body, and plaintext body.
func RenderDigest(data DigestTemplateData) (string, string, string, error) {
	return renderPair(digestHTML, digestText, data)
}

func renderPair(html *htmltpl.Template, text *texttpl.Template, data any) (string, string, string, error) {
	// Render subject from the text template's "subject" block.
	var subjectBuf bytes.Buffer
	if err := text.ExecuteTemplate(&subjectBuf, "subject", data); err != nil {
		return "", "", "", fmt.Errorf("render subject: %w", err)
	}
	subject := sanitizeSubject(subjectBuf.String())

	// Render HTML body.
	var htmlBuf bytes.Buffer
	if err := html.ExecuteTemplate(&htmlBuf, "body", data); err != nil {
		return "", "", "", fmt.Errorf("render html: %w", err)
	}

	// Render text body.
	var textBuf bytes.Buffer
	if err := text.ExecuteTemplate(&textBuf, "body", data); err != nil {
		return "", "", "", fmt.Errorf("render text: %w", err)
	}

	return subject, htmlBuf.String(), textBuf.String(), nil
}

// sanitizeSubject strips CR/LF to prevent email header injection.
func sanitizeSubject(s string) string {
	s = strings.TrimSpace(s)
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}
