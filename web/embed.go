// ABOUTME: Embeds the frontend static assets (built by Vite) into the Go binary.
// ABOUTME: Import this package and use web.Assets to serve the SPA.

package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var assets embed.FS

// Assets returns the frontend static files rooted at the dist/ directory.
// The returned FS has the dist/ prefix stripped, so files are accessed
// as "index.html" rather than "dist/index.html".
func Assets() (fs.FS, error) {
	return fs.Sub(assets, "dist")
}
