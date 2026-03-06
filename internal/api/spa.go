// ABOUTME: SPA fallback handler for serving the embedded Vue frontend.
// ABOUTME: Serves static files from the embedded FS; unknown paths return index.html.

package api

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// newSPAHandler returns an http.Handler that serves static files from the
// provided filesystem. If the requested path does not exist, it serves
// index.html (SPA client-side routing fallback).
//
// Cache policy:
//   - Files under assets/ get immutable caching (Vite hashes filenames)
//   - index.html gets no-cache (must always be fresh)
func newSPAHandler(staticFS fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(staticFS))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Clean the path and try to open the file.
		p := path.Clean(r.URL.Path)
		if p == "/" {
			p = "index.html"
		} else {
			p = strings.TrimPrefix(p, "/")
		}

		// Check if the file exists in the embedded FS.
		f, err := staticFS.Open(p)
		if err != nil {
			// File doesn't exist — serve index.html (SPA fallback).
			setCacheHeaders(w, "index.html")
			r.URL.Path = "/"
			fileServer.ServeHTTP(w, r)
			return
		}
		_ = f.Close()

		// File exists — serve it with appropriate cache headers.
		setCacheHeaders(w, p)
		fileServer.ServeHTTP(w, r)
	})
}

func setCacheHeaders(w http.ResponseWriter, filePath string) {
	if strings.HasPrefix(filePath, "assets/") {
		// Vite-hashed assets — cache forever.
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		// index.html and other non-hashed files — always revalidate.
		w.Header().Set("Cache-Control", "no-cache")
	}
}
