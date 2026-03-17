// ABOUTME: No-op SIGHUP stub for Windows where SIGHUP does not exist.
// ABOUTME: Returns a no-op cancel function to match the Unix signature.
package config

// StartSIGHUPHandler is a no-op on Windows. SIGHUP is a Unix-only signal.
func StartSIGHUPHandler(_ *Holder, _ string, _ func()) func() {
	return func() {}
}
