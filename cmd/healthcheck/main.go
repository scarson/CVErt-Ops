// ABOUTME: Minimal healthcheck binary for Docker HEALTHCHECK in distroless containers.
// ABOUTME: Exits 0 if /healthz returns 200, exits 1 otherwise.
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	url := fmt.Sprintf("http://localhost%s/healthz", addr)

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url) //nolint:noctx // healthcheck binary — no parent context
	if err != nil {
		os.Exit(1)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
}
