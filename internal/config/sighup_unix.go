//go:build !windows

// ABOUTME: SIGHUP signal handler for hot-reloading configuration on Unix systems.
// ABOUTME: Uses a separate signal channel — must never be added to the shutdown context.
package config

import (
	"os"
	"os/signal"
	"syscall"
)

// StartSIGHUPHandler listens for SIGHUP and reloads configuration.
// Returns a cancel function to stop the listener goroutine.
func StartSIGHUPHandler(holder *Holder, secretsFile string, rescan func()) func() {
	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	done := make(chan struct{})

	go func() {
		for {
			select {
			case <-sighupCh:
				ReloadConfig(holder, secretsFile, rescan)
			case <-done:
				signal.Stop(sighupCh)
				return
			}
		}
	}()

	return func() { close(done) }
}
