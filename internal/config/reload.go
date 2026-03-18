// ABOUTME: Reloads hot-reloadable configuration from the secrets file.
// ABOUTME: Called by SIGHUP handler (Unix) and the admin API endpoint.
package config

import "log/slog"

// ReloadConfig reads the secrets file and atomically updates the config holder.
// If rescan is non-nil, it is called after a successful reload to re-read feed
// configuration files. Panics are recovered so callers (signal handlers,
// HTTP handlers) never crash the process.
func ReloadConfig(holder *Holder, secretsFile string, rescan func()) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("config reload panicked", "panic", r)
		}
	}()

	if secretsFile == "" {
		slog.Info("config reload requested but CVERTOPS_SECRETS_FILE not configured — no-op")
		return
	}

	newCfg, err := LoadFromSecretsFile(secretsFile, holder.Load())
	if err != nil {
		slog.Error("config reload failed — keeping current config", "error", err)
		return
	}

	holder.Store(newCfg)
	slog.Info("config reloaded successfully")

	if rescan != nil {
		rescan()
	}
}
