// ABOUTME: Tests for tier resolver — override precedence, tier fallback, type handling.
// ABOUTME: Covers IntLimit and BoolFlag with various tier + override combinations.
package tier

import "testing"

func TestIntLimit(t *testing.T) {
	tests := []struct {
		name                      string
		tier                      string
		overrides                 map[string]any
		limitName                 string
		free, pro, enterprise int
		want                      int
	}{
		{"free default", "free", nil, "max_alert_rules", 5, 50, -1, 5},
		{"pro default", "pro", nil, "max_alert_rules", 5, 50, -1, 50},
		{"enterprise default", "enterprise", nil, "max_alert_rules", 5, 50, -1, -1},
		{"unknown tier falls back to free", "unknown", nil, "max_alert_rules", 5, 50, -1, 5},
		{"override takes precedence", "free", map[string]any{"max_alert_rules": float64(100)}, "max_alert_rules", 5, 50, -1, 100},
		{"override zero is valid", "pro", map[string]any{"max_alert_rules": float64(0)}, "max_alert_rules", 5, 50, -1, 0},
		{"wrong key ignored", "pro", map[string]any{"wrong_key": float64(99)}, "max_alert_rules", 5, 50, -1, 50},
		{"empty overrides map", "pro", map[string]any{}, "max_alert_rules", 5, 50, -1, 50},
		{"wrong-type override ignored", "pro", map[string]any{"max_alert_rules": "100"}, "max_alert_rules", 5, 50, -1, 50},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Resolver{Tier: tt.tier, Overrides: tt.overrides}
			got := r.IntLimit(tt.limitName, tt.free, tt.pro, tt.enterprise)
			if got != tt.want {
				t.Errorf("IntLimit() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestBoolFlag(t *testing.T) {
	tests := []struct {
		name                      string
		tier                      string
		overrides                 map[string]any
		flagName                  string
		free, pro, enterprise bool
		want                      bool
	}{
		{"free no email", "free", nil, "channels_email", false, true, true, false},
		{"pro has email", "pro", nil, "channels_email", false, true, true, true},
		{"override enables for free", "free", map[string]any{"channels_email": true}, "channels_email", false, true, true, true},
		{"override disables for pro", "pro", map[string]any{"channels_email": false}, "channels_email", false, true, true, false},
		{"enterprise default", "enterprise", nil, "channels_email", false, true, true, true},
		{"unknown tier falls back to free", "unknown", nil, "channels_email", false, true, true, false},
		{"wrong-type override ignored", "free", map[string]any{"channels_email": float64(1)}, "channels_email", false, true, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Resolver{Tier: tt.tier, Overrides: tt.overrides}
			got := r.BoolFlag(tt.flagName, tt.free, tt.pro, tt.enterprise)
			if got != tt.want {
				t.Errorf("BoolFlag() = %v, want %v", got, tt.want)
			}
		})
	}
}
