package updater

import (
	"testing"
)

func TestVersionComparison(t *testing.T) {
	tests := []struct {
		current  string
		latest   string
		expected bool
	}{
		{"v1.0.0", "v1.0.1", true},
		{"v1.0.1", "v1.0.2", true},
		{"v1.0.2", "v1.0.2", false},
		{"v1.0.2", "v1.0.1", false},
		{"1.0.3", "v1.0.4", true},
		{"v1.0.2", "v1.1.0", true},
		{"v1.0.2", "v2.0.0", true},
		{"v2.0.0", "v1.9.9", false},
	}

	for _, tt := range tests {
		got := IsNewerVersion(tt.current, tt.latest)
		if got != tt.expected {
			t.Errorf("IsNewerVersion(%q, %q) = %v; want %v", tt.current, tt.latest, got, tt.expected)
		}
	}
}
