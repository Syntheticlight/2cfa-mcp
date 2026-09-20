package security

import (
	"path/filepath"
	"testing"
)

func TestSafePath(t *testing.T) {
	tmpDir := t.TempDir()
	cleanTmpDir, err := filepath.Abs(tmpDir)
	if err != nil {
		t.Fatalf("failed to get abs temp dir: %v", err)
	}

	tests := []struct {
		name        string
		target      string
		shouldError bool
	}{
		{
			name:        "valid relative path",
			target:      "foo/bar.txt",
			shouldError: false,
		},
		{
			name:        "valid current dir",
			target:      ".",
			shouldError: false,
		},
		{
			name:        "path traversal attack with ..",
			target:      "../secret.txt",
			shouldError: true,
		},
		{
			name:        "nested path traversal attack",
			target:      "subfolder/../../etc/passwd",
			shouldError: true,
		},
		{
			name:        "absolute path outside workspace",
			target:      "/etc/passwd",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SafePath(cleanTmpDir, tt.target)
			if tt.shouldError {
				if err == nil {
					t.Errorf("expected error for target %q, got path %q", tt.target, got)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for target %q: %v", tt.target, err)
				}
			}
		})
	}
}
