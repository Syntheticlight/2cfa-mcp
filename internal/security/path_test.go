package security

import (
	"os"
	"path/filepath"
	"runtime"
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

func TestWorkspaceHandleRejectsLinkReplacedAfterValidation(t *testing.T) {
	workspace, outside := t.TempDir(), t.TempDir()
	target := filepath.Join(workspace, "target")
	if err := os.WriteFile(target, []byte("inside"), 0600); err != nil {
		t.Fatal(err)
	}
	root, relative, err := OpenWorkspacePath(workspace, "target")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "created.txt"), target); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink privilege unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if err := root.WriteFile(relative, []byte("escaped"), 0600); err == nil {
		t.Fatal("write followed a link replaced after validation")
	}
	if _, err := os.Stat(filepath.Join(outside, "created.txt")); !os.IsNotExist(err) {
		t.Fatalf("outside file unexpectedly exists: %v", err)
	}
}

func TestWorkspaceHandleAllowsRelativeLinksInsideRoot(t *testing.T) {
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "target"), []byte("inside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(workspace, "link")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink privilege unavailable: %v", err)
		}
		t.Fatal(err)
	}
	root, relative, err := OpenWorkspacePath(workspace, "link")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	data, err := root.ReadFile(relative)
	if err != nil || string(data) != "inside" {
		t.Fatalf("internal link failed: %q, %v", data, err)
	}
}
