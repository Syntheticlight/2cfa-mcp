package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDotEnvPreservesExistingEnvironment(t *testing.T) {
	tmp := t.TempDir()
	envFile := filepath.Join(tmp, ".env")
	if err := os.WriteFile(envFile, []byte("AUTH_TOKEN=from-file\nONLY_IN_FILE=loaded\n"), 0600); err != nil {
		t.Fatalf("write test env: %v", err)
	}

	t.Setenv("AUTH_TOKEN", "from-process")
	_ = os.Unsetenv("ONLY_IN_FILE")
	t.Cleanup(func() { _ = os.Unsetenv("ONLY_IN_FILE") })

	gotPath := loadDotEnv(envFile)
	if gotPath == "" {
		t.Fatal("expected resolved env path")
	}
	if got := os.Getenv("AUTH_TOKEN"); got != "from-process" {
		t.Fatalf("process environment must win over .env, got %q", got)
	}
	if got := os.Getenv("ONLY_IN_FILE"); got != "loaded" {
		t.Fatalf("missing environment variable should be loaded from .env, got %q", got)
	}
}

func TestLoadDotEnvTightensFilePermissions(t *testing.T) {
	tmp := t.TempDir()
	envFile := filepath.Join(tmp, ".env")
	if err := os.WriteFile(envFile, []byte("PERMISSION_TEST=value\n"), 0644); err != nil {
		t.Fatalf("write test env: %v", err)
	}
	_ = os.Unsetenv("PERMISSION_TEST")
	t.Cleanup(func() { _ = os.Unsetenv("PERMISSION_TEST") })

	loadDotEnv(envFile)

	info, err := os.Stat(envFile)
	if err != nil {
		t.Fatalf("stat env file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("expected .env permissions 0600 after load, got %04o", got)
	}
}
