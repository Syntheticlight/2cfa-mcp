package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadDotEnvPreservesExplicitEnvironment(t *testing.T) {
	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(envPath, []byte("AUTH_TOKEN=from-file\nPORT=4321\n"), 0644); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	oldToken, hadToken := os.LookupEnv("AUTH_TOKEN")
	oldPort, hadPort := os.LookupEnv("PORT")
	defer func() {
		if hadToken {
			_ = os.Setenv("AUTH_TOKEN", oldToken)
		} else {
			_ = os.Unsetenv("AUTH_TOKEN")
		}
		if hadPort {
			_ = os.Setenv("PORT", oldPort)
		} else {
			_ = os.Unsetenv("PORT")
		}
	}()

	_ = os.Setenv("AUTH_TOKEN", "from-process")
	_ = os.Unsetenv("PORT")

	gotPath := loadDotEnv(envPath)
	if gotPath == "" {
		t.Fatal("expected env path")
	}
	if got := os.Getenv("AUTH_TOKEN"); got != "from-process" {
		t.Fatalf("explicit process environment must win, got %q", got)
	}
	if got := os.Getenv("PORT"); got != "4321" {
		t.Fatalf("expected unset PORT to load from .env, got %q", got)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(envPath)
		if err != nil {
			t.Fatalf("stat .env: %v", err)
		}
		if got := info.Mode().Perm(); got != 0600 {
			t.Fatalf("expected .env permissions 0600, got %o", got)
		}
	}
}
