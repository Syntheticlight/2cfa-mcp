package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHealthCheckZeroLeakage(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := ServerConfig{
		Port:          8080,
		AuthToken:     "secret-token-xyz-999",
		WorkspacePath: tmpDir,
		ExecTimeout:   120 * time.Second,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	srv.httpSrv.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp HealthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse json response: %v", err)
	}

	if resp.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", resp.Status)
	}

	// Verify zero-leak policy: Body must not contain secret tokens or workspace paths
	bodyStr := rec.Body.String()
	if strings.Contains(bodyStr, "secret-token-xyz-999") {
		t.Errorf("SECURITY LEAK DETECTED: health response leaks AuthToken")
	}
	if strings.Contains(bodyStr, tmpDir) {
		t.Errorf("SECURITY LEAK DETECTED: health response leaks WorkspacePath")
	}
}

func TestGateDashboardAccess(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := ServerConfig{
		Port:          8080,
		AuthToken:     "gate-token-12345",
		WorkspacePath: tmpDir,
		ExecTimeout:   120 * time.Second,
		Enable2FAGate: true,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// 1. Unauthorized /gate access (missing token)
	req := httptest.NewRequest(http.MethodGet, "/gate", nil)
	rec := httptest.NewRecorder()
	srv.httpSrv.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for /gate without token, got %d", rec.Code)
	}

	// 2. Authorized /gate access
	req = httptest.NewRequest(http.MethodGet, "/gate?token=gate-token-12345", nil)
	rec = httptest.NewRecorder()
	srv.httpSrv.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for /gate with token, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "2cfa-mcp 2FA Gate") {
		t.Errorf("expected dashboard HTML response")
	}
}
