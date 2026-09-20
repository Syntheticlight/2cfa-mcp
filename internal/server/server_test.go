package server

import (
	"context"
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
		Port:          2232,
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
		Port:          2232,
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

func TestSSERoutingWithPathToken(t *testing.T) {
	tmpDir := t.TempDir()
	token := "valid-test-token-777"
	cfg := ServerConfig{
		Port:          2232,
		AuthToken:     token,
		WorkspacePath: tmpDir,
		ExecTimeout:   120 * time.Second,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Connect to /mcp/<TOKEN>/sse with path token
	req := httptest.NewRequest(http.MethodGet, "/mcp/"+token+"/sse", nil)
	ctx, cancel := context.WithTimeout(req.Context(), 100*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	srv.httpSrv.Handler.ServeHTTP(rec, req)

	// SSE response headers should be text/event-stream
	if rec.Header().Get("Content-Type") != "text/event-stream" {
		t.Errorf("expected text/event-stream, got %s", rec.Header().Get("Content-Type"))
	}

	body := rec.Body.String()
	// Should contain event: endpoint with dynamic base path /mcp/<TOKEN>/message
	if !strings.Contains(body, "/mcp/"+token) {
		t.Errorf("expected SSE endpoint event to contain dynamic base path /mcp/%s, got %s", token, body)
	}
}

func TestCloudflareTunnelReverseProxyHostProtectionDisabled(t *testing.T) {
	tmpDir := t.TempDir()
	token := "tunnel-test-token"
	cfg := ServerConfig{
		Port:          2232,
		AuthToken:     token,
		WorkspacePath: tmpDir,
		ExecTimeout:   120 * time.Second,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Simulate Cloudflare Tunnel request connecting from localhost with external domain Host header
	req := httptest.NewRequest(http.MethodGet, "/mcp/"+token+"/sse", nil)
	req.RemoteAddr = "127.0.0.1:45678"
	req.Host = "mcp.example.com"
	ctx, cancel := context.WithTimeout(req.Context(), 100*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	srv.httpSrv.Handler.ServeHTTP(rec, req)

	// Must NOT be blocked with 403 Forbidden ("invalid Host header")
	if rec.Code == http.StatusForbidden {
		t.Fatalf("Cloudflare Tunnel request was rejected with 403 Forbidden due to Host header protection: %s", rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "text/event-stream" {
		t.Errorf("expected text/event-stream, got %s", rec.Header().Get("Content-Type"))
	}
}

func TestSSERoutingTrailingSlashAndDirectAccept(t *testing.T) {
	tmpDir := t.TempDir()
	token := "trailing-test-token"
	cfg := ServerConfig{
		Port:          2232,
		AuthToken:     token,
		WorkspacePath: tmpDir,
		ExecTimeout:   120 * time.Second,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// 1. Trailing slash on SSE: /mcp/<TOKEN>/sse/
	req := httptest.NewRequest(http.MethodGet, "/mcp/"+token+"/sse/", nil)
	ctx, cancel := context.WithTimeout(req.Context(), 100*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	srv.httpSrv.Handler.ServeHTTP(rec, req)

	if rec.Header().Get("Content-Type") != "text/event-stream" {
		t.Errorf("expected text/event-stream for trailing slash, got %s", rec.Header().Get("Content-Type"))
	}

	// 2. Direct path without /sse but with Accept: text/event-stream
	reqDirect := httptest.NewRequest(http.MethodGet, "/mcp/"+token, nil)
	reqDirect.Header.Set("Accept", "text/event-stream")
	ctx2, cancel2 := context.WithTimeout(reqDirect.Context(), 100*time.Millisecond)
	defer cancel2()
	reqDirect = reqDirect.WithContext(ctx2)

	recDirect := httptest.NewRecorder()
	srv.httpSrv.Handler.ServeHTTP(recDirect, reqDirect)

	if recDirect.Header().Get("Content-Type") != "text/event-stream" {
		t.Errorf("expected text/event-stream for direct accept header, got %s", recDirect.Header().Get("Content-Type"))
	}
}


func TestGateLikePathCannotBypassAuth(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := ServerConfig{
		Port:          2232,
		AuthToken:     "gate-bypass-test-token",
		WorkspacePath: tmpDir,
		ExecTimeout:   120 * time.Second,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/gateevil", nil)
	req.Header.Set("Accept", "text/event-stream")
	rec := httptest.NewRecorder()
	srv.httpSrv.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected auth rejection for /gateevil, got %d", rec.Code)
	}
}
