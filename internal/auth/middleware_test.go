package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthenticate(t *testing.T) {
	secretToken := "super-secret-high-entropy-token-12345"
	mw := NewMiddleware(secretToken)

	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success"}`))
	}))

	tests := []struct {
		name           string
		path           string
		headerKey      string
		headerVal      string
		expectedStatus int
	}{
		{
			name:           "health check unauthenticated",
			path:           "/health",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "no token provided",
			path:           "/sse",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "invalid bearer token",
			path:           "/sse",
			headerKey:      "Authorization",
			headerVal:      "Bearer wrong-token",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "valid bearer token",
			path:           "/sse",
			headerKey:      "Authorization",
			headerVal:      "Bearer " + secretToken,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "valid lowercase bearer token",
			path:           "/sse",
			headerKey:      "Authorization",
			headerVal:      "bearer " + secretToken,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "valid query token",
			path:           "/sse?token=" + secretToken,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "valid path token",
			path:           "/mcp/" + secretToken + "/sse",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if tt.headerKey != "" {
				req.Header.Set(tt.headerKey, tt.headerVal)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rec.Code)
			}
		})
	}
}

func TestSanitizeURL(t *testing.T) {
	token := "secret123"
	url := "/mcp/secret123/sse?token=secret123"
	sanitized := SanitizeURL(url, token)

	if sanitized == url {
		t.Errorf("failed to sanitize token from URL")
	}
	if sanitized != "/mcp/[REDACTED]/sse?token=[REDACTED]" {
		t.Errorf("unexpected sanitized output: %s", sanitized)
	}
}

func TestCORSPreflightOptions(t *testing.T) {
	mw := NewMiddleware("test-token")
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/mcp/random/message", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK for OPTIONS preflight, got %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("missing Access-Control-Allow-Origin header")
	}
}
func TestProxyBufferingDisabledHeaders(t *testing.T) {
	mw := NewMiddleware("test-token")
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("X-Accel-Buffering") != "no" {
		t.Errorf("expected X-Accel-Buffering: no, got '%s'", rec.Header().Get("X-Accel-Buffering"))
	}
	if rec.Header().Get("Cache-Control") != "no-cache, no-transform" {
		t.Errorf("expected Cache-Control: no-cache, no-transform, got '%s'", rec.Header().Get("Cache-Control"))
	}
}
