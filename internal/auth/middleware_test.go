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
		{
			name:           "gate lookalike path must not bypass auth",
			path:           "/gateevil",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "gate prefix lookalike must not bypass auth",
			path:           "/gate123/api/status",
			expectedStatus: http.StatusUnauthorized,
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


func TestCanonicalClientIdentityRejectsSpoofedProxyHeadersFromPublicPeer(t *testing.T) {
	mw := NewMiddleware("test-token")
	var gotIP, gotCountry string
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIP = r.Header.Get(CanonicalClientIPHeader)
		gotCountry = r.Header.Get(CanonicalClientCountryHeader)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/sse", nil)
	req.RemoteAddr = "203.0.113.55:4567"
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("CF-Connecting-IP", "1.2.3.4")
	req.Header.Set("X-Forwarded-For", "5.6.7.8")
	req.Header.Set("CF-IPCountry", "ZZ")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected request to be authenticated, got %d", rec.Code)
	}
	if gotIP != "203.0.113.55" {
		t.Fatalf("expected public peer IP to win over spoofed proxy headers, got %q", gotIP)
	}
	if gotCountry != "DIRECT" {
		t.Fatalf("expected direct peer country marker, got %q", gotCountry)
	}
}

func TestCanonicalClientIdentityTrustsLocalReverseProxy(t *testing.T) {
	mw := NewMiddleware("test-token")
	var gotIP, gotCountry string
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIP = r.Header.Get(CanonicalClientIPHeader)
		gotCountry = r.Header.Get(CanonicalClientCountryHeader)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/sse", nil)
	req.RemoteAddr = "127.0.0.1:4567"
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("CF-Connecting-IP", "198.51.100.20")
	req.Header.Set("CF-IPCountry", "US")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected request to be authenticated, got %d", rec.Code)
	}
	if gotIP != "198.51.100.20" {
		t.Fatalf("expected trusted local proxy client IP, got %q", gotIP)
	}
	if gotCountry != "US" {
		t.Fatalf("expected trusted proxy country, got %q", gotCountry)
	}
}
