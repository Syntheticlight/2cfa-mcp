package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// Middleware holds authentication settings.
type Middleware struct {
	token string
}

// NewMiddleware creates an Auth middleware instance.
func NewMiddleware(token string) *Middleware {
	return &Middleware{
		token: token,
	}
}

// Authenticate verifies the incoming request for a valid token.
// Supports:
// 1. Authorization: Bearer <TOKEN>
// 2. Query param: ?token=<TOKEN>
// 3. URL path prefix/segment matching /mcp/<TOKEN>/...
func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Public endpoints or gate handler bypass authentication
		if r.URL.Path == "/health" || r.URL.Path == "/healthz" || strings.HasPrefix(r.URL.Path, "/gate") {
			next.ServeHTTP(w, r)
			return
		}

		if m.token == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"server authentication token not configured"}`))
			return
		}

		clientToken := extractToken(r, m.token)
		if !constantTimeCompare(clientToken, m.token) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// extractToken extracts token from Header, Query, or Path.
func extractToken(r *http.Request, expectedToken string) string {
	// 1. Check Authorization Header: Bearer <TOKEN>
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "bearer ") {
		return strings.TrimSpace(authHeader[7:])
	}

	// 2. Check Query parameter ?token=<TOKEN>
	if qToken := r.URL.Query().Get("token"); qToken != "" {
		return qToken
	}

	// 3. Check URL path prefix: e.g., /mcp/<TOKEN>/sse or /mcp/<TOKEN>/messages
	path := r.URL.Path
	if strings.HasPrefix(path, "/mcp/") {
		parts := strings.Split(strings.TrimPrefix(path, "/mcp/"), "/")
		if len(parts) > 0 && parts[0] != "" {
			return parts[0]
		}
	}

	return ""
}

// constantTimeCompare performs constant-time comparison of two token strings.
func constantTimeCompare(a, b string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// SanitizeURL removes token values from URL paths for safe logging.
func SanitizeURL(path string, token string) string {
	if token != "" && strings.Contains(path, token) {
		return strings.ReplaceAll(path, token, "[REDACTED]")
	}
	return path
}
