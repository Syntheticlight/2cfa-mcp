package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

const MaxRequestBodyBytes int64 = 16 * 1024 * 1024

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
		// Set CORS headers for all requests (essential for browser-based clients like ChatGPT Web)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE, HEAD")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Expose-Headers", "*")

		// Automatically disable proxy buffering in Nginx, Caddy, Cloudflare, Traefik, etc.
		// Nginx natively honors "X-Accel-Buffering: no" to disable proxy_buffering automatically
		// without requiring the user to manually configure "proxy_buffering off" in nginx.conf.
		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Set("Cache-Control", "no-cache, no-transform")

		// Bound request bodies before any transport handler reads them. This prevents
		// Streamable HTTP / SSE message requests from allocating unbounded memory.
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
		}

		// Allow CORS preflight OPTIONS requests without requiring authentication
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.WriteHeader(http.StatusOK)
			return
		}

		// Public health endpoints and the exact /gate subtree use their own policy.
		// Do not use a broad "/gate" prefix here: paths such as /gateevil would
		// otherwise bypass this middleware and fall through to the MCP handler.
		if r.URL.Path == "/health" || r.URL.Path == "/healthz" ||
			r.URL.Path == "/gate" || strings.HasPrefix(r.URL.Path, "/gate/") {
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
