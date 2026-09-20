package auth

import (
	"crypto/subtle"
	"net"
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
		setCanonicalClientHeaders(r)

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

		// Allow CORS preflight OPTIONS requests without requiring authentication
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.WriteHeader(http.StatusOK)
			return
		}

		// Public endpoints or gate handler bypass authentication
		if r.URL.Path == "/health" || r.URL.Path == "/healthz" || r.URL.Path == "/gate" || strings.HasPrefix(r.URL.Path, "/gate/") {
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

const (
	CanonicalClientIPHeader      = "X-2CFA-Client-IP"
	CanonicalClientCountryHeader = "X-2CFA-Client-Country"
)

func remoteHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(remoteAddr)
}

func validForwardedIP(value string) string {
	value = strings.TrimSpace(value)
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return ""
}

func firstForwardedIP(value string) string {
	for _, part := range strings.Split(value, ",") {
		if ip := validForwardedIP(part); ip != "" {
			return ip
		}
	}
	return ""
}

func trustedProxyPeer(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

// setCanonicalClientHeaders converts proxy-controlled identity headers into
// server-owned canonical headers. Forwarded headers are trusted only when the
// immediate peer is loopback/private (the normal Cloudflare Tunnel, FRP, Nginx
// or local reverse-proxy deployment). Direct public clients cannot spoof the
// IP used for audit logs and per-client TOTP rate limiting.
func setCanonicalClientHeaders(r *http.Request) {
	peer := remoteHost(r.RemoteAddr)
	clientIP := peer
	country := "DIRECT"

	if trustedProxyPeer(peer) {
		country = strings.TrimSpace(r.Header.Get("CF-IPCountry"))
		if country == "" {
			country = "LOCAL"
		}

		switch {
		case validForwardedIP(r.Header.Get("CF-Connecting-IP")) != "":
			clientIP = validForwardedIP(r.Header.Get("CF-Connecting-IP"))
		case firstForwardedIP(r.Header.Get("X-Forwarded-For")) != "":
			clientIP = firstForwardedIP(r.Header.Get("X-Forwarded-For"))
		case validForwardedIP(r.Header.Get("X-Real-IP")) != "":
			clientIP = validForwardedIP(r.Header.Get("X-Real-IP"))
		}
	}

	if clientIP == "" {
		clientIP = "unknown"
	}
	r.Header.Set(CanonicalClientIPHeader, clientIP)
	r.Header.Set(CanonicalClientCountryHeader, country)
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
