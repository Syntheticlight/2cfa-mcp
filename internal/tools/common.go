package tools

import (
	"net"
	"net/http"
	"strings"
)

// resolveHeaderIP parses client IP and country from MCP CallToolRequest HTTP headers.
func resolveHeaderIP(header http.Header) (string, string) {
	if header == nil {
		return "127.0.0.1", "LOCAL"
	}

	country := sanitizeHeaderCountry(header.Get("X-2CFA-Client-Country"), "LOCAL")
	if ip := net.ParseIP(strings.TrimSpace(header.Get("X-2CFA-Client-IP"))); ip != nil {
		return ip.String(), country
	}

	// Fallback for direct unit/in-process use where requests did not pass through
	// the HTTP server wrapper. Values are still syntax-validated.
	for _, candidate := range []string{
		header.Get("CF-Connecting-IP"),
		firstHeaderForwardedIP(header.Get("X-Forwarded-For")),
		header.Get("X-Real-IP"),
	} {
		if ip := net.ParseIP(strings.TrimSpace(candidate)); ip != nil {
			return ip.String(), sanitizeHeaderCountry(header.Get("CF-IPCountry"), "LOCAL")
		}
	}

	return "127.0.0.1", country
}

func firstHeaderForwardedIP(value string) string {
	if value == "" {
		return ""
	}
	parts := strings.Split(value, ",")
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}

func sanitizeHeaderCountry(value, fallback string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if len(value) != 2 {
		return fallback
	}
	for _, ch := range value {
		if ch < 'A' || ch > 'Z' {
			return fallback
		}
	}
	return value
}
