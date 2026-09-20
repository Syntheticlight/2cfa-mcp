package tools

import (
	"net/http"
	"strings"
)

// resolveHeaderIP parses client IP and country from MCP CallToolRequest HTTP headers.
func resolveHeaderIP(header http.Header) (string, string) {
	if header == nil {
		return "127.0.0.1", "LOCAL"
	}

	country := header.Get("CF-IPCountry")
	if country == "" {
		country = "LOCAL"
	}

	if cfIP := strings.TrimSpace(header.Get("CF-Connecting-IP")); cfIP != "" {
		return cfIP, country
	}

	if xff := header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip, country
			}
		}
	}

	if xri := strings.TrimSpace(header.Get("X-Real-IP")); xri != "" {
		return xri, country
	}

	return "127.0.0.1", country
}
