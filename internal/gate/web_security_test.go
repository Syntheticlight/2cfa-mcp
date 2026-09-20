package gate

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDashboardSecurityHeadersAndEscaping(t *testing.T) {
	mgr := NewManager(Config{Enabled: false})
	h := NewHandler(mgr, "dashboard-token")

	req := httptest.NewRequest(http.MethodGet, "/gate?token=dashboard-token", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected dashboard 200, got %d", rec.Code)
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("expected Content-Security-Policy header")
	}
	if rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("expected no-referrer policy, got %q", rec.Header().Get("Referrer-Policy"))
	}

	body := rec.Body.String()
	if !strings.Contains(body, "function escapeHTML") ||
		!strings.Contains(body, "escapeHTML(a.message || '-')") ||
		!strings.Contains(body, "escapeHTML(a.client_ip)") {
		t.Fatal("dashboard must HTML-escape audit-controlled fields")
	}
}
