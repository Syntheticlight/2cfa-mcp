package gate

import (
	"net/http"
	"testing"
	"time"
)

func TestGateDefaultAndLeaseLifecycle(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"

	// 1. Default state: Enabled = false (Token-only direct connection)
	mgr := NewManager(Config{
		Enabled:    false,
		TOTPSecret: secret,
	})

	allowed, msg := mgr.ValidateLease("")
	if !allowed {
		t.Errorf("expected default disabled 2FA to allow access directly, got: %s", msg)
	}

	// 2. Enable 2FA dynamically via Configure2FA
	mgr.Configure2FA(secret, true)

	allowed, _ = mgr.ValidateLease("")
	if allowed {
		t.Errorf("expected access to be denied once 2FA is enabled without lease")
	}

	// 3. Unlock with permanent lease (durationMinutes = 0)
	code, err := GenerateCurrentTOTP(secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate TOTP: %v", err)
	}

	token, err := mgr.CreateLease(code, 0, "127.0.0.1", "LOCAL")
	if err != nil {
		t.Fatalf("failed to create permanent lease: %v", err)
	}

	allowed, _ = mgr.ValidateLease(token)
	if !allowed {
		t.Errorf("expected permanent lease token to be valid")
	}

	// 4. Manual lock invalidates all leases
	mgr.Lock()
	allowed, _ = mgr.ValidateLease(token)
	if allowed {
		t.Errorf("expected lease to be invalidated after Lock()")
	}

	// 5. Test timed lease expiration
	code, _ = GenerateCurrentTOTP(secret, time.Now())
	timedToken, err := mgr.CreateLease(code, 1, "127.0.0.1", "LOCAL") // 1 minute
	if err != nil {
		t.Fatalf("failed to create timed lease: %v", err)
	}

	allowed, _ = mgr.ValidateLease(timedToken)
	if !allowed {
		t.Errorf("expected timed lease to be valid immediately")
	}
}

func TestAuditRingBuffer(t *testing.T) {
	mgr := NewManager(Config{Enabled: false})

	for i := 0; i < 25; i++ {
		mgr.AddAudit(AuditEntry{
			ToolName: "test_tool",
			ClientIP: "1.2.3.4",
			Country:  "US",
			Status:   "SUCCESS",
		})
	}

	audits := mgr.GetAudits()
	if len(audits) != 20 {
		t.Errorf("expected 20 audits in ring buffer, got %d", len(audits))
	}
}

func TestResolveClientIP(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/mcp", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	// Fallback RemoteAddr
	ip, country := ResolveClientIP(req)
	if ip != "192.168.1.100" || country != "LOCAL" {
		t.Errorf("unexpected IP/country: %s/%s", ip, country)
	}

	// Cloudflare headers
	req.Header.Set("CF-Connecting-IP", "203.0.113.195")
	req.Header.Set("CF-IPCountry", "SG")

	ip, country = ResolveClientIP(req)
	if ip != "203.0.113.195" || country != "SG" {
		t.Errorf("unexpected CF IP/country: %s/%s", ip, country)
	}
}
