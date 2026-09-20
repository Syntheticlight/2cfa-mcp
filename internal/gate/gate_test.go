package gate

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	code, _ = GenerateCurrentTOTP(secret, time.Now().Add(30*time.Second))
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

func TestGateHandlerCaseInsensitiveBearer(t *testing.T) {
	mgr := NewManager(Config{Enabled: false})
	h := NewHandler(mgr, "test-secret-token")

	req, _ := http.NewRequest(http.MethodGet, "/gate/api/status", nil)
	req.Header.Set("Authorization", "bearer test-secret-token")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with lowercase bearer token, got %d", rec.Code)
	}
}

func TestAutoGenerateSecretAndPersistEnv(t *testing.T) {
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env")

	mgr := NewManager(Config{
		Enabled: false,
		EnvPath: envFile,
	})

	// 1. Configure2FA with empty secret -> Should auto generate Base32 secret!
	secret, err := mgr.Configure2FA("", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secret) != 32 {
		t.Errorf("expected 32-character Base32 secret, got: %s (len: %d)", secret, len(secret))
	}
	if err := ValidateSecretFormat(secret); err != nil {
		t.Errorf("generated secret is not valid Base32: %v", err)
	}

	// 2. Check that .env file was created and contains the secret and ENABLE_2FA_GATE=true
	data, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("failed to read persisted .env: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "ENABLE_2FA_GATE=true") {
		t.Errorf("expected .env to contain ENABLE_2FA_GATE=true, got: %s", content)
	}
	if !strings.Contains(content, "TOTP_SECRET="+secret) {
		t.Errorf("expected .env to contain TOTP_SECRET=%s, got: %s", secret, content)
	}

	// 3. Disable 2FA -> should update .env
	_, err = mgr.Configure2FA("", false)
	if err != nil {
		t.Fatalf("unexpected error disabling 2FA: %v", err)
	}
	data, _ = os.ReadFile(envFile)
	if !strings.Contains(string(data), "ENABLE_2FA_GATE=false") {
		t.Errorf("expected .env to contain ENABLE_2FA_GATE=false, got: %s", string(data))
	}
}

func TestPendingSecretReuseAndReset(t *testing.T) {
	mgr := NewManager(Config{Enabled: false})

	// 1. Initial begin setup -> generates Secret A
	secA, err := mgr.BeginSetup2FA("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 2. Immediate re-call without code -> should return identical Secret A
	secB, err := mgr.BeginSetup2FA("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secA != secB {
		t.Errorf("expected secret to be preserved during pending setup, got %s vs %s", secA, secB)
	}

	// 3. Re-call with reset -> should generate a new Secret C
	secC, err := mgr.BeginSetup2FA("reset")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secC == secA {
		t.Errorf("expected new secret after reset, got same secret")
	}
}

func TestPersistEnvPreservesAuthToken(t *testing.T) {
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env")

	_ = os.Setenv("AUTH_TOKEN", "test-token-preserved-1234")
	defer os.Unsetenv("AUTH_TOKEN")

	err := PersistEnv(envFile, map[string]string{
		"ENABLE_2FA_GATE": "true",
		"TOTP_SECRET":     "JBSWY3DPEHPK3PXP",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("failed to read persisted .env: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "AUTH_TOKEN=test-token-preserved-1234") {
		t.Errorf("expected .env to preserve AUTH_TOKEN, got: %s", content)
	}
}


func TestTOTPReplayProtection(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	mgr := NewManager(Config{Enabled: true, TOTPSecret: secret})

	code, err := GenerateCurrentTOTP(secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate TOTP: %v", err)
	}

	if _, err := mgr.CreateLease(code, 0, "198.51.100.10", "TEST"); err != nil {
		t.Fatalf("first use of TOTP should succeed: %v", err)
	}
	if _, err := mgr.CreateLease(code, 0, "198.51.100.10", "TEST"); err == nil || !strings.Contains(err.Error(), "already been used") {
		t.Fatalf("expected replayed TOTP to be rejected, got: %v", err)
	}
}

func TestTOTPRateLimit(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	mgr := NewManager(Config{Enabled: true, TOTPSecret: secret})
	client := "203.0.113.20"

	for i := 0; i < totpClientFailureLimit; i++ {
		_, _ = mgr.CreateLease("000000", 0, client, "TEST")
	}

	validCode, err := GenerateCurrentTOTP(secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate TOTP: %v", err)
	}
	if _, err := mgr.CreateLease(validCode, 0, client, "TEST"); err == nil || !strings.Contains(err.Error(), "too many failed") {
		t.Fatalf("expected rate limit after repeated failures, got: %v", err)
	}
}

func TestConfigure2FAPersistFailureDoesNotChangeRuntimeState(t *testing.T) {
	tmpDir := t.TempDir()
	missingDirEnv := filepath.Join(tmpDir, "missing", ".env")
	secret := "JBSWY3DPEHPK3PXP"

	mgr := NewManager(Config{
		Enabled: false,
		EnvPath: missingDirEnv,
	})

	if _, err := mgr.Configure2FA(secret, true); err == nil {
		t.Fatal("expected persistence failure")
	}
	if mgr.IsEnabled() {
		t.Fatal("2FA runtime state must remain disabled when persistence fails")
	}
	if mgr.GetSecret() != "" {
		t.Fatal("TOTP secret must not be committed to runtime state when persistence fails")
	}
}


func TestLeaseRetentionIsCapped(t *testing.T) {
	mgr := NewManager(Config{Enabled: true, TOTPSecret: "JBSWY3DPEHPK3PXP"})
	now := time.Now()

	mgr.mu.Lock()
	for i := 0; i < maxActiveLeases; i++ {
		token := fmt.Sprintf("lease_%03d", i)
		mgr.leases[token] = &Lease{Token: token, CreatedAt: now.Add(time.Duration(i) * time.Second)}
	}
	mgr.enforceLeaseLimitLocked()
	if len(mgr.leases) != maxActiveLeases-1 {
		mgr.mu.Unlock()
		t.Fatalf("expected one oldest lease to be evicted before insertion, got %d", len(mgr.leases))
	}
	if _, exists := mgr.leases["lease_000"]; exists {
		mgr.mu.Unlock()
		t.Fatal("expected oldest lease to be evicted")
	}
	mgr.mu.Unlock()
}
