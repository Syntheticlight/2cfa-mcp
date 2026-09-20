package gate

import (
	"testing"
	"time"
)

func TestTOTPValidation(t *testing.T) {
	// Standard test secret (RFC 6238 / Google Authenticator test vector)
	secret := "JBSWY3DPEHPK3PXP" // ASCII "Hello!\xde\xad\xbe\xef" in Base32

	now := time.Now()
	key, err := decodeBase32(secret)
	if err != nil {
		t.Fatalf("failed to decode secret: %v", err)
	}

	currentStep := now.Unix() / TOTPPeriod
	validCode := generateHOTP(key, uint64(currentStep), TOTPDigits)

	// Test 1: Valid current code
	valid, err := ValidateTOTP(secret, validCode, now)
	if err != nil || !valid {
		t.Errorf("expected valid code %q to pass, got valid=%v, err=%v", validCode, valid, err)
	}

	// Test 2: Drift code (-30s)
	pastCode := generateHOTP(key, uint64(currentStep-1), TOTPDigits)
	valid, err = ValidateTOTP(secret, pastCode, now)
	if err != nil || !valid {
		t.Errorf("expected past drift code %q to pass, got valid=%v, err=%v", pastCode, valid, err)
	}

	// Test 3: Invalid code
	valid, err = ValidateTOTP(secret, "000000", now)
	if err != nil {
		t.Errorf("unexpected error for invalid code: %v", err)
	}
	if valid {
		t.Errorf("expected '000000' to fail, but it passed")
	}

	// Test 4: Too old code (-60s, beyond 1 step)
	oldCode := generateHOTP(key, uint64(currentStep-2), TOTPDigits)
	valid, err = ValidateTOTP(secret, oldCode, now)
	if valid {
		t.Errorf("expected old code %q beyond window to fail, but it passed", oldCode)
	}
}
