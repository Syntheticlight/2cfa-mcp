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

func TestValidateSecretFormatAndPadding(t *testing.T) {
	validPadded := "JBSWY3DPEHPK3PXP===="
	validUnpadded := "JBSWY3DPEHPK3PXP"
	invalidBase32 := "INVALID_SECRET_WITH_8_AND_9"

	if err := ValidateSecretFormat(validPadded); err != nil {
		t.Errorf("expected padded secret to be valid, got: %v", err)
	}
	if err := ValidateSecretFormat(validUnpadded); err != nil {
		t.Errorf("expected unpadded secret to be valid, got: %v", err)
	}
	if err := ValidateSecretFormat(invalidBase32); err == nil {
		t.Errorf("expected invalid secret to fail validation, but passed")
	}

	now := time.Now()
	code1, err1 := GenerateCurrentTOTP(validPadded, now)
	code2, err2 := GenerateCurrentTOTP(validUnpadded, now)
	if err1 != nil || err2 != nil {
		t.Fatalf("failed to generate code: %v, %v", err1, err2)
	}
	if code1 != code2 {
		t.Errorf("codes should match regardless of padding: %q vs %q", code1, code2)
	}
}
