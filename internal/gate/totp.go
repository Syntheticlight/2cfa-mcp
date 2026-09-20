package gate

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	TOTPPeriod = 30 // 30 seconds interval per RFC 6238
	TOTPDigits = 6  // 6 digits
)

// GenerateRandomSecret generates a 20-byte (160-bit) cryptographically secure Base32 TOTP secret.
func GenerateRandomSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// ValidateSecretFormat checks whether a string is a valid Base32 secret.
func ValidateSecretFormat(secret string) error {
	cleanSecret := strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	if cleanSecret == "" {
		return errors.New("TOTP secret is empty")
	}
	_, err := decodeBase32(cleanSecret)
	if err != nil {
		return fmt.Errorf("invalid base32 secret: %w", err)
	}
	return nil
}

// ValidateTOTP validates a 6-digit TOTP code against a Base32 secret string.
// Allows a +/- 1 step drift window (total 90 seconds window).
func ValidateTOTP(secretBase32, inputCode string, t time.Time) (bool, error) {
	valid, _, err := ValidateTOTPWithStep(secretBase32, inputCode, t)
	return valid, err
}

// ValidateTOTPWithStep performs the same validation as ValidateTOTP and also
// returns the matched RFC 6238 time-step. The step is used by the gate manager
// to prevent replaying the same TOTP to mint multiple leases.
func ValidateTOTPWithStep(secretBase32, inputCode string, t time.Time) (bool, int64, error) {
	cleanSecret := strings.ToUpper(strings.ReplaceAll(secretBase32, " ", ""))
	if cleanSecret == "" {
		return false, 0, errors.New("TOTP secret is empty")
	}

	key, err := decodeBase32(cleanSecret)
	if err != nil {
		return false, 0, fmt.Errorf("invalid base32 secret: %w", err)
	}

	cleanInput := strings.TrimSpace(inputCode)
	if len(cleanInput) != TOTPDigits {
		return false, 0, nil
	}
	for _, ch := range cleanInput {
		if ch < '0' || ch > '9' {
			return false, 0, nil
		}
	}

	currentStep := t.Unix() / TOTPPeriod

	// Check current step, previous step (-1), and next step (+1) for clock drift.
	for stepOffset := int64(-1); stepOffset <= 1; stepOffset++ {
		step := currentStep + stepOffset
		if step < 0 {
			continue
		}
		expectedCode := generateHOTP(key, uint64(step), TOTPDigits)
		if subtle.ConstantTimeCompare([]byte(expectedCode), []byte(cleanInput)) == 1 {
			return true, step, nil
		}
	}

	return false, 0, nil
}

// GenerateCurrentTOTP generates the current 6-digit TOTP code for the given Base32 secret.
func GenerateCurrentTOTP(secretBase32 string, t time.Time) (string, error) {
	cleanSecret := strings.ToUpper(strings.ReplaceAll(secretBase32, " ", ""))
	if cleanSecret == "" {
		return "", errors.New("TOTP secret is empty")
	}

	key, err := decodeBase32(cleanSecret)
	if err != nil {
		return "", fmt.Errorf("invalid base32 secret: %w", err)
	}

	currentStep := t.Unix() / TOTPPeriod
	return generateHOTP(key, uint64(currentStep), TOTPDigits), nil
}

func decodeBase32(s string) ([]byte, error) {
	unpadded := strings.TrimRight(s, "=")
	padLen := (8 - (len(unpadded) % 8)) % 8
	padded := unpadded + strings.Repeat("=", padLen)
	return base32.StdEncoding.DecodeString(padded)
}

func generateHOTP(key []byte, counter uint64, digits int) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	binaryCode := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}

	otp := binaryCode % mod
	return fmt.Sprintf("%0*d", digits, otp)
}
