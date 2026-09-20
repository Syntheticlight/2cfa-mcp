package gate

import (
	"crypto/hmac"
	"crypto/sha1"
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

// ValidateTOTP validates a 6-digit TOTP code against a Base32 secret string.
// Allows a +/- 1 step drift window (total 90 seconds window).
func ValidateTOTP(secretBase32, inputCode string, t time.Time) (bool, error) {
	cleanSecret := strings.ToUpper(strings.ReplaceAll(secretBase32, " ", ""))
	if cleanSecret == "" {
		return false, errors.New("TOTP secret is empty")
	}

	key, err := decodeBase32(cleanSecret)
	if err != nil {
		return false, fmt.Errorf("invalid base32 secret: %w", err)
	}

	currentStep := t.Unix() / TOTPPeriod

	// Check current step, previous step (-1), and next step (+1) for clock drift
	for stepOffset := int64(-1); stepOffset <= 1; stepOffset++ {
		expectedCode := generateHOTP(key, uint64(currentStep+stepOffset), TOTPDigits)
		if expectedCode == strings.TrimSpace(inputCode) {
			return true, nil
		}
	}

	return false, nil
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
	// Add padding if missing
	padLen := (8 - (len(s) % 8)) % 8
	padded := s + strings.Repeat("=", padLen)
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
