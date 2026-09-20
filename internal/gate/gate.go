package gate

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// AuditEntry stores an individual execution audit record.
type AuditEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	ClientIP   string    `json:"client_ip"`
	Country    string    `json:"country"`
	ToolName   string    `json:"tool_name"`
	DurationMs int64     `json:"duration_ms"`
	Status     string    `json:"status"` // SUCCESS, ERROR, LOCKED
	Message    string    `json:"message"`
}

// Lease represents a dynamic permission token issued via 2FA verification.
type Lease struct {
	Token           string    `json:"token"`
	CreatedAt       time.Time `json:"created_at"`
	LastActivityAt  time.Time `json:"last_activity_at"`
	ExpiresAt       time.Time `json:"expires_at"` // Zero time means never expires
	DurationMinutes int       `json:"duration_minutes"`
	ClientIP        string    `json:"client_ip"`
	Country         string    `json:"country"`
}

// StateInfo represents the current dynamic state of the gate.
type StateInfo struct {
	Enabled           bool   `json:"enabled"`
	HasSecret         bool   `json:"has_secret"`
	ActiveLeasesCount int    `json:"active_leases_count"`
	Status            string `json:"status"` // "DISABLED", "LOCKED", "UNLOCKED"
	Unlocked          bool   `json:"unlocked"`
}

const (
	totpFailureWindow      = 5 * time.Minute
	totpClientFailureLimit = 5
	totpGlobalFailureLimit = 25
	totpUsedRetention      = 3 * time.Minute
)

type totpAttemptState struct {
	Failures     []time.Time
	BlockedUntil time.Time
}

// Manager manages the 2FA lifecycle, leases, and audit logs.
type Manager struct {
	mu            sync.RWMutex
	enabled       bool
	totpSecret    string
	pendingSecret string
	pendingAt     time.Time
	envPath       string
	leases        map[string]*Lease
	auditRing     []AuditEntry
	maxAudits     int

	totpAttempts  map[string]*totpAttemptState
	globalFailures []time.Time
	usedTOTPSteps map[string]time.Time
}

// Config holds Gate Manager initialization options.
type Config struct {
	Enabled    bool
	TOTPSecret string
	EnvPath    string
}

// NewManager creates a Gate Manager instance.
func NewManager(cfg Config) *Manager {
	envPath := cfg.EnvPath
	if envPath == "" {
		if _, err := os.Stat(".env"); err == nil {
			envPath = ".env"
		}
	}
	return &Manager{
		enabled:    cfg.Enabled,
		totpSecret: cfg.TOTPSecret,
		envPath:    envPath,
		leases:         make(map[string]*Lease),
		maxAudits:       20,
		auditRing:       make([]AuditEntry, 0, 20),
		totpAttempts:    make(map[string]*totpAttemptState),
		usedTOTPSteps:   make(map[string]time.Time),
		globalFailures:  make([]time.Time, 0, totpGlobalFailureLimit),
	}
}

// BeginSetup2FA initiates the 2FA setup process without locking the user out.
// Generates or validates a Base32 secret and puts it in pending state.
func (m *Manager) BeginSetup2FA(customSecret string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	secret := strings.TrimSpace(customSecret)
	isReset := strings.EqualFold(secret, "new") || strings.EqualFold(secret, "reset") || strings.EqualFold(secret, "regenerate")
	if isReset {
		secret = ""
	}

	if secret != "" {
		if err := ValidateSecretFormat(secret); err != nil {
			return "", err
		}
		secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	} else {
		// If a setup was already initiated recently (within 15 minutes) and not yet confirmed,
		// reuse the pending secret so that if the user/AI asks again or re-requests,
		// the secret does not silently change under their feet!
		if !isReset && m.pendingSecret != "" && time.Since(m.pendingAt) < 15*time.Minute {
			return m.pendingSecret, nil
		}

		sec, err := GenerateRandomSecret()
		if err != nil {
			return "", err
		}
		secret = sec
	}

	m.pendingSecret = secret
	m.pendingAt = time.Now()
	return secret, nil
}

// ConfirmSetup2FA verifies the 6-digit TOTP code against the pending secret.
// If valid: activates 2FA, persists to .env, and issues an immediate lease token for the current session.
func (m *Manager) ConfirmSetup2FA(code, clientIP, country string) (string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.pendingSecret == "" {
		return "", "", errors.New("no pending 2FA setup in progress. Please call setup_2fa without code first to generate a secret")
	}

	valid, err := m.validateAndConsumeTOTPLocked(m.pendingSecret, code, clientIP)
	if err != nil {
		return "", "", fmt.Errorf("verification error: %w", err)
	}
	if !valid {
		return "", "", errors.New("invalid verification code. Please make sure the key was added correctly to your authenticator app and try again")
	}

	newSecret := m.pendingSecret
	token, err := generateSecureToken("lease_")
	if err != nil {
		return "", "", fmt.Errorf("failed to mint lease token: %w", err)
	}

	// Persist first. Security state must not claim success if the durable
	// configuration could not be written.
	if m.envPath != "" {
		updates := map[string]string{
			"ENABLE_2FA_GATE": "true",
			"TOTP_SECRET":     newSecret,
		}
		if err := PersistEnv(m.envPath, updates); err != nil {
			return "", "", fmt.Errorf("failed to persist 2FA configuration: %w", err)
		}
	}

	// Verification and persistence succeeded: activate 2FA and issue the
	// first dynamic lease token so the current session remains usable.
	m.totpSecret = newSecret
	m.pendingSecret = ""
	m.enabled = true

	now := time.Now()
	m.leases[token] = &Lease{
		Token:           token,
		CreatedAt:       now,
		LastActivityAt:  now,
		DurationMinutes: 0,
		ClientIP:        clientIP,
		Country:         country,
	}

	return m.totpSecret, token, nil
}

// Disable2FA disables 2FA, revokes all leases, and updates .env.
func (m *Manager) Disable2FA() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Persist first so a disk/permission failure cannot create a fail-open
	// mismatch where RAM says 2FA is disabled but restart behavior differs.
	if m.envPath != "" {
		updates := map[string]string{
			"ENABLE_2FA_GATE": "false",
		}
		if err := PersistEnv(m.envPath, updates); err != nil {
			return fmt.Errorf("failed to persist disabled 2FA state: %w", err)
		}
	}

	m.enabled = false
	m.pendingSecret = ""
	m.leases = make(map[string]*Lease)
	return nil
}

// Configure2FA is a direct configuration method (backward-compatible).
func (m *Manager) Configure2FA(secret string, enable bool) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	activeSecret := m.totpSecret
	if enable {
		if secret != "" {
			if err := ValidateSecretFormat(secret); err != nil {
				return "", err
			}
			activeSecret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
		} else if activeSecret == "" {
			sec, err := GenerateRandomSecret()
			if err != nil {
				return "", err
			}
			activeSecret = sec
		}
	}

	if m.envPath != "" {
		updates := map[string]string{
			"ENABLE_2FA_GATE": fmt.Sprintf("%t", enable),
		}
		if enable && activeSecret != "" {
			updates["TOTP_SECRET"] = activeSecret
		}
		if err := PersistEnv(m.envPath, updates); err != nil {
			return "", fmt.Errorf("failed to persist 2FA configuration: %w", err)
		}
	}

	m.totpSecret = activeSecret
	m.enabled = enable
	if !enable {
		m.leases = make(map[string]*Lease)
	}

	return m.totpSecret, nil
}

// HasSecret returns whether a TOTP secret is configured.
func (m *Manager) HasSecret() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.totpSecret != ""
}

// GetSecret returns the configured TOTP secret.
func (m *Manager) GetSecret() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.totpSecret
}

// GetPendingSecret returns the pending TOTP secret if any.
func (m *Manager) GetPendingSecret() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.pendingSecret
}

// IsEnabled returns whether 2FA gate is currently active.
func (m *Manager) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

func (m *Manager) pruneFailuresLocked(now time.Time) {
	cutoff := now.Add(-totpFailureWindow)

	filterTimes := func(in []time.Time) []time.Time {
		out := in[:0]
		for _, ts := range in {
			if ts.After(cutoff) {
				out = append(out, ts)
			}
		}
		return out
	}

	m.globalFailures = filterTimes(m.globalFailures)
	for key, state := range m.totpAttempts {
		state.Failures = filterTimes(state.Failures)
		if !state.BlockedUntil.IsZero() && now.After(state.BlockedUntil) {
			state.BlockedUntil = time.Time{}
		}
		if len(state.Failures) == 0 && state.BlockedUntil.IsZero() {
			delete(m.totpAttempts, key)
		}
	}
}

func (m *Manager) checkTOTPRateLimitLocked(clientKey string, now time.Time) error {
	m.pruneFailuresLocked(now)

	if len(m.globalFailures) >= totpGlobalFailureLimit {
		return errors.New("too many failed 2FA attempts; please wait a few minutes before trying again")
	}

	if state := m.totpAttempts[clientKey]; state != nil && now.Before(state.BlockedUntil) {
		return errors.New("too many failed 2FA attempts from this client; please wait before trying again")
	}

	return nil
}

func (m *Manager) recordTOTPFailureLocked(clientKey string, now time.Time) {
	state := m.totpAttempts[clientKey]
	if state == nil {
		state = &totpAttemptState{}
		m.totpAttempts[clientKey] = state
	}

	state.Failures = append(state.Failures, now)
	m.globalFailures = append(m.globalFailures, now)

	if len(state.Failures) >= totpClientFailureLimit {
		state.BlockedUntil = now.Add(totpFailureWindow)
	}
}

func (m *Manager) clearClientTOTPFailuresLocked(clientKey string) {
	delete(m.totpAttempts, clientKey)
}

func totpReplayKey(secret string, step int64) string {
	sum := sha256.Sum256([]byte(secret))
	return fmt.Sprintf("%x:%d", sum[:], step)
}

func (m *Manager) purgeUsedTOTPStepsLocked(now time.Time) {
	cutoff := now.Add(-totpUsedRetention)
	for key, usedAt := range m.usedTOTPSteps {
		if usedAt.Before(cutoff) {
			delete(m.usedTOTPSteps, key)
		}
	}
}

// validateAndConsumeTOTPLocked validates a TOTP, rate-limits failures and marks
// a successful RFC 6238 time-step as consumed so the same code cannot mint
// multiple leases. Caller must hold m.mu for writing.
func (m *Manager) validateAndConsumeTOTPLocked(secret, code, clientKey string) (bool, error) {
	if clientKey == "" {
		clientKey = "unknown"
	}

	now := time.Now()
	if err := m.checkTOTPRateLimitLocked(clientKey, now); err != nil {
		return false, err
	}

	valid, step, err := ValidateTOTPWithStep(secret, code, now)
	if err != nil {
		return false, err
	}
	if !valid {
		m.recordTOTPFailureLocked(clientKey, now)
		return false, nil
	}

	m.clearClientTOTPFailuresLocked(clientKey)
	m.purgeUsedTOTPStepsLocked(now)

	replayKey := totpReplayKey(secret, step)
	if _, exists := m.usedTOTPSteps[replayKey]; exists {
		return false, errors.New("this 2FA code has already been used; wait for the next authenticator code")
	}
	m.usedTOTPSteps[replayKey] = now

	return true, nil
}

func (m *Manager) validateLeaseLocked(token string, now time.Time) (bool, string) {
	if !m.enabled {
		return true, ""
	}

	if token != "" {
		if lease, exists := m.leases[token]; exists {
			if !lease.ExpiresAt.IsZero() && now.After(lease.ExpiresAt) {
				delete(m.leases, token)
				return false, "SECURITY GATE: 2FA Lease time limit expired. Please unlock again."
			}

			lease.LastActivityAt = now
			return true, ""
		}
	}

	return false, "SECURITY GATE LOCKED: 2FA verification required. Please ask the user for their 6-digit Google Authenticator code, then invoke the 'unlock_gate' tool with the code to obtain a dynamic lease_token."
}

// AuthorizeManagement requires a valid active lease or a fresh current TOTP
// before security-sensitive 2FA configuration can be changed.
func (m *Manager) AuthorizeManagement(leaseToken, currentCode, clientKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.enabled {
		return nil
	}

	if allowed, _ := m.validateLeaseLocked(leaseToken, time.Now()); allowed {
		return nil
	}

	if strings.TrimSpace(currentCode) == "" {
		return errors.New("2FA management requires a valid lease_token or current authenticator code")
	}

	valid, err := m.validateAndConsumeTOTPLocked(m.totpSecret, currentCode, clientKey)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("invalid current authenticator code")
	}

	return nil
}

// CreateLease verifies the TOTP code and mints a dynamic lease token.
// durationMinutes == 0 means permanent (never expires).
func (m *Manager) CreateLease(code string, durationMinutes int, clientIP, country string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.enabled {
		return "2fa_disabled", nil
	}

	if m.totpSecret == "" {
		return "", errors.New("TOTP_SECRET is not configured. Please invoke setup_2fa first")
	}

	valid, err := m.validateAndConsumeTOTPLocked(m.totpSecret, code, clientIP)
	if err != nil {
		return "", err
	}
	if !valid {
		return "", errors.New("invalid TOTP verification code")
	}

	now := time.Now()
	m.purgeExpiredLeasesLocked(now)
	token, err := generateSecureToken("lease_")
	if err != nil {
		return "", fmt.Errorf("failed to mint lease token: %w", err)
	}

	lease := &Lease{
		Token:           token,
		CreatedAt:       now,
		LastActivityAt:  now,
		DurationMinutes: durationMinutes,
		ClientIP:        clientIP,
		Country:         country,
	}

	if durationMinutes > 0 {
		lease.ExpiresAt = now.Add(time.Duration(durationMinutes) * time.Minute)
	}

	m.leases[token] = lease
	return token, nil
}

// ValidateLease verifies if the given lease_token is valid and active.
func (m *Manager) ValidateLease(token string) (bool, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.validateLeaseLocked(token, time.Now())
}

// CheckAccess provides a backward-compatible check.
func (m *Manager) CheckAccess() (bool, string) {
	return m.ValidateLease("")
}

// RecordActivity placeholder for backward compatibility.
func (m *Manager) RecordActivity() {}

// Unlock mints a lease for backward-compatible callers.
func (m *Manager) Unlock(code string) (string, error) {
	return m.CreateLease(code, 0, "web_ui", "LOCAL")
}

// UnlockForClient preserves the real client identity for rate limiting and audit.
func (m *Manager) UnlockForClient(code, clientIP, country string) (string, error) {
	return m.CreateLease(code, 0, clientIP, country)
}

// RevokeLease removes a specific lease token.
func (m *Manager) RevokeLease(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.leases, token)
}

// Lock invalidates all active leases.
func (m *Manager) Lock() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.leases = make(map[string]*Lease)
}

// purgeExpiredLeasesLocked cleans up expired leases from memory (caller must hold Lock).
func (m *Manager) purgeExpiredLeasesLocked(now time.Time) {
	for token, lease := range m.leases {
		if !lease.ExpiresAt.IsZero() && now.After(lease.ExpiresAt) {
			delete(m.leases, token)
		}
	}
}

// GetState returns clean dynamic status.
func (m *Manager) GetState() StateInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	activeCount := 0
	for _, lease := range m.leases {
		if lease.ExpiresAt.IsZero() || !now.After(lease.ExpiresAt) {
			activeCount++
		}
	}

	info := StateInfo{
		Enabled:           m.enabled,
		HasSecret:         m.totpSecret != "",
		ActiveLeasesCount: activeCount,
		Status:            "DISABLED",
	}

	if m.enabled {
		if activeCount > 0 {
			info.Status = "UNLOCKED"
			info.Unlocked = true
		} else {
			info.Status = "LOCKED"
			info.Unlocked = false
		}
	} else {
		info.Unlocked = true
	}

	return info
}

// AddAudit records a tool execution into the ring buffer.
func (m *Manager) AddAudit(entry AuditEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	if len(m.auditRing) >= m.maxAudits {
		m.auditRing = m.auditRing[1:]
	}
	m.auditRing = append(m.auditRing, entry)
}

// GetAudits returns the recorded audit logs in reverse chronological order (newest first).
func (m *Manager) GetAudits() []AuditEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	n := len(m.auditRing)
	res := make([]AuditEntry, n)
	for i, entry := range m.auditRing {
		res[n-1-i] = entry
	}
	return res
}

// ResolveClientIP parses real client IP and country from request headers.
func ResolveClientIP(r *http.Request) (string, string) {
	country := r.Header.Get("CF-IPCountry")
	if country == "" {
		country = "LOCAL"
	}

	if cfIP := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cfIP != "" {
		return cfIP, country
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip, country
			}
		}
	}

	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		return xri, country
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host, country
	}

	return r.RemoteAddr, country
}

func generateSecureToken(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("secure random generation failed: %w", err)
	}
	return prefix + hex.EncodeToString(b), nil
}

// PersistEnv writes or updates key-value pairs in a .env file.
// The replacement is atomic and process environment variables are updated only
// after the durable file replacement succeeds.
func PersistEnv(filePath string, updates map[string]string) error {
	if filePath == "" || len(updates) == 0 {
		return nil
	}

	var lines []string
	foundKeys := make(map[string]bool)

	if data, err := os.ReadFile(filePath); err == nil {
		rawLines := strings.Split(string(data), "\n")
		for _, rawLine := range rawLines {
			trimmed := strings.TrimSpace(rawLine)
			if strings.HasPrefix(trimmed, "#") || !strings.Contains(trimmed, "=") {
				lines = append(lines, rawLine)
				continue
			}

			parts := strings.SplitN(trimmed, "=", 2)
			key := strings.TrimSpace(parts[0])

			if newVal, ok := updates[key]; ok {
				lines = append(lines, fmt.Sprintf("%s=%s", key, newVal))
				foundKeys[key] = true
			} else {
				lines = append(lines, rawLine)
				foundKeys[key] = true
			}
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to read env file: %w", err)
	}

	for key, val := range updates {
		if !foundKeys[key] {
			lines = append(lines, fmt.Sprintf("%s=%s", key, val))
			foundKeys[key] = true
		}
	}

	// Safety: if AUTH_TOKEN is not in .env but is present in current environment, preserve it.
	if !foundKeys["AUTH_TOKEN"] {
		if tok := os.Getenv("AUTH_TOKEN"); tok != "" {
			lines = append([]string{fmt.Sprintf("AUTH_TOKEN=%s", tok)}, lines...)
		}
	}

	outContent := strings.Join(lines, "\n")
	if !strings.HasSuffix(outContent, "\n") {
		outContent += "\n"
	}

	dir := filepath.Dir(filePath)
	base := filepath.Base(filePath)
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary env file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	defer cleanup()

	if err := tmp.Chmod(0600); err != nil {
		return fmt.Errorf("failed to secure temporary env file: %w", err)
	}
	if _, err := tmp.WriteString(outContent); err != nil {
		return fmt.Errorf("failed to write temporary env file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("failed to sync temporary env file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temporary env file: %w", err)
	}
	if err := os.Rename(tmpName, filePath); err != nil {
		return fmt.Errorf("failed to atomically replace env file: %w", err)
	}

	for key, val := range updates {
		if err := os.Setenv(key, val); err != nil {
			return fmt.Errorf("env file persisted but failed to update process environment for %s: %w", key, err)
		}
	}

	return nil
}
