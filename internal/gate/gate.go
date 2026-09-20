package gate

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
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
}

// Manager manages the 2FA lifecycle, leases, and audit logs.
type Manager struct {
	mu         sync.RWMutex
	enabled    bool
	totpSecret string
	leases     map[string]*Lease
	auditRing  []AuditEntry
	maxAudits  int
}

// Config holds Gate Manager initialization options.
type Config struct {
	Enabled    bool
	TOTPSecret string
}

// NewManager creates a Gate Manager instance.
func NewManager(cfg Config) *Manager {
	return &Manager{
		enabled:    cfg.Enabled,
		totpSecret: cfg.TOTPSecret,
		leases:     make(map[string]*Lease),
		maxAudits:  20,
		auditRing:  make([]AuditEntry, 0, 20),
	}
}

// Configure2FA dynamically updates the 2FA secret and enabled toggle via chat or API.
func (m *Manager) Configure2FA(secret string, enable bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if secret != "" {
		m.totpSecret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	}
	m.enabled = enable
	if !enable {
		m.leases = make(map[string]*Lease)
	}
}

// IsEnabled returns whether 2FA gate is currently active.
func (m *Manager) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
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

	valid, err := ValidateTOTP(m.totpSecret, code, time.Now())
	if err != nil {
		return "", err
	}
	if !valid {
		return "", errors.New("invalid TOTP verification code")
	}

	now := time.Now()
	token := generateSecureToken("lease_")

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

	// 1. If 2FA is disabled, direct access granted!
	if !m.enabled {
		return true, ""
	}

	now := time.Now()

	// 2. Check Lease Token
	if token != "" {
		if lease, exists := m.leases[token]; exists {
			// Check expiration if duration was specified (> 0)
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

// CheckAccess provides a backward-compatible check.
func (m *Manager) CheckAccess() (bool, string) {
	return m.ValidateLease("")
}

// RecordActivity placeholder for backward compatibility.
func (m *Manager) RecordActivity() {}

// Unlock globally for web UI backward compatibility.
func (m *Manager) Unlock(code string) error {
	_, err := m.CreateLease(code, 0, "web_ui", "LOCAL")
	return err
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

// GetState returns clean dynamic status.
func (m *Manager) GetState() StateInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	info := StateInfo{
		Enabled:           m.enabled,
		HasSecret:         m.totpSecret != "",
		ActiveLeasesCount: len(m.leases),
		Status:            "DISABLED",
	}

	if m.enabled {
		if len(m.leases) > 0 {
			info.Status = "UNLOCKED"
		} else {
			info.Status = "LOCKED"
		}
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

	// 1. Cloudflare connecting IP
	if cfIP := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cfIP != "" {
		return cfIP, country
	}

	// 2. X-Forwarded-For (first hop)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip, country
			}
		}
	}

	// 3. X-Real-IP
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		return xri, country
	}

	// 4. RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host, country
	}

	return r.RemoteAddr, country
}

func generateSecureToken(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}
