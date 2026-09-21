package tools

// CommandOutput is the structured result returned by execute_command.
type CommandOutput struct {
	Success         bool   `json:"success"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	ExitCode        int    `json:"exit_code"`
	DurationMs      int64  `json:"duration_ms"`
	TimedOut        bool   `json:"timed_out"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
}

// ReadFileOutput is the structured result returned by read_file.
type ReadFileOutput struct {
	Success bool   `json:"success"`
	Path    string `json:"path"`
	Content string `json:"content"`
	Size    int    `json:"size"`
}

// WriteFileOutput is the structured result returned by write_file.
type WriteFileOutput struct {
	Success      bool   `json:"success"`
	Path         string `json:"path"`
	BytesWritten int    `json:"bytes_written"`
}

// DirectoryEntry describes one list_dir entry.
type DirectoryEntry struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Size     int64  `json:"size"`
	Modified string `json:"modified"`
}

// ListDirOutput is the structured result returned by list_dir.
type ListDirOutput struct {
	Success   bool             `json:"success"`
	Path      string           `json:"path"`
	Entries   []DirectoryEntry `json:"entries"`
	Count     int              `json:"count"`
	Truncated bool             `json:"truncated"`
}

// Setup2FAOutput covers all successful setup_2fa lifecycle states.
type Setup2FAOutput struct {
	Success    bool   `json:"success"`
	Action     string `json:"action"`
	Enabled    bool   `json:"enabled"`
	Status     string `json:"status"`
	Message    string `json:"message"`
	Secret     string `json:"secret,omitempty"`
	OTPAuthURI string `json:"otp_auth_uri,omitempty"`
	QRCode     string `json:"qr_code,omitempty"`
	LeaseToken string `json:"lease_token,omitempty"`
}

// UnlockGateOutput is the structured result returned by unlock_gate.
type UnlockGateOutput struct {
	Success         bool   `json:"success"`
	Enabled         bool   `json:"enabled"`
	Status          string `json:"status"`
	LeaseToken      string `json:"lease_token,omitempty"`
	DurationMinutes int    `json:"duration_minutes"`
	HasTimeExpiry   bool   `json:"has_time_expiry"`
	Message         string `json:"message"`
}

// LockGateOutput is the structured result returned by lock_gate.
type LockGateOutput struct {
	Success bool   `json:"success"`
	Status  string `json:"status"`
	Scope   string `json:"scope"`
	Message string `json:"message"`
}

// SystemStatusOutput is the structured result returned by system_status/system_info.
type SystemStatusOutput struct {
	Version         string  `json:"version"`
	LatestVersion   string  `json:"latest_version"`
	UpdateAvailable bool    `json:"update_available"`
	ReleaseURL      string  `json:"release_url,omitempty"`
	OS              string  `json:"os"`
	Architecture    string  `json:"architecture"`
	LogicalCPUs     int     `json:"logical_cpus"`
	Goroutines      int     `json:"goroutines"`
	UptimeSeconds   int64   `json:"uptime_seconds"`
	AllocatedRAMMB  float64 `json:"allocated_ram_mb"`
	RuntimeSysMB    float64 `json:"runtime_sys_mb"`
	HeapAllocatedMB float64 `json:"heap_allocated_mb"`
	GCCycles        uint32  `json:"gc_cycles"`
	GateEnabled     bool    `json:"gate_enabled"`
	GateStatus      string  `json:"gate_status"`
	ActiveLeases    int     `json:"active_leases"`
}

// CheckUpdateOutput is the structured result returned by check_update.
type CheckUpdateOutput struct {
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	HasUpdate      bool   `json:"has_update"`
	ReleaseURL     string `json:"release_url,omitempty"`
	ReleaseName    string `json:"release_name,omitempty"`
	PublishedAt    string `json:"published_at,omitempty"`
	CheckedAt      string `json:"checked_at,omitempty"`
	CheckError     string `json:"check_error,omitempty"`
}
