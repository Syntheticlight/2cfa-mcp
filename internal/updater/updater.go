package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	CurrentVersion = "v1.0.4"
	RepoOwner      = "Syntheticlight"
	RepoName       = "2cfa-mcp"
	GitHubAPIURL   = "https://api.github.com/repos/Syntheticlight/2cfa-mcp/releases/latest"
	CacheTTL       = 6 * time.Hour
)

// UpdateInfo holds the latest release metadata and status.
type UpdateInfo struct {
	CurrentVersion string    `json:"current_version"`
	LatestVersion  string    `json:"latest_version"`
	HasUpdate      bool      `json:"has_update"`
	ReleaseURL     string    `json:"release_url"`
	ReleaseName    string    `json:"release_name"`
	PublishedAt    time.Time `json:"published_at"`
	CheckedAt      time.Time `json:"checked_at"`
	CheckError     string    `json:"check_error,omitempty"`
}

var (
	mu          sync.RWMutex
	cachedInfo  UpdateInfo = UpdateInfo{
		CurrentVersion: CurrentVersion,
		LatestVersion:  CurrentVersion,
		HasUpdate:      false,
		ReleaseURL:     fmt.Sprintf("https://github.com/%s/%s/releases", RepoOwner, RepoName),
	}
	lastChecked time.Time
)

// GetInfo returns the cached or current update status.
func GetInfo() UpdateInfo {
	mu.RLock()
	defer mu.RUnlock()
	return cachedInfo
}

// Check checks for updates from GitHub Releases API with memory caching.
func Check(ctx context.Context, force bool) UpdateInfo {
	mu.Lock()
	defer mu.Unlock()

	if !force && !lastChecked.IsZero() && time.Since(lastChecked) < CacheTTL {
		return cachedInfo
	}

	info := UpdateInfo{
		CurrentVersion: CurrentVersion,
		LatestVersion:  CurrentVersion,
		HasUpdate:      false,
		ReleaseURL:     fmt.Sprintf("https://github.com/%s/%s/releases", RepoOwner, RepoName),
		CheckedAt:      time.Now(),
	}

	reqCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, GitHubAPIURL, nil)
	if err != nil {
		info.CheckError = err.Error()
		cachedInfo = info
		lastChecked = time.Now()
		return info
	}

	req.Header.Set("User-Agent", "2cfa-mcp/"+CurrentVersion)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		info.CheckError = err.Error()
		cachedInfo = info
		lastChecked = time.Now()
		return info
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		info.CheckError = fmt.Sprintf("GitHub API status %d", resp.StatusCode)
		cachedInfo = info
		lastChecked = time.Now()
		return info
	}

	var ghRelease struct {
		TagName     string    `json:"tag_name"`
		Name        string    `json:"name"`
		HTMLURL     string    `json:"html_url"`
		PublishedAt time.Time `json:"published_at"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ghRelease); err != nil {
		info.CheckError = err.Error()
		cachedInfo = info
		lastChecked = time.Now()
		return info
	}

	latestTag := strings.TrimSpace(ghRelease.TagName)
	if latestTag != "" {
		info.LatestVersion = latestTag
		info.ReleaseName = ghRelease.Name
		info.ReleaseURL = ghRelease.HTMLURL
		info.PublishedAt = ghRelease.PublishedAt
		info.HasUpdate = IsNewerVersion(CurrentVersion, latestTag)
	}

	cachedInfo = info
	lastChecked = time.Now()
	return info
}

// StartBackgroundChecker launches a non-blocking background check on startup and periodically.
func StartBackgroundChecker() {
	go func() {
		// Initial check after short delay (let server bind port first)
		time.Sleep(2 * time.Second)
		info := Check(context.Background(), true)
		if info.HasUpdate {
			log.Printf("[UPDATE] 🚀 A new release %s is available! (Current: %s). Download: %s",
				info.LatestVersion, info.CurrentVersion, info.ReleaseURL)
		}

		// Periodic check every 6 hours
		ticker := time.NewTicker(CacheTTL)
		defer ticker.Stop()
		for range ticker.C {
			info := Check(context.Background(), false)
			if info.HasUpdate {
				log.Printf("[UPDATE] 🚀 A new release %s is available! (Current: %s). Download: %s",
					info.LatestVersion, info.CurrentVersion, info.ReleaseURL)
			}
		}
	}()
}

// IsNewerVersion returns true if latest is semantically newer than current.
func IsNewerVersion(current, latest string) bool {
	c := cleanVersion(current)
	l := cleanVersion(latest)
	return compareVersions(c, l) < 0
}

func cleanVersion(v string) string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	return v
}

// compareVersions returns -1 if v1 < v2, 1 if v1 > v2, 0 if equal.
func compareVersions(v1, v2 string) int {
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var n1, n2 int
		if i < len(parts1) {
			_, _ = fmt.Sscanf(parts1[i], "%d", &n1)
		}
		if i < len(parts2) {
			_, _ = fmt.Sscanf(parts2[i], "%d", &n2)
		}
		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}
	}
	return 0
}
