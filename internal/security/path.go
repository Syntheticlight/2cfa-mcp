package security

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

var (
	ErrAccessDenied = errors.New("access denied: path outside workspace")
)

// SafePath resolves and verifies that targetPath resides inside workspaceRoot.
// It prevents path traversal attacks like "../", absolute path escapes, etc.
func SafePath(workspaceRoot, targetPath string) (string, error) {
	if workspaceRoot == "" {
		return "", errors.New("workspace root is not configured")
	}

	cleanRoot, err := filepath.Abs(filepath.Clean(workspaceRoot))
	if err != nil {
		return "", fmt.Errorf("invalid workspace root: %w", err)
	}

	// Normalize separators for cross-platform checking
	slashTarget := strings.ReplaceAll(targetPath, "\\", "/")

	var fullPath string
	// Check if target is absolute or starts with root slash/drive
	if filepath.IsAbs(targetPath) || strings.HasPrefix(slashTarget, "/") || filepath.VolumeName(targetPath) != "" {
		fullPath = filepath.Clean(targetPath)
	} else {
		fullPath = filepath.Clean(filepath.Join(cleanRoot, targetPath))
	}

	fullPath, err = filepath.Abs(fullPath)
	if err != nil {
		return "", fmt.Errorf("invalid target path: %w", err)
	}

	// Calculate relative path from cleanRoot to fullPath
	rel, err := filepath.Rel(cleanRoot, fullPath)
	if err != nil {
		return "", ErrAccessDenied
	}

	// If relative path starts with ".." or equals "..", it's outside cleanRoot
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || strings.HasPrefix(rel, "../") {
		return "", ErrAccessDenied
	}

	return fullPath, nil
}
