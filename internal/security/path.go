package security

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrAccessDenied = errors.New("access denied: path outside workspace")
)

// SafePath resolves and verifies that targetPath resides inside workspaceRoot.
// It prevents path traversal attacks like "../", absolute path escapes, and symlink escapes.
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

	// 1. Lexical traversal check (cleanRoot to fullPath)
	rel, err := filepath.Rel(cleanRoot, fullPath)
	if err != nil {
		return "", ErrAccessDenied
	}

	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || strings.HasPrefix(rel, "../") {
		return "", ErrAccessDenied
	}

	// 2. Symlink evaluation check (defend against symlink jailbreak)
	realRoot, err := filepath.EvalSymlinks(cleanRoot)
	if err != nil {
		realRoot = cleanRoot
	}

	// If the file or target exists, evaluate symlinks directly
	if _, statErr := os.Lstat(fullPath); statErr == nil {
		realTarget, evalErr := filepath.EvalSymlinks(fullPath)
		if evalErr == nil {
			realRel, rErr := filepath.Rel(realRoot, realTarget)
			if rErr != nil || realRel == ".." || strings.HasPrefix(realRel, ".."+string(filepath.Separator)) || strings.HasPrefix(realRel, "../") {
				return "", ErrAccessDenied
			}
		}
	} else {
		// If target doesn't exist yet (e.g. write_file), evaluate existing parent
		curr := filepath.Dir(fullPath)
		for {
			if _, err := os.Stat(curr); err == nil {
				if realDir, err := filepath.EvalSymlinks(curr); err == nil {
					relDir, rErr := filepath.Rel(realRoot, realDir)
					if rErr != nil || relDir == ".." || strings.HasPrefix(relDir, ".."+string(filepath.Separator)) || strings.HasPrefix(relDir, "../") {
						return "", ErrAccessDenied
					}
				}
				break
			}
			parent := filepath.Dir(curr)
			if parent == curr {
				break
			}
			curr = parent
		}
	}

	return fullPath, nil
}
