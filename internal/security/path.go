package security

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var ErrAccessDenied = errors.New("access denied: path outside workspace")

// OpenWorkspacePath returns a directory handle and a relative path. Callers must
// perform file operations through Root, then close it, so symlink replacement
// cannot escape the workspace between validation and use.
func OpenWorkspacePath(workspaceRoot, targetPath string) (*os.Root, string, error) {
	if workspaceRoot == "" {
		return nil, "", errors.New("workspace root is not configured")
	}
	cleanRoot, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return nil, "", fmt.Errorf("invalid workspace root: %w", err)
	}
	if targetPath == "" {
		targetPath = "."
	}
	if filepath.IsAbs(targetPath) {
		targetPath, err = filepath.Rel(cleanRoot, targetPath)
		if err != nil {
			return nil, "", ErrAccessDenied
		}
	}
	if !filepath.IsLocal(targetPath) {
		return nil, "", ErrAccessDenied
	}
	root, err := os.OpenRoot(cleanRoot)
	if err != nil {
		return nil, "", fmt.Errorf("open workspace: %w", err)
	}
	return root, targetPath, nil
}

// SafePath checks a shell's initial working directory. It is not a sandbox;
// file tools must use OpenWorkspacePath and Root operations instead.
func SafePath(workspaceRoot, targetPath string) (string, error) {
	root, relative, err := OpenWorkspacePath(workspaceRoot, targetPath)
	if err != nil {
		return "", err
	}
	defer root.Close()
	if _, err := root.Stat(relative); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("%w: %v", ErrAccessDenied, err)
	}
	return filepath.Abs(filepath.Join(root.Name(), relative))
}
