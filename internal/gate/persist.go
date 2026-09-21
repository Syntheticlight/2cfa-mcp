package gate

import (
	"fmt"
	"os"
	"path/filepath"
)

// replaceFileSafely prefers a same-directory atomic rename. On platforms where
// replacing an existing destination with Rename is unsupported, it falls back
// to a rollback-capable swap.
func replaceFileSafely(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	} else {
		firstErr := err
		if _, statErr := os.Stat(dst); statErr != nil {
			return firstErr
		}

		dir := filepath.Dir(dst)
		base := filepath.Base(dst)
		placeholder, createErr := os.CreateTemp(dir, "."+base+".backup-*")
		if createErr != nil {
			return fmt.Errorf("prepare replacement backup: %w", createErr)
		}
		backup := placeholder.Name()
		if closeErr := placeholder.Close(); closeErr != nil {
			_ = os.Remove(backup)
			return fmt.Errorf("close replacement backup placeholder: %w", closeErr)
		}
		if removeErr := os.Remove(backup); removeErr != nil {
			return fmt.Errorf("prepare replacement backup path: %w", removeErr)
		}

		if err := os.Rename(dst, backup); err != nil {
			return fmt.Errorf("move existing destination aside: %w", err)
		}

		if err := os.Rename(src, dst); err != nil {
			rollbackErr := os.Rename(backup, dst)
			if rollbackErr != nil {
				return fmt.Errorf("install replacement: %v; rollback also failed: %w", err, rollbackErr)
			}
			return fmt.Errorf("install replacement: %w", err)
		}

		if err := os.Remove(backup); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("replacement succeeded but cleanup backup failed: %w", err)
		}
		return nil
	}
}
