//go:build windows

package tools

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// configureCommandCancellation uses taskkill /T so context cancellation tears
// down the whole child process tree instead of leaving grandchildren running.
func configureCommandCancellation(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}

		err := exec.Command("taskkill", "/PID", strconv.Itoa(cmd.Process.Pid), "/T", "/F").Run()
		if err == nil {
			return nil
		}

		// Fallback to the direct process if taskkill is unavailable.
		if killErr := cmd.Process.Kill(); killErr != nil {
			if errors.Is(killErr, os.ErrProcessDone) {
				return os.ErrProcessDone
			}
			return killErr
		}
		return nil
	}
	cmd.WaitDelay = 2 * time.Second
}
