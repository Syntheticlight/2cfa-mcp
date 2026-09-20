//go:build windows

package tools

import (
	"os/exec"
	"time"
)

// Windows keeps os/exec's direct-process cancellation semantics. A short
// WaitDelay prevents inherited pipes from holding Command.Wait indefinitely.
func configureCommandCancellation(cmd *exec.Cmd) {
	cmd.WaitDelay = 2 * time.Second
}
