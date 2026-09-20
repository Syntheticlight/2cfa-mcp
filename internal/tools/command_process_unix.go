//go:build linux || android || darwin || freebsd || openbsd || netbsd

package tools

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// configureCommandCancellation places the shell and its ordinary descendants
// in a dedicated process group. Context cancellation then kills the whole
// group instead of only the outer shell process.
func configureCommandCancellation(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 2 * time.Second
}
