package tools

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/Syntheticlight/2cfa-mcp/internal/gate"
	"github.com/Syntheticlight/2cfa-mcp/internal/security"
)

const (
	DefaultExecTimeout = 120 * time.Second
	MaxOutputBytes     = 4 * 1024 * 1024 // 4 MB limit (protects LLM context window & RAM)
)

// RegisterCommandTool registers execute_command tool to MCP server.
func RegisterCommandTool(s *server.MCPServer, workspaceRoot string, defaultTimeout time.Duration, gateMgr *gate.Manager) {
	if defaultTimeout <= 0 {
		defaultTimeout = DefaultExecTimeout
	}

	tool := mcp.NewTool("execute_command",
		mcp.WithDescription("Execute a shell command starting in the workspace with strict timeout and bounded captured output. The shell inherits the server process OS permissions and is not a filesystem sandbox."),
		mcp.WithString("command", mcp.Required(), mcp.Description("The shell command to execute")),
		mcp.WithString("work_dir", mcp.Description("Optional sub-directory relative to workspace root")),
		mcp.WithNumber("timeout_seconds", mcp.Description("Optional execution timeout in seconds (e.g. 600 or 1800 for long tasks/downloads). Set -1 for unlimited")),
		mcp.WithString("lease_token", mcp.Description("Optional. Leave empty in normal use. Only pass if 2FA gate was explicitly turned on")),
	)

	s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		ip, country := resolveHeaderIP(request.Header)
		leaseToken := request.GetString("lease_token", "")

		// 1. Gate & Lease Access Check
		if allowed, gateMsg := gateMgr.ValidateLease(leaseToken); !allowed {
			gateMgr.AddAudit(gate.AuditEntry{
				Timestamp:  time.Now(),
				ClientIP:   ip,
				Country:    country,
				ToolName:   "execute_command",
				DurationMs: 0,
				Status:     "LOCKED",
				Message:    gateMsg,
			})
			return mcp.NewToolResultError(gateMsg), nil
		}

		command, err := request.RequireString("command")
		if err != nil || command == "" {
			return mcp.NewToolResultError("argument 'command' is required and must be a non-empty string"), nil
		}

		workDirStr := request.GetString("work_dir", "")

		execDir, err := security.SafePath(workspaceRoot, workDirStr)
		if err != nil {
			gateMgr.AddAudit(gate.AuditEntry{
				Timestamp:  time.Now(),
				ClientIP:   ip,
				Country:    country,
				ToolName:   "execute_command",
				DurationMs: time.Since(start).Milliseconds(),
				Status:     "ERROR",
				Message:    "Path traversal denied",
			})
			return mcp.NewToolResultError(fmt.Sprintf("security violation for work_dir: %v", err)), nil
		}

		timeout := defaultTimeout
		tSec := request.GetFloat("timeout_seconds", 0)
		if tSec > 0 {
			timeout = time.Duration(tSec * float64(time.Second))
		} else if tSec < 0 {
			timeout = 0 // any negative value (e.g. -1) indicates unlimited execution
		}

		var execCtx context.Context
		var cancel context.CancelFunc
		if timeout > 0 {
			execCtx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		} else {
			execCtx = ctx
		}

		shellBin, shellArg := resolveShell()
		cmd := exec.CommandContext(execCtx, shellBin, shellArg, command)
		configureCommandCancellation(cmd)

		cmd.Dir = execDir

		stdoutBuf := newCappedBuffer(MaxOutputBytes)
		stderrBuf := newCappedBuffer(MaxOutputBytes)
		cmd.Stdout = stdoutBuf
		cmd.Stderr = stderrBuf

		cmdErr := cmd.Run()

		stdoutStr := stdoutBuf.String()
		stderrStr := stderrBuf.String()
		if stdoutBuf.Truncated() {
			stdoutStr += "\n... [stdout truncated at 4MB while command was running. Tip: redirect large output to file with > file.log]"
		}
		if stderrBuf.Truncated() {
			stderrStr += "\n... [stderr truncated at 4MB while command was running]"
		}

		output := fmt.Sprintf("=== STDOUT ===\n%s\n=== STDERR ===\n%s", stdoutStr, stderrStr)
		duration := time.Since(start).Milliseconds()

		if execCtx.Err() == context.DeadlineExceeded {
			gateMgr.AddAudit(gate.AuditEntry{
				Timestamp:  time.Now(),
				ClientIP:   ip,
				Country:    country,
				ToolName:   "execute_command",
				DurationMs: duration,
				Status:     "ERROR",
				Message:    "Command timed out",
			})
			return mcp.NewToolResultError(fmt.Sprintf("command timed out after %v\nPartial Output:\n%s", timeout, output)), nil
		}

		if cmdErr != nil {
			gateMgr.AddAudit(gate.AuditEntry{
				Timestamp:  time.Now(),
				ClientIP:   ip,
				Country:    country,
				ToolName:   "execute_command",
				DurationMs: duration,
				Status:     "ERROR",
				Message:    fmt.Sprintf("Exited with error: %v", cmdErr),
			})
			return mcp.NewToolResultText(fmt.Sprintf("Command exited with status error: %v\n%s", cmdErr, output)), nil
		}

		gateMgr.AddAudit(gate.AuditEntry{
			Timestamp:  time.Now(),
			ClientIP:   ip,
			Country:    country,
			ToolName:   "execute_command",
			DurationMs: duration,
			Status:     "SUCCESS",
			Message:    fmt.Sprintf("Command: %s", truncateStr(command, 50)),
		})

		return mcp.NewToolResultText(output), nil
	})
}

type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func newCappedBuffer(limit int) *cappedBuffer {
	return &cappedBuffer{limit: limit}
}

// Write implements io.Writer while retaining at most limit bytes. It reports
// the full input length as consumed so child processes never block because the
// capture buffer reached its memory ceiling.
func (b *cappedBuffer) Write(p []byte) (int, error) {
	originalLen := len(p)
	if b.limit <= 0 {
		b.truncated = b.truncated || originalLen > 0
		return originalLen, nil
	}

	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		n := originalLen
		if n > remaining {
			n = remaining
		}
		if _, err := b.buf.Write(p[:n]); err != nil {
			return 0, err
		}
	}
	if originalLen > remaining {
		b.truncated = true
	}
	return originalLen, nil
}

func (b *cappedBuffer) String() string {
	return b.buf.String()
}

func (b *cappedBuffer) Truncated() bool {
	return b.truncated
}

func truncateStr(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// resolveShell returns the shell executable and argument flag appropriate for the host platform.
// It prioritizes absolute paths to prevent Go's os/exec from invoking LookPath, which on modern Go
// uses faccessat2 — a system call blocked by seccomp on certain Android kernels (e.g. OnePlus 9R)
// leading to SIGSYS (bad system call) crashes.
func resolveShell() (string, string) {
	if runtime.GOOS == "windows" {
		return "cmd.exe", "/c"
	}

	// 1. Check $SHELL environment variable if it points to an existing absolute path
	if envShell := os.Getenv("SHELL"); strings.HasPrefix(envShell, "/") {
		if _, err := os.Stat(envShell); err == nil {
			return envShell, "-c"
		}
	}

	// 2. Check Android Termux $PREFIX if present
	if termuxPrefix := os.Getenv("PREFIX"); termuxPrefix != "" {
		for _, sub := range []string{"bin/bash", "bin/sh"} {
			p := filepath.Join(termuxPrefix, sub)
			if _, err := os.Stat(p); err == nil {
				return p, "-c"
			}
		}
	}

	// 3. Known absolute paths across Termux, Android OS, and standard Linux/macOS
	candidates := []string{
		"/data/data/com.termux/files/usr/bin/bash",
		"/data/data/com.termux/files/usr/bin/sh",
		"/bin/bash",
		"/bin/sh",
		"/usr/bin/bash",
		"/usr/bin/sh",
		"/system/bin/sh",
	}

	for _, cand := range candidates {
		if _, err := os.Stat(cand); err == nil {
			return cand, "-c"
		}
	}

	// 4. Fallback (if no absolute path exists)
	return "sh", "-c"
}
