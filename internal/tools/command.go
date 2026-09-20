package tools

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
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
		mcp.WithDescription("Execute shell command within workspace with strict timeout and output limits"),
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
			timeout = time.Duration(tSec) * time.Second
		} else if tSec == -1 {
			timeout = 0 // unlimited
		}

		var execCtx context.Context
		var cancel context.CancelFunc
		if timeout > 0 {
			execCtx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		} else {
			execCtx = ctx
		}

		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.CommandContext(execCtx, "cmd.exe", "/c", command)
		} else {
			cmd = exec.CommandContext(execCtx, "sh", "-c", command)
		}

		cmd.Dir = execDir

		var stdoutBuf, stderrBuf bytes.Buffer
		cmd.Stdout = &stdoutBuf
		cmd.Stderr = &stderrBuf

		cmdErr := cmd.Run()

		stdoutStr := stdoutBuf.String()
		stderrStr := stderrBuf.String()

		if len(stdoutStr) > MaxOutputBytes {
			stdoutStr = stdoutStr[:MaxOutputBytes] + "\n... [stdout truncated due to 4MB limit. Tip: redirect large output to file with > file.log]"
		}
		if len(stderrStr) > MaxOutputBytes {
			stderrStr = stderrStr[:MaxOutputBytes] + "\n... [stderr truncated due to 4MB limit]"
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

func truncateStr(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
