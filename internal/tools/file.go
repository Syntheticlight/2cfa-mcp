package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/Syntheticlight/2cfa-mcp/internal/gate"
	"github.com/Syntheticlight/2cfa-mcp/internal/security"
)

const MaxReadFileBytes = 10 * 1024 * 1024 // 10 MB limit for single file read

// RegisterFileTools registers read_file, write_file, and list_dir tools to MCP server.
func RegisterFileTools(s *server.MCPServer, workspaceRoot string, gateMgr *gate.Manager) {
	// 1. read_file
	readTool := mcp.NewTool("read_file",
		mcp.WithDescription("Read file contents from workspace"),
		mcp.WithString("path", mcp.Required(), mcp.Description("File path relative to workspace root")),
		mcp.WithString("lease_token", mcp.Description("Dynamic 2FA lease token acquired from unlock_gate")),
	)

	s.AddTool(readTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		ip, country := resolveHeaderIP(request.Header)
		leaseToken := request.GetString("lease_token", "")

		// Gate & Lease check
		if allowed, gateMsg := gateMgr.ValidateLease(leaseToken); !allowed {
			gateMgr.AddAudit(gate.AuditEntry{
				Timestamp:  time.Now(),
				ClientIP:   ip,
				Country:    country,
				ToolName:   "read_file",
				DurationMs: 0,
				Status:     "LOCKED",
				Message:    gateMsg,
			})
			return mcp.NewToolResultError(gateMsg), nil
		}

		relPath, err := request.RequireString("path")
		if err != nil || relPath == "" {
			return mcp.NewToolResultError("argument 'path' is required"), nil
		}

		targetPath, err := security.SafePath(workspaceRoot, relPath)
		if err != nil {
			gateMgr.AddAudit(gate.AuditEntry{
				Timestamp:  time.Now(),
				ClientIP:   ip,
				Country:    country,
				ToolName:   "read_file",
				DurationMs: time.Since(start).Milliseconds(),
				Status:     "ERROR",
				Message:    "Path traversal denied",
			})
			return mcp.NewToolResultError(fmt.Sprintf("security violation: %v", err)), nil
		}

		info, err := os.Stat(targetPath)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to stat file: %v", err)), nil
		}

		if info.IsDir() {
			return mcp.NewToolResultError("target path is a directory, not a file"), nil
		}

		if info.Size() > MaxReadFileBytes {
			return mcp.NewToolResultError(fmt.Sprintf("file size (%d bytes) exceeds max read limit (%d bytes)", info.Size(), MaxReadFileBytes)), nil
		}

		content, err := os.ReadFile(targetPath)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to read file: %v", err)), nil
		}

		gateMgr.AddAudit(gate.AuditEntry{
			Timestamp:  time.Now(),
			ClientIP:   ip,
			Country:    country,
			ToolName:   "read_file",
			DurationMs: time.Since(start).Milliseconds(),
			Status:     "SUCCESS",
			Message:    fmt.Sprintf("Read %s (%d bytes)", relPath, len(content)),
		})

		return mcp.NewToolResultText(string(content)), nil
	})

	// 2. write_file
	writeTool := mcp.NewTool("write_file",
		mcp.WithDescription("Write or replace file content in workspace"),
		mcp.WithString("path", mcp.Required(), mcp.Description("File path relative to workspace root")),
		mcp.WithString("content", mcp.Required(), mcp.Description("Content to write into the file")),
		mcp.WithString("lease_token", mcp.Description("Dynamic 2FA lease token acquired from unlock_gate")),
	)

	s.AddTool(writeTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		ip, country := resolveHeaderIP(request.Header)
		leaseToken := request.GetString("lease_token", "")

		// Gate & Lease check
		if allowed, gateMsg := gateMgr.ValidateLease(leaseToken); !allowed {
			gateMgr.AddAudit(gate.AuditEntry{
				Timestamp:  time.Now(),
				ClientIP:   ip,
				Country:    country,
				ToolName:   "write_file",
				DurationMs: 0,
				Status:     "LOCKED",
				Message:    gateMsg,
			})
			return mcp.NewToolResultError(gateMsg), nil
		}

		relPath, err := request.RequireString("path")
		if err != nil || relPath == "" {
			return mcp.NewToolResultError("argument 'path' is required"), nil
		}

		content, err := request.RequireString("content")
		if err != nil {
			return mcp.NewToolResultError("argument 'content' is required"), nil
		}

		targetPath, err := security.SafePath(workspaceRoot, relPath)
		if err != nil {
			gateMgr.AddAudit(gate.AuditEntry{
				Timestamp:  time.Now(),
				ClientIP:   ip,
				Country:    country,
				ToolName:   "write_file",
				DurationMs: time.Since(start).Milliseconds(),
				Status:     "ERROR",
				Message:    "Path traversal denied",
			})
			return mcp.NewToolResultError(fmt.Sprintf("security violation: %v", err)), nil
		}

		// Ensure parent directory exists
		parentDir := filepath.Dir(targetPath)
		if err := os.MkdirAll(parentDir, 0755); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to create directory structure: %v", err)), nil
		}

		if err := os.WriteFile(targetPath, []byte(content), 0644); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to write file: %v", err)), nil
		}

		gateMgr.AddAudit(gate.AuditEntry{
			Timestamp:  time.Now(),
			ClientIP:   ip,
			Country:    country,
			ToolName:   "write_file",
			DurationMs: time.Since(start).Milliseconds(),
			Status:     "SUCCESS",
			Message:    fmt.Sprintf("Wrote %s (%d bytes)", relPath, len(content)),
		})

		return mcp.NewToolResultText(fmt.Sprintf("successfully wrote %d bytes to %s", len(content), relPath)), nil
	})

	// 3. list_dir
	listTool := mcp.NewTool("list_dir",
		mcp.WithDescription("List contents of a directory within workspace"),
		mcp.WithString("path", mcp.Description("Directory path relative to workspace root (defaults to workspace root if empty)")),
		mcp.WithString("lease_token", mcp.Description("Dynamic 2FA lease token acquired from unlock_gate")),
	)

	s.AddTool(listTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		ip, country := resolveHeaderIP(request.Header)
		leaseToken := request.GetString("lease_token", "")

		// Gate & Lease check
		if allowed, gateMsg := gateMgr.ValidateLease(leaseToken); !allowed {
			gateMgr.AddAudit(gate.AuditEntry{
				Timestamp:  time.Now(),
				ClientIP:   ip,
				Country:    country,
				ToolName:   "list_dir",
				DurationMs: 0,
				Status:     "LOCKED",
				Message:    gateMsg,
			})
			return mcp.NewToolResultError(gateMsg), nil
		}

		relPath := request.GetString("path", "")

		targetPath, err := security.SafePath(workspaceRoot, relPath)
		if err != nil {
			gateMgr.AddAudit(gate.AuditEntry{
				Timestamp:  time.Now(),
				ClientIP:   ip,
				Country:    country,
				ToolName:   "list_dir",
				DurationMs: time.Since(start).Milliseconds(),
				Status:     "ERROR",
				Message:    "Path traversal denied",
			})
			return mcp.NewToolResultError(fmt.Sprintf("security violation: %v", err)), nil
		}

		entries, err := os.ReadDir(targetPath)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to read directory: %v", err)), nil
		}

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Directory listing for: %s\n\n", relPath))
		sb.WriteString(fmt.Sprintf("%-30s %-10s %-12s %s\n", "NAME", "TYPE", "SIZE", "MODIFIED"))
		sb.WriteString(strings.Repeat("-", 70) + "\n")

		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				continue
			}

			entryType := "FILE"
			sizeStr := fmt.Sprintf("%d B", info.Size())
			if entry.IsDir() {
				entryType = "DIR"
				sizeStr = "-"
			}

			sb.WriteString(fmt.Sprintf("%-30s %-10s %-12s %s\n",
				entry.Name(), entryType, sizeStr, info.ModTime().Format("2006-01-02 15:04:05")))
		}

		gateMgr.AddAudit(gate.AuditEntry{
			Timestamp:  time.Now(),
			ClientIP:   ip,
			Country:    country,
			ToolName:   "list_dir",
			DurationMs: time.Since(start).Milliseconds(),
			Status:     "SUCCESS",
			Message:    fmt.Sprintf("Listed %s (%d entries)", relPath, len(entries)),
		})

		return mcp.NewToolResultText(sb.String()), nil
	})
}
