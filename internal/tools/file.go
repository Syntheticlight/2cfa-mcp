package tools

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Syntheticlight/2cfa-mcp/internal/gate"
	"github.com/Syntheticlight/2cfa-mcp/internal/security"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const (
	MaxReadFileBytes  = 10 * 1024 * 1024 // 10 MB limit for single file read
	MaxListDirEntries = 2000             // bound directory listing output and memory
)

// RegisterFileTools registers read_file, write_file, and list_dir tools to MCP server.
func RegisterFileTools(s *server.MCPServer, workspaceRoot string, gateMgr *gate.Manager) {
	// 1. read_file
	readTool := mcp.NewTool("read_file",
		mcp.WithDescription("Read file contents from workspace"),
		mcp.WithString("path", mcp.Required(), mcp.Description("File path relative to workspace root")),
		mcp.WithString("lease_token", mcp.Description("Optional. Leave empty in normal use. Only pass if 2FA gate was explicitly turned on")),
		mcp.WithOutputSchema[ReadFileOutput](),
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

		root, targetPath, err := security.OpenWorkspacePath(workspaceRoot, relPath)
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

		defer root.Close()
		file, err := root.Open(targetPath)
		if err != nil {
			if os.IsNotExist(err) {
				return mcp.NewToolResultError(fmt.Sprintf("file not found: %s", relPath)), nil
			}
			return mcp.NewToolResultError(fmt.Sprintf("failed to open file '%s': permission denied or read error", relPath)), nil
		}
		defer file.Close()

		info, err := file.Stat()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to stat file: %s", relPath)), nil
		}
		if info.IsDir() {
			return mcp.NewToolResultError("target path is a directory, not a file"), nil
		}
		if info.Size() > MaxReadFileBytes {
			return mcp.NewToolResultError(fmt.Sprintf("file size (%d bytes) exceeds max read limit (%d bytes)", info.Size(), MaxReadFileBytes)), nil
		}

		// The reader itself is also bounded. This closes the Stat -> ReadFile
		// race where another local process could grow the file after the size
		// check and force an unexpectedly large allocation.
		content, err := io.ReadAll(io.LimitReader(file, int64(MaxReadFileBytes)+1))
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to read file '%s': permission denied or read error", relPath)), nil
		}
		if len(content) > MaxReadFileBytes {
			return mcp.NewToolResultError(fmt.Sprintf("file exceeded max read limit (%d bytes) while being read", MaxReadFileBytes)), nil
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

		result := ReadFileOutput{
			Success: true,
			Path:    relPath,
			Content: string(content),
			Size:    len(content),
		}
		return mcp.NewToolResultStructured(result, string(content)), nil
	})

	// 2. write_file
	writeTool := mcp.NewTool("write_file",
		mcp.WithDescription("Write or replace file content in workspace"),
		mcp.WithString("path", mcp.Required(), mcp.Description("File path relative to workspace root")),
		mcp.WithString("content", mcp.Required(), mcp.Description("Content to write into the file")),
		mcp.WithString("lease_token", mcp.Description("Optional. Leave empty in normal use. Only pass if 2FA gate was explicitly turned on")),
		mcp.WithOutputSchema[WriteFileOutput](),
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

		root, targetPath, err := security.OpenWorkspacePath(workspaceRoot, relPath)
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

		defer root.Close()
		// Ensure parent directory exists
		parentDir := filepath.Dir(targetPath)
		if err := root.MkdirAll(parentDir, 0755); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to create directory structure for '%s'", relPath)), nil
		}

		if err := root.WriteFile(targetPath, []byte(content), 0644); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to write file '%s': permission denied or disk error", relPath)), nil
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

		result := WriteFileOutput{
			Success:      true,
			Path:         relPath,
			BytesWritten: len(content),
		}
		return mcp.NewToolResultStructured(result, fmt.Sprintf("successfully wrote %d bytes to %s", len(content), relPath)), nil
	})

	// 3. list_dir
	listTool := mcp.NewTool("list_dir",
		mcp.WithDescription("List contents of a directory within workspace"),
		mcp.WithString("path", mcp.Description("Directory path relative to workspace root (defaults to workspace root if empty)")),
		mcp.WithString("lease_token", mcp.Description("Optional. Leave empty in normal use. Only pass if 2FA gate was explicitly turned on")),
		mcp.WithOutputSchema[ListDirOutput](),
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

		root, targetPath, err := security.OpenWorkspacePath(workspaceRoot, relPath)
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

		defer root.Close()
		dir, err := root.Open(targetPath)
		if err != nil {
			if os.IsNotExist(err) {
				return mcp.NewToolResultError(fmt.Sprintf("directory not found: %s", relPath)), nil
			}
			return mcp.NewToolResultError(fmt.Sprintf("failed to open directory: %s", relPath)), nil
		}
		defer dir.Close()

		entries, err := dir.ReadDir(MaxListDirEntries + 1)
		if err != nil && err != io.EOF {
			return mcp.NewToolResultError(fmt.Sprintf("failed to read directory: %s", relPath)), nil
		}
		truncated := len(entries) > MaxListDirEntries
		if truncated {
			entries = entries[:MaxListDirEntries]
		}

		structuredEntries := make([]DirectoryEntry, 0, len(entries))

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
			entrySize := info.Size()
			sizeStr := fmt.Sprintf("%d B", entrySize)
			if entry.IsDir() {
				entryType = "DIR"
				entrySize = 0
				sizeStr = "-"
			}

			modified := info.ModTime().UTC().Format(time.RFC3339)
			structuredEntries = append(structuredEntries, DirectoryEntry{
				Name:     entry.Name(),
				Type:     entryType,
				Size:     entrySize,
				Modified: modified,
			})

			sb.WriteString(fmt.Sprintf("%-30s %-10s %-12s %s\n",
				entry.Name(), entryType, sizeStr, info.ModTime().Format("2006-01-02 15:04:05")))
		}
		if truncated {
			sb.WriteString(fmt.Sprintf("\n... [listing truncated after %d entries]\n", MaxListDirEntries))
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

		result := ListDirOutput{
			Success:   true,
			Path:      relPath,
			Entries:   structuredEntries,
			Count:     len(structuredEntries),
			Truncated: truncated,
		}
		return mcp.NewToolResultStructured(result, sb.String()), nil
	})
}
