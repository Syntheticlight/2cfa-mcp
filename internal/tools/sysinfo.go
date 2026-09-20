package tools

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/Syntheticlight/2cfa-mcp/internal/gate"
	"github.com/Syntheticlight/2cfa-mcp/internal/updater"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var startTime = time.Now()

// RegisterSysInfoTool registers system_status, system_info, and check_update tools to MCP server.
// System info and update checks are harmless read-only telemetry and NEVER require 2FA or lease_token.
func RegisterSysInfoTool(s *server.MCPServer, gateMgr *gate.Manager) {
	statusHandler := func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		ip, country := resolveHeaderIP(request.Header)

		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		uptime := time.Since(startTime).Truncate(time.Second)
		gateState := gateMgr.GetState()
		upInfo := updater.GetInfo()

		var sb strings.Builder
		sb.WriteString("=== Version & Update Information ===\n")
		sb.WriteString(fmt.Sprintf("Server Version:    %s\n", updater.CurrentVersion))
		if upInfo.HasUpdate {
			sb.WriteString(fmt.Sprintf("Update Available:  YES (🚀 %s)\n", upInfo.LatestVersion))
			sb.WriteString(fmt.Sprintf("Release URL:       %s\n\n", upInfo.ReleaseURL))
		} else {
			sb.WriteString("Update Available:  Up to date (✅)\n\n")
		}

		sb.WriteString("=== System & Runtime Information ===\n")
		sb.WriteString(fmt.Sprintf("OS / Architecture: %s / %s\n", runtime.GOOS, runtime.GOARCH))
		sb.WriteString(fmt.Sprintf("Logical CPUs:      %d\n", runtime.NumCPU()))
		sb.WriteString(fmt.Sprintf("Active Goroutines: %d\n", runtime.NumGoroutine()))
		sb.WriteString(fmt.Sprintf("Server Uptime:     %s\n\n", uptime))

		sb.WriteString("=== Memory Metrics (Process) ===\n")
		sb.WriteString(fmt.Sprintf("Allocated RAM:     %.2f MB\n", float64(m.Alloc)/1024/1024))
		sb.WriteString(fmt.Sprintf("Go Runtime Sys:    %.2f MB\n", float64(m.Sys)/1024/1024))
		sb.WriteString(fmt.Sprintf("Heap Allocated:    %.2f MB\n", float64(m.HeapAlloc)/1024/1024))
		sb.WriteString(fmt.Sprintf("GC Cycles:         %d\n\n", m.NumGC))

		sb.WriteString("=== 2FA Security Gate ===\n")
		if !gateState.Enabled {
			sb.WriteString("Status:            DISABLED (Default Token-only Direct Connect - 100% Unrestricted)\n")
		} else if gateState.Status == "UNLOCKED" {
			sb.WriteString("Status:            OPEN & ACTIVE\n")
			sb.WriteString(fmt.Sprintf("Active Leases:     %d\n", gateState.ActiveLeasesCount))
		} else {
			sb.WriteString("Status:            LOCKED (Call unlock_gate with Google Authenticator code)\n")
		}

		gateMgr.AddAudit(gate.AuditEntry{
			Timestamp:  time.Now(),
			ClientIP:   ip,
			Country:    country,
			ToolName:   "system_status",
			DurationMs: time.Since(start).Milliseconds(),
			Status:     "SUCCESS",
			Message:    "Retrieved system and gate status",
		})

		return mcp.NewToolResultText(sb.String()), nil
	}

	toolStatus := mcp.NewTool("system_status",
		mcp.WithDescription("Get system hardware load (CPU, RAM), 2FA gate status, and version update information. Harmless read-only tool."),
	)
	s.AddTool(toolStatus, statusHandler)

	toolInfo := mcp.NewTool("system_info",
		mcp.WithDescription("Alias for system_status"),
	)
	s.AddTool(toolInfo, statusHandler)

	// check_update tool: allows on-demand update checks directly via chat
	checkUpdateTool := mcp.NewTool("check_update",
		mcp.WithDescription("Check GitHub for the latest 2cfa-mcp release and compare with current version. Harmless read-only tool."),
		mcp.WithBoolean("force", mcp.Description("Optional. Set true to bypass cache and check GitHub API immediately")),
	)
	s.AddTool(checkUpdateTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		force := request.GetBool("force", false)
		info := updater.Check(ctx, force)

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Current Version: %s\n", info.CurrentVersion))
		sb.WriteString(fmt.Sprintf("Latest Release:  %s\n", info.LatestVersion))
		if info.HasUpdate {
			sb.WriteString(fmt.Sprintf("Status: 🚀 New version available!\nRelease URL: %s\n", info.ReleaseURL))
			sb.WriteString("To update on Linux/Termux, run: ./scripts/daemon.sh update\n")
		} else {
			sb.WriteString("Status: ✅ You are running the latest version.\n")
		}
		if info.CheckError != "" {
			sb.WriteString(fmt.Sprintf("Notice: %s\n", info.CheckError))
		}
		return mcp.NewToolResultText(sb.String()), nil
	})
}
