package tools

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/Syntheticlight/2cfa-mcp/internal/gate"
)

var startTime = time.Now()

// RegisterSysInfoTool registers system_status and system_info tools to MCP server.
// System info is harmless read-only telemetry and NEVER requires 2FA or lease_token.
func RegisterSysInfoTool(s *server.MCPServer, gateMgr *gate.Manager) {
	handler := func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		ip, country := resolveHeaderIP(request.Header)

		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		uptime := time.Since(startTime).Truncate(time.Second)
		gateState := gateMgr.GetState()

		var sb strings.Builder
		sb.WriteString("=== System & Runtime Information ===\n")
		sb.WriteString(fmt.Sprintf("OS / Architecture: %s / %s\n", runtime.GOOS, runtime.GOARCH))
		sb.WriteString(fmt.Sprintf("Logical CPUs:      %d\n", runtime.NumCPU()))
		sb.WriteString(fmt.Sprintf("Active Goroutines: %d\n", runtime.NumGoroutine()))
		sb.WriteString(fmt.Sprintf("Server Uptime:     %s\n\n", uptime))

		sb.WriteString("=== Memory Metrics (Process) ===\n")
		sb.WriteString(fmt.Sprintf("Allocated RAM:     %.2f MB\n", float64(m.Alloc)/1024/1024))
		sb.WriteString(fmt.Sprintf("Total Sys RAM:     %.2f MB\n", float64(m.Sys)/1024/1024))
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
		mcp.WithDescription("Get system hardware load (CPU, RAM) and 2FA gate status. Harmless read-only tool."),
	)
	s.AddTool(toolStatus, handler)

	toolInfo := mcp.NewTool("system_info",
		mcp.WithDescription("Alias for system_status"),
	)
	s.AddTool(toolInfo, handler)
}