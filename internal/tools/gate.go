package tools

import (
	"context"
	"fmt"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/Syntheticlight/2cfa-mcp/internal/gate"
)

// RegisterGateTools registers setup_2fa, unlock_gate, and lock_gate tools to MCP server.
func RegisterGateTools(s *server.MCPServer, gateMgr *gate.Manager) {
	// 1. setup_2fa: Configure 2FA in chat dynamically
	setupTool := mcp.NewTool("setup_2fa",
		mcp.WithDescription("Enable, disable, or configure 2FA Google Authenticator protection directly via chat conversation."),
		mcp.WithBoolean("enable", mcp.Required(), mcp.Description("true to turn ON 2FA physical gate, false to turn OFF (use token-only direct connect)")),
		mcp.WithString("secret", mcp.Description("Optional Base32 secret string (e.g. JBSWY3DPEHPK3PXP) for Google Authenticator")),
	)

	s.AddTool(setupTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		enable, err := request.RequireBool("enable")
		if err != nil {
			return mcp.NewToolResultError("argument 'enable' (boolean) is required"), nil
		}
		secret := request.GetString("secret", "")

		if enable && secret == "" && !gateMgr.HasSecret() {
			return mcp.NewToolResultError("Cannot enable 2FA: No TOTP secret provided and none currently configured. Please provide 'secret' (e.g. your Google Authenticator Base32 secret string like JBSWY3DPEHPK3PXP)."), nil
		}

		if err := gateMgr.Configure2FA(secret, enable); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to configure 2FA: %v. Please provide a valid Base32 secret (A-Z, 2-7).", err)), nil
		}

		if enable {
			return mcp.NewToolResultText("2FA Gate has been ENABLED. The server is now protected by Google Authenticator. Future tool calls will require unlocking via 'unlock_gate'."), nil
		}
		return mcp.NewToolResultText("2FA Gate has been DISABLED. The server is now in default Token-only direct mode (no 2FA required)."), nil
	})

	// 2. unlock_gate: Unlock with optional duration (0 = never expires)
	unlockTool := mcp.NewTool("unlock_gate",
		mcp.WithDescription("Unlock the 2FA security gate using a 6-digit Google Authenticator code. Generates a dynamic lease_token. Defaults to permanent (never expires) unless duration_minutes is specified."),
		mcp.WithString("code", mcp.Required(), mcp.Description("The 6-digit TOTP verification code from Google Authenticator")),
		mcp.WithNumber("duration_minutes", mcp.Description("Optional validity period in minutes. Default 0 means permanent (never expires for this conversation).")),
	)

	s.AddTool(unlockTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		ip, country := resolveHeaderIP(request.Header)

		code, err := request.RequireString("code")
		if err != nil || code == "" {
			return mcp.NewToolResultError("argument 'code' is required and must be a 6-digit string"), nil
		}

		durationMinutes := int(request.GetFloat("duration_minutes", 0))
		if durationMinutes < 0 {
			durationMinutes = 0
		} else if durationMinutes > 525600 {
			durationMinutes = 525600
		}

		token, err := gateMgr.CreateLease(code, durationMinutes, ip, country)
		duration := time.Since(start).Milliseconds()

		if err != nil {
			gateMgr.AddAudit(gate.AuditEntry{
				Timestamp:  time.Now(),
				ClientIP:   ip,
				Country:    country,
				ToolName:   "unlock_gate",
				DurationMs: duration,
				Status:     "ERROR",
				Message:    fmt.Sprintf("Unlock failed: %v", err),
			})
			return mcp.NewToolResultError(fmt.Sprintf("2FA Verification Failed: %v. Please check your Google Authenticator code and try again.", err)), nil
		}

		gateMgr.AddAudit(gate.AuditEntry{
			Timestamp:  time.Now(),
			ClientIP:   ip,
			Country:    country,
			ToolName:   "unlock_gate",
			DurationMs: duration,
			Status:     "SUCCESS",
			Message:    fmt.Sprintf("Lease token issued (duration: %d mins)", durationMinutes),
		})

		durationText := "Permanent (Never expires for this conversation)"
		if durationMinutes > 0 {
			durationText = fmt.Sprintf("Valid for %d minutes", durationMinutes)
		}

		msg := fmt.Sprintf(`2FA Verification SUCCESSFUL!
Security Gate is now OPEN.
Dynamic Lease Token: %s
Duration: %s

[CRITICAL INSTRUCTION FOR ASSISTANT]:
1. You MUST include the argument lease_token="%s" in ALL subsequent tool calls (e.g. execute_command, read_file, write_file, list_dir).
2. DO NOT reveal, print, or display this lease_token in your reply to the user. Keep your conversation clean and proceed with the user's request.`,
			token, durationText, token)

		return mcp.NewToolResultText(msg), nil
	})

	// 3. lock_gate: One-click lock
	lockTool := mcp.NewTool("lock_gate",
		mcp.WithDescription("Lock the 2FA security gate and revoke active lease tokens immediately."),
		mcp.WithString("lease_token", mcp.Description("Optional specific lease token to revoke")),
	)

	s.AddTool(lockTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		ip, country := resolveHeaderIP(request.Header)
		leaseToken := request.GetString("lease_token", "")

		if leaseToken != "" {
			gateMgr.RevokeLease(leaseToken)
		} else {
			gateMgr.Lock()
		}

		gateMgr.AddAudit(gate.AuditEntry{
			Timestamp:  time.Now(),
			ClientIP:   ip,
			Country:    country,
			ToolName:   "lock_gate",
			DurationMs: 1,
			Status:     "SUCCESS",
			Message:    "Gate locked",
		})

		return mcp.NewToolResultText("Security Gate has been LOCKED. Further tool executions will require 2FA verification."), nil
	})
}
