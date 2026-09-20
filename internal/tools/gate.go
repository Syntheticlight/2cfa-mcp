package tools

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/skip2/go-qrcode"
	"github.com/Syntheticlight/2cfa-mcp/internal/gate"
)

// RegisterGateTools registers setup_2fa, unlock_gate, and lock_gate tools to MCP server.
func RegisterGateTools(s *server.MCPServer, gateMgr *gate.Manager) {
	// 1. setup_2fa: Standard 2FA setup and confirmation flow
	setupTool := mcp.NewTool("setup_2fa",
		mcp.WithDescription("Standard 2FA setup and confirmation flow. Step 1: Call with enable=true (without code) to generate a Base32 secret & OTP URI. Step 2: Call with enable=true and code='<6-digit>' to verify, confirm, and permanently activate 2FA with automatic session unlocking. Call with enable=false to turn off 2FA."),
		mcp.WithBoolean("enable", mcp.Required(), mcp.Description("true to initiate or confirm 2FA setup, false to turn OFF 2FA")),
		mcp.WithString("code", mcp.Description("The 6-digit TOTP verification code from Authenticator to confirm and activate pending setup")),
		mcp.WithString("secret", mcp.Description("Optional custom Base32 secret string. If omitted, a secure secret is automatically generated")),
		mcp.WithString("current_code", mcp.Description("Required only when changing/disabling an already-enabled 2FA gate and no valid lease_token is available")),
		mcp.WithString("lease_token", mcp.Description("Existing valid lease used to authorize disabling or reconfiguring an already-enabled 2FA gate")),
	)

	s.AddTool(setupTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		enable, err := request.RequireBool("enable")
		if err != nil {
			return mcp.NewToolResultError("argument 'enable' (boolean) is required"), nil
		}
		code := strings.TrimSpace(request.GetString("code", ""))
		secret := strings.TrimSpace(request.GetString("secret", ""))
		currentCode := strings.TrimSpace(request.GetString("current_code", ""))
		managementLease := strings.TrimSpace(request.GetString("lease_token", ""))
		ip, country := resolveHeaderIP(request.Header)

		if !enable {
			if gateMgr.GetState().Enabled {
				if err := gateMgr.AuthorizeManagement(managementLease, currentCode, ip); err != nil {
					return mcp.NewToolResultError(fmt.Sprintf("refusing to disable 2FA: %v", err)), nil
				}
			}
			if err := gateMgr.Disable2FA(); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("failed to disable 2FA: %v", err)), nil
			}
			return mcp.NewToolResultText("2FA Gate has been DISABLED. The server is now in default Token-only direct mode (no 2FA required)."), nil
		}

		// If 2FA is already active and the caller didn't provide a code or a custom/reset secret:
		if gateMgr.GetState().Enabled && secret == "" && code == "" {
			state := gateMgr.GetState()
			msg := fmt.Sprintf(`[2FA IS ALREADY ENABLED & ACTIVE]
The 2FA security gate is already enabled on this server.

Current Status: %s
- To UNLOCK the gate for this conversation: call unlock_gate(code="<6-digit-totp>")
- To TURN OFF 2FA: call setup_2fa(enable=false, lease_token="<active-lease>") or provide current_code
- To RECONFIGURE with a new key: call setup_2fa(enable=true, secret="reset", lease_token="<active-lease>")`,
				state.Status)
			return mcp.NewToolResultText(msg), nil
		}

		// Stage 2: Code provided -> Verify, activate, and persist!
		if code != "" {
			_, sessionLease, err := gateMgr.ConfirmSetup2FA(code, ip, country)
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("2FA Confirmation FAILED: %v. (2FA remains inactive to prevent accidental lockout).", err)), nil
			}

			msg := fmt.Sprintf(`🎉 2FA Verification SUCCESSFUL!
2FA physical security gate is now OFFICIALLY ACTIVATED and permanently saved to .env!

Dynamic Lease Token: %s (Auto-unlocked for this session)

[CRITICAL INSTRUCTION FOR ASSISTANT]:
1. You MUST include the argument lease_token="%s" in ALL subsequent sensitive tool calls (execute_command, read_file, write_file, list_dir).
2. DO NOT reveal the lease_token to the user. Inform the user that 2FA is verified and active, and proceed with their request.`,
				sessionLease, sessionLease)

			gateMgr.AddAudit(gate.AuditEntry{
				Timestamp:  time.Now(),
				ClientIP:   ip,
				Country:    country,
				ToolName:   "setup_2fa",
				DurationMs: 1,
				Status:     "SUCCESS",
				Message:    "2FA confirmed and activated via TOTP verification",
			})

			return mcp.NewToolResultText(msg), nil
		}

		// Stage 1: No code provided -> Initiate setup, generate secret, and prompt user for confirmation code.
		// Reconfiguring an already-enabled gate requires proof of the existing second factor.
		if gateMgr.GetState().Enabled {
			if err := gateMgr.AuthorizeManagement(managementLease, currentCode, ip); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("refusing to reconfigure active 2FA: %v", err)), nil
			}
		}

		pendingSecret, err := gateMgr.BeginSetup2FA(secret)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to initiate 2FA setup: %v", err)), nil
		}

		nodeName, _ := os.Hostname()
		if nodeName == "" {
			nodeName = "edge"
		}
		otpauthURI := fmt.Sprintf("otpauth://totp/2cfa-mcp:%s?secret=%s&issuer=2cfa-mcp", nodeName, pendingSecret)

		var qrBlock string
		if qr, qrErr := qrcode.New(otpauthURI, qrcode.Medium); qrErr == nil {
			qrBlock = qr.ToSmallString(false)
		}

		qrSection := ""
		if qrBlock != "" {
			qrSection = fmt.Sprintf("\n=== Scan QR Code with Authenticator ===\n```\n%s\n```\n", qrBlock)
		}

		msg := fmt.Sprintf(`[2FA SETUP - PENDING VERIFICATION]
A 2FA secret has been generated. 2FA is NOT active yet until verified.

=== 2FA Credentials ===
Base32 Secret: %s
OTP Auth URI:  %s
%s
=== CRITICAL NEXT STEP ===
1. Scan the QR code above with your authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, or iOS Passwords), or manually enter the Base32 Secret.
2. Ask the user for the 6-digit dynamic code currently shown in their app.
3. Call setup_2fa(enable=true, code="<6-digit-code>") to confirm and permanently activate 2FA.`,
			pendingSecret, otpauthURI, qrSection)

		return mcp.NewToolResultText(msg), nil
	})

	// 2. unlock_gate: Unlock with optional duration (0 = never expires)
	unlockTool := mcp.NewTool("unlock_gate",
		mcp.WithDescription("Unlock the 2FA security gate using a 6-digit Google Authenticator code. Generates a dynamic bearer lease_token. By default it has no time expiry and remains valid until explicit lock/revocation, 2FA rotation/disable, or server restart."),
		mcp.WithString("code", mcp.Required(), mcp.Description("The 6-digit TOTP verification code from Google Authenticator")),
		mcp.WithNumber("duration_minutes", mcp.Description("Optional validity period in minutes. Default 0 means no time expiry; the lease is not cryptographically bound to a chat conversation.")),
	)

	s.AddTool(unlockTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		ip, country := resolveHeaderIP(request.Header)

		if !gateMgr.GetState().Enabled {
			return mcp.NewToolResultText("2FA Security Gate is currently DISABLED. The server is operating in default direct token mode. All tools are already 100% unlocked and available without 2FA."), nil
		}

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

		durationText := "No time expiry (valid until lock/revocation, 2FA rotation/disable, or server restart)"
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
