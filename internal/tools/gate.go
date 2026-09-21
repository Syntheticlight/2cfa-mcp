package tools

import (
	"context"
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/Syntheticlight/2cfa-mcp/internal/gate"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/skip2/go-qrcode"
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
		mcp.WithOutputSchema[Setup2FAOutput](),
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
		credentials := gate.ManagementCredentials{LeaseToken: managementLease, CurrentCode: currentCode, ClientIP: ip}

		if !enable {
			if err := gateMgr.Disable2FA(credentials); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("failed to disable 2FA: %v", err)), nil
			}
			message := "2FA Gate has been DISABLED. The server is now in default Token-only direct mode (no 2FA required)."
			result := Setup2FAOutput{
				Success: true,
				Action:  "disabled",
				Enabled: false,
				Status:  "DISABLED",
				Message: message,
			}
			return mcp.NewToolResultStructured(result, message), nil
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
			result := Setup2FAOutput{
				Success: true,
				Action:  "status",
				Enabled: true,
				Status:  state.Status,
				Message: "2FA is already enabled and active.",
			}
			return mcp.NewToolResultStructured(result, msg), nil
		}

		// Stage 2: Code provided -> Verify, activate, and persist!
		if code != "" {
			_, sessionLease, err := gateMgr.ConfirmSetup2FA(code, ip, country)
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("2FA Confirmation FAILED: %v. The existing 2FA configuration is unchanged.", err)), nil
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

			result := Setup2FAOutput{
				Success:    true,
				Action:     "activated",
				Enabled:    true,
				Status:     "UNLOCKED",
				Message:    "2FA verified, activated, and persisted.",
				LeaseToken: sessionLease,
			}
			return mcp.NewToolResultStructured(result, msg), nil
		}

		// Stage 1: No code provided -> Initiate setup, generate secret, and prompt user for confirmation code.
		pendingSecret, err := gateMgr.BeginSetup2FA(secret, credentials)
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

		state := gateMgr.GetState()
		result := Setup2FAOutput{
			Success:    true,
			Action:     "pending_verification",
			Enabled:    state.Enabled,
			Status:     state.Status,
			Message:    "2FA setup is pending verification with a 6-digit TOTP code.",
			Secret:     pendingSecret,
			OTPAuthURI: otpauthURI,
			QRCode:     qrBlock,
		}
		return mcp.NewToolResultStructured(result, msg), nil
	})

	// 2. unlock_gate: Unlock with optional duration (0 = never expires)
	unlockTool := mcp.NewTool("unlock_gate",
		mcp.WithDescription("Unlock the 2FA security gate using a 6-digit Google Authenticator code. Generates a dynamic bearer lease_token. By default it has no time expiry and remains valid until explicit lock/revocation, 2FA rotation/disable, or server restart."),
		mcp.WithString("code", mcp.Required(), mcp.Description("The 6-digit TOTP verification code from Google Authenticator")),
		mcp.WithNumber("duration_minutes", mcp.Description("Optional validity period in minutes. Default 0 means no time expiry; the lease is not cryptographically bound to a chat conversation.")),
		mcp.WithOutputSchema[UnlockGateOutput](),
	)

	s.AddTool(unlockTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		ip, country := resolveHeaderIP(request.Header)

		if !gateMgr.GetState().Enabled {
			message := "2FA Security Gate is currently DISABLED. The server is operating in default direct token mode. All tools are already 100% unlocked and available without 2FA."
			result := UnlockGateOutput{
				Success:         true,
				Enabled:         false,
				Status:          "DISABLED",
				DurationMinutes: 0,
				HasTimeExpiry:   false,
				Message:         message,
			}
			return mcp.NewToolResultStructured(result, message), nil
		}

		code, err := request.RequireString("code")
		if err != nil || code == "" {
			return mcp.NewToolResultError("argument 'code' is required and must be a 6-digit string"), nil
		}

		durationValue := request.GetFloat("duration_minutes", 0)
		if math.IsNaN(durationValue) || math.IsInf(durationValue, 0) || durationValue < 0 || durationValue > gate.MaxLeaseDurationMinutes || math.Trunc(durationValue) != durationValue {
			return mcp.NewToolResultError("duration_minutes must be a whole number between 0 and 525600; 0 means no time expiry"), nil
		}
		durationMinutes := int(durationValue)

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

		result := UnlockGateOutput{
			Success:         true,
			Enabled:         true,
			Status:          "UNLOCKED",
			LeaseToken:      token,
			DurationMinutes: durationMinutes,
			HasTimeExpiry:   durationMinutes > 0,
			Message:         "2FA verified and a dynamic lease token was issued.",
		}
		return mcp.NewToolResultStructured(result, msg), nil
	})

	// 3. lock_gate: One-click lock
	lockTool := mcp.NewTool("lock_gate",
		mcp.WithDescription("Lock the 2FA security gate and revoke active lease tokens immediately."),
		mcp.WithString("lease_token", mcp.Description("Optional specific lease token to revoke")),
		mcp.WithOutputSchema[LockGateOutput](),
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

		state := gateMgr.GetState()
		message := "Security Gate has been LOCKED. Further tool executions will require 2FA verification."
		if !state.Enabled {
			message = "All leases and pending setup have been revoked. 2FA is disabled; tools remain available in Token-only mode."
		}
		scope := "all_leases"
		if leaseToken != "" {
			scope = "specific_lease"
			message = "The requested lease token has been revoked."
		}
		result := LockGateOutput{
			Success: true,
			Status:  state.Status,
			Scope:   scope,
			Message: message,
		}
		return mcp.NewToolResultStructured(result, message), nil
	})
}
