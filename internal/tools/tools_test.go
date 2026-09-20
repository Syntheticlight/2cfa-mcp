package tools

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/Syntheticlight/2cfa-mcp/internal/gate"
)

func TestFullConversational2FAWorkflow(t *testing.T) {
	tmpDir := t.TempDir()
	secret := "JBSWY3DPEHPK3PXP"

	// 1. Start with default Token-only mode (2FA disabled)
	gateMgr := gate.NewManager(gate.Config{
		Enabled: false,
	})

	mcpSrv := server.NewMCPServer("test", "1.0.0")
	RegisterGateTools(mcpSrv, gateMgr)
	RegisterCommandTool(mcpSrv, tmpDir, 5*time.Second, gateMgr)
	RegisterFileTools(mcpSrv, tmpDir, gateMgr)
	RegisterSysInfoTool(mcpSrv, gateMgr)

	cmdTool := mcpSrv.GetTool("execute_command")
	setupTool := mcpSrv.GetTool("setup_2fa")
	unlockTool := mcpSrv.GetTool("unlock_gate")
	lockTool := mcpSrv.GetTool("lock_gate")

	// Phase A: Direct connection (no 2FA required)
	req := mcp.CallToolRequest{}
	req.Params.Name = "execute_command"
	req.Params.Arguments = map[string]any{"command": "echo default_direct_connect"}

	res, err := cmdTool.Handler(context.Background(), req)
	if err != nil || res.IsError {
		t.Fatalf("expected direct connect to succeed by default, got: %+v", res)
	}
	if !strings.Contains(res.Content[0].(mcp.TextContent).Text, "default_direct_connect") {
		t.Errorf("unexpected output: %+v", res)
	}

	// Phase B: Enable 2FA dynamically via setup_2fa
	setupReq := mcp.CallToolRequest{}
	setupReq.Params.Name = "setup_2fa"
	setupReq.Params.Arguments = map[string]any{
		"enable": true,
		"secret": secret,
	}

	setupRes, err := setupTool.Handler(context.Background(), setupReq)
	if err != nil || setupRes.IsError {
		t.Fatalf("setup_2fa failed: %v", err)
	}

	// Now execute_command should be BLOCKED because 2FA is on and no lease provided
	resBlocked, err := cmdTool.Handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if !resBlocked.IsError {
		t.Errorf("expected command to be blocked once 2FA is enabled")
	}

	// Phase C: Unlock via unlock_gate (default duration = 0, permanent for conversation)
	validCode, err := generateTestTOTP(secret)
	if err != nil {
		t.Fatalf("failed to generate totp: %v", err)
	}

	unlockReq := mcp.CallToolRequest{}
	unlockReq.Params.Name = "unlock_gate"
	unlockReq.Params.Arguments = map[string]any{
		"code": validCode,
	}

	unlockRes, err := unlockTool.Handler(context.Background(), unlockReq)
	if err != nil || unlockRes.IsError {
		t.Fatalf("unlock_gate failed: %v, res: %+v", err, unlockRes)
	}

	unlockText := unlockRes.Content[0].(mcp.TextContent).Text
	leaseToken := extractLeaseToken(unlockText)
	if leaseToken == "" {
		t.Fatalf("failed to extract lease token from: %s", unlockText)
	}

	// Phase D: Call tool with dynamic lease_token -> SUCCESS
	reqWithLease := mcp.CallToolRequest{}
	reqWithLease.Params.Name = "execute_command"
	reqWithLease.Params.Arguments = map[string]any{
		"command":     "echo 2fa_unlocked_success",
		"lease_token": leaseToken,
	}

	resWithLease, err := cmdTool.Handler(context.Background(), reqWithLease)
	if err != nil || resWithLease.IsError {
		t.Fatalf("execute_command with lease failed: %v", err)
	}
	if !strings.Contains(resWithLease.Content[0].(mcp.TextContent).Text, "2fa_unlocked_success") {
		t.Errorf("unexpected output: %+v", resWithLease)
	}

	// Phase E: Lock gate via lock_gate -> BLOCKED again
	lockReq := mcp.CallToolRequest{}
	lockReq.Params.Name = "lock_gate"
	lockReq.Params.Arguments = map[string]any{}

	_, _ = lockTool.Handler(context.Background(), lockReq)

	resAfterLock, _ := cmdTool.Handler(context.Background(), reqWithLease)
	if !resAfterLock.IsError {
		t.Errorf("expected command to be blocked after lock_gate")
	}

	// Phase F: Disable 2FA via setup_2fa -> back to direct connect
	setupReqDisable := mcp.CallToolRequest{}
	setupReqDisable.Params.Name = "setup_2fa"
	setupReqDisable.Params.Arguments = map[string]any{
		"enable": false,
	}
	_, _ = setupTool.Handler(context.Background(), setupReqDisable)

	resDisabled, _ := cmdTool.Handler(context.Background(), req)
	if resDisabled.IsError {
		t.Errorf("expected command to succeed directly when 2FA is disabled")
	}
}

func generateTestTOTP(secret string) (string, error) {
	return gate.GenerateCurrentTOTP(secret, time.Now())
}

func extractLeaseToken(text string) string {
	idx := strings.Index(text, "lease_")
	if idx == -1 {
		return ""
	}
	sub := text[idx:]
	end := strings.IndexAny(sub, " \n\r\t")
	if end != -1 {
		return sub[:end]
	}
	return sub
}
