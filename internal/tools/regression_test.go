package tools

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Syntheticlight/2cfa-mcp/internal/gate"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func TestFileToolsRejectSymlinkEscapes(t *testing.T) {
	workspace, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "existing.txt"), []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{
		"existing":  filepath.Join(outside, "existing.txt"),
		"dangling":  filepath.Join(outside, "new.txt"),
		"directory": outside,
	} {
		if err := os.Symlink(target, filepath.Join(workspace, name)); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("symlink privilege unavailable: %v", err)
			}
			t.Fatal(err)
		}
	}
	s := server.NewMCPServer("test", "1")
	RegisterFileTools(s, workspace, gate.NewManager(gate.Config{}))
	for _, tc := range []struct{ tool, path string }{
		{"read_file", "existing"}, {"write_file", "existing"},
		{"write_file", "dangling"}, {"write_file", "directory/new/sub/file.txt"},
		{"list_dir", "directory"},
	} {
		t.Run(tc.tool+"/"+tc.path, func(t *testing.T) {
			req := mcp.CallToolRequest{}
			req.Params.Arguments = map[string]any{"path": tc.path, "content": "overwritten"}
			res, err := s.GetTool(tc.tool).Handler(context.Background(), req)
			if err != nil || !res.IsError {
				t.Fatalf("escape was not rejected: %v, %+v", err, res)
			}
		})
	}
	data, err := os.ReadFile(filepath.Join(outside, "existing.txt"))
	if err != nil || string(data) != "private" {
		t.Fatalf("outside file changed: %q, %v", data, err)
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 1 {
		t.Fatalf("outside files created: %v, %v", entries, err)
	}
}

func TestCommandTimeoutReturnsStructuredPartialOutput(t *testing.T) {
	command := "echo partial; sleep 10"
	if runtime.GOOS == "windows" {
		command = "echo partial & ping -n 11 127.0.0.1 >nul"
	}
	s := server.NewMCPServer("test", "1")
	RegisterCommandTool(s, t.TempDir(), time.Second, gate.NewManager(gate.Config{}))
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"command": command}
	res, err := s.GetTool("execute_command").Handler(context.Background(), req)
	if err != nil || !res.IsError {
		t.Fatalf("expected timeout error: %v, %+v", err, res)
	}
	out, ok := res.StructuredContent.(CommandOutput)
	if !ok || !out.TimedOut || out.Success || !strings.Contains(out.Stdout, "partial") {
		t.Fatalf("missing structured timeout/partial output: %#v", res.StructuredContent)
	}
}

func TestUnlockRejectsInvalidDurations(t *testing.T) {
	s := server.NewMCPServer("test", "1")
	secret := "JBSWY3DPEHPK3PXP"
	RegisterGateTools(s, gate.NewManager(gate.Config{Enabled: true, TOTPSecret: secret}))
	code, err := gate.GenerateCurrentTOTP(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []float64{-1, 0.5, 525601, 1e30} {
		req := mcp.CallToolRequest{}
		req.Params.Arguments = map[string]any{"code": code, "duration_minutes": value}
		res, err := s.GetTool("unlock_gate").Handler(context.Background(), req)
		if err != nil || !res.IsError || !strings.Contains(res.Content[0].(mcp.TextContent).Text, "duration_minutes") {
			t.Fatalf("invalid duration %v accepted or consumed code: %v, %+v", value, err, res)
		}
	}
	// Rejected arguments must not consume the valid TOTP.
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"code": code, "duration_minutes": 1}
	res, err := s.GetTool("unlock_gate").Handler(context.Background(), req)
	if err != nil || res.IsError {
		t.Fatalf("valid timed lease failed: %v, %+v", err, res)
	}
}
