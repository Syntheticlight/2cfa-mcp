package main

import (
	"context"
	"flag"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestStartupFailureExits(t *testing.T) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_SERVER_PORT", port)
	t.Setenv("AUTH_TOKEN", "test-startup-token")
	t.Setenv("ENABLE_2FA_GATE", "false")
	t.Setenv("WORKSPACE_PATH", t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStartupHelper$")
	cmd.Dir = t.TempDir()
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("server stayed alive after bind failure: %s", output)
	}
	if err == nil || !strings.Contains(string(output), "HTTP server failed") {
		t.Fatalf("expected nonzero exit on bind failure: %v, %s", err, output)
	}
}

func TestStartupHelper(t *testing.T) {
	port := os.Getenv("TEST_SERVER_PORT")
	if port == "" {
		return
	}
	flag.CommandLine = flag.NewFlagSet("server", flag.ExitOnError)
	os.Args = []string{"server", "-port=" + port}
	main()
}
