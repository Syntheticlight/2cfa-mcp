package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Syntheticlight/2cfa-mcp/internal/server"
)

func main() {
	// Parse CLI flags and environment variables
	portFlag := flag.Int("port", getEnvInt("PORT", 2232), "Server listening port")
	tokenFlag := flag.String("token", os.Getenv("AUTH_TOKEN"), "Secret authentication token")
	workspaceFlag := flag.String("workspace", getEnvStr("WORKSPACE_PATH", "."), "Allowed workspace directory")
	timeoutFlag := flag.Int("timeout", getEnvInt("EXEC_TIMEOUT", 120), "Default execution timeout in seconds")

	// 2FA Gate flags (Defaults to false for zero-friction direct token connect)
	enable2FAFlag := flag.Bool("2fa", getEnvBool("ENABLE_2FA_GATE", false), "Enable 2FA Gate physical protection (false by default)")
	totpSecretFlag := flag.String("totp-secret", getEnvStr("TOTP_SECRET", ""), "Base32 TOTP secret for Google Authenticator")

	flag.Parse()

	if *tokenFlag == "" {
		log.Fatalf("[FATAL] AUTH_TOKEN must be set via env or -token flag for security!")
	}

	cfg := server.ServerConfig{
		Port:          *portFlag,
		AuthToken:     *tokenFlag,
		WorkspacePath: *workspaceFlag,
		ExecTimeout:   time.Duration(*timeoutFlag) * time.Second,
		Enable2FAGate: *enable2FAFlag,
		TOTPSecret:    *totpSecretFlag,
	}

	srv, err := server.NewServer(cfg)
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize 2cfa-mcp Server: %v", err)
	}

	// Channel for signal handling
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := srv.Start(); err != nil {
			log.Printf("[INFO] Server stopped: %v", err)
		}
	}()

	fmt.Println("==========================================================================")
	fmt.Println("                  2cfa-mcp - Go Remote MCP Server                           ")
	fmt.Println("==========================================================================")
	fmt.Printf(" Listening Port:  :%d\n", cfg.Port)
	fmt.Printf(" Workspace Path:  %s\n", cfg.WorkspacePath)
	fmt.Printf(" Health Endpoint: http://localhost:%d/health\n", cfg.Port)
	if cfg.Enable2FAGate {
		fmt.Println(" 2FA Protection:  ENABLED (Unlock via in-chat 'unlock_gate' or /gate)")
	} else {
		fmt.Println(" 2FA Protection:  DISABLED (Default Token-only Direct Connection)")
	}
	fmt.Println(" Zero-Leakage:    Enabled (Strict secret masking in logs & /health)")
	fmt.Println("==========================================================================")

	<-stopChan
	log.Println("[INFO] Interrupt signal received, initiating graceful shutdown...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[ERROR] Shutdown error: %v", err)
	} else {
		log.Println("[INFO] 2cfa-mcp Server stopped cleanly.")
	}
}

func getEnvStr(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	if val := os.Getenv(key); val != "" {
		v := strings.ToLower(val)
		return v == "true" || v == "1" || v == "yes" || v == "on"
	}
	return defaultVal
}
