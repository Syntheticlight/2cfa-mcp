package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Syntheticlight/2cfa-mcp/internal/server"
	"github.com/Syntheticlight/2cfa-mcp/internal/updater"
)

func init() {
	// Auto-inject Termux user bin into PATH on Android / Linux edge devices if present
	termuxBin := "/data/data/com.termux/files/usr/bin"
	if _, err := os.Stat(termuxBin); err == nil {
		path := os.Getenv("PATH")
		if !strings.Contains(path, termuxBin) {
			_ = os.Setenv("PATH", termuxBin+":"+path)
		}
	}
}

func main() {
	// Auto-load .env if present and set env vars not yet configured in OS
	envPath := loadDotEnv(".env", "../.env")

	// Parse non-secret CLI flags. Secrets are intentionally accepted only
	// through the process environment/.env so they never appear in argv.
	portFlag := flag.Int("port", getEnvInt("PORT", 2232), "Server listening port")
	workspaceFlag := flag.String("workspace", getEnvStr("WORKSPACE_PATH", "."), "Allowed workspace directory")
	timeoutFlag := flag.Int("timeout", getEnvInt("EXEC_TIMEOUT", 120), "Default execution timeout in seconds")
	enable2FAFlag := flag.Bool("2fa", getEnvBool("ENABLE_2FA_GATE", false), "Enable 2FA Gate physical protection (false by default)")

	flag.Parse()

	authToken := os.Getenv("AUTH_TOKEN")
	totpSecret := getEnvStr("TOTP_SECRET", "")

	if err := validateSecurityConfig(authToken, *enable2FAFlag, totpSecret); err != nil {
		log.Fatalf("[FATAL] %v", err)
	}

	cfg := server.ServerConfig{
		Port:          *portFlag,
		AuthToken:     authToken,
		WorkspacePath: *workspaceFlag,
		ExecTimeout:   time.Duration(*timeoutFlag) * time.Second,
		Enable2FAGate: *enable2FAFlag,
		TOTPSecret:    totpSecret,
		EnvPath:       envPath,
	}

	srv, err := server.NewServer(cfg)
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize 2cfa-mcp Server: %v", err)
	}

	// Channel for signal handling
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stopChan)

	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- srv.Start()
	}()

	// Non-blocking auto-check for updates from GitHub Releases
	updater.StartBackgroundChecker()

	fmt.Println("==========================================================================")
	fmt.Println("                  2cfa-mcp - Go Remote MCP Server                           ")
	fmt.Println("==========================================================================")
	fmt.Printf(" Version:         %s\n", updater.CurrentVersion)
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

	select {
	case err := <-serverErrors:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] HTTP server failed: %v", err)
		}
		return
	case <-stopChan:
	}
	log.Println("[INFO] Interrupt signal received, initiating graceful shutdown...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[ERROR] Shutdown error: %v", err)
	} else {
		log.Println("[INFO] 2cfa-mcp Server stopped cleanly.")
	}
}

func validateSecurityConfig(authToken string, enable2FA bool, totpSecret string) error {
	if authToken == "" {
		return fmt.Errorf("AUTH_TOKEN must be set via environment or .env")
	}
	if enable2FA && strings.TrimSpace(totpSecret) == "" {
		return fmt.Errorf("ENABLE_2FA_GATE=true requires TOTP_SECRET; disable 2FA or configure a valid TOTP secret before startup")
	}
	return nil
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

func loadDotEnv(paths ...string) string {
	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			// Best-effort secret hardening for multi-user hosts. On Unix-like
			// systems this removes group/other access from an existing .env.
			_ = os.Chmod(p, 0600)

			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
					continue
				}
				parts := strings.SplitN(line, "=", 2)
				k := strings.TrimSpace(parts[0])
				v := strings.TrimSpace(parts[1])
				v = strings.Trim(v, "\"'")
				// Explicit process environment wins over .env. This makes
				// systemd/Docker/Termux wrappers predictable and matches the
				// documented precedence.
				if _, exists := os.LookupEnv(k); !exists {
					_ = os.Setenv(k, v)
				}
			}
			abs, err := filepath.Abs(p)
			if err == nil {
				return abs
			}
			return p
		}
	}
	abs, err := filepath.Abs(".env")
	if err == nil {
		return abs
	}
	return ".env"
}
