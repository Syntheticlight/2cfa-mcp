package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/Syntheticlight/2cfa-mcp/internal/auth"
	"github.com/Syntheticlight/2cfa-mcp/internal/gate"
	"github.com/Syntheticlight/2cfa-mcp/internal/tools"
)

// ServerConfig defines the server configuration parameters.
type ServerConfig struct {
	Port          int
	AuthToken     string
	WorkspacePath string
	ExecTimeout   time.Duration
	Enable2FAGate bool
	TOTPSecret    string
	EnvPath       string
}

// Server holds the HTTP server and MCP server components.
type Server struct {
	config    ServerConfig
	mcpServer *server.MCPServer
	sseServer *server.SSEServer
	gateMgr   *gate.Manager
	httpSrv   *http.Server
}

// NewServer creates and initializes the 2cfa-mcp Server.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.WorkspacePath == "" {
		return nil, fmt.Errorf("workspace path cannot be empty")
	}

	if err := os.MkdirAll(cfg.WorkspacePath, 0755); err != nil {
		log.Printf("[WARN] Failed to ensure workspace directory %s exists: %v", cfg.WorkspacePath, err)
	}

	mcpSrv := server.NewMCPServer(
		"2cfa-mcp", "1.0.4",
		server.WithDescription("High-security, low-memory remote MCP Server for edge devices"),
	)

	// Initialize 2FA Gate Manager
	gateMgr := gate.NewManager(gate.Config{
		Enabled:    cfg.Enable2FAGate,
		TOTPSecret: cfg.TOTPSecret,
		EnvPath:    cfg.EnvPath,
	})

	// Register tools with gate protection and audit tracking
	tools.RegisterGateTools(mcpSrv, gateMgr)
	tools.RegisterCommandTool(mcpSrv, cfg.WorkspacePath, cfg.ExecTimeout, gateMgr)
	tools.RegisterFileTools(mcpSrv, cfg.WorkspacePath, gateMgr)
	tools.RegisterSysInfoTool(mcpSrv, gateMgr)

	// Create SSE Server with dynamic base path and query preservation
	sseSrv := server.NewSSEServer(
		mcpSrv,
		server.WithSSEDisableLocalhostProtection(true),
		server.WithAppendQueryToMessageEndpoint(),
		server.WithSSECORS(
			server.WithCORSAllowedOrigins("*"),
			server.WithCORSAllowedMethods("GET", "POST", "OPTIONS", "DELETE", "HEAD"),
			server.WithCORSAllowedHeaders("*"),
			server.WithCORSExposedHeaders("*"),
		),
		server.WithDynamicBasePath(func(r *http.Request, sessionID string) string {
			if strings.HasPrefix(r.URL.Path, "/mcp/") {
				parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/mcp/"), "/")
				if len(parts) > 0 && parts[0] != "" {
					return "/mcp/" + parts[0]
				}
			}
			return ""
		}),
	)

	// Create Streamable HTTP Server
	streamableSrv := server.NewStreamableHTTPServer(
		mcpSrv,
		server.WithDisableLocalhostProtection(true),
		server.WithStreamableHTTPCORS(
			server.WithCORSAllowedOrigins("*"),
			server.WithCORSAllowedMethods("GET", "POST", "OPTIONS", "DELETE", "HEAD"),
			server.WithCORSAllowedHeaders("*"),
			server.WithCORSExposedHeaders("*"),
		),
	)

	mux := http.NewServeMux()

	// Public Health Check Endpoint (Zero-Leakage Policy: strictly {"status":"ok"})
	mux.HandleFunc("/health", healthCheckHandler)
	mux.HandleFunc("/healthz", healthCheckHandler)

	// Embedded 2FA Gate Web Dashboard & API
	gateHandler := gate.NewHandler(gateMgr, cfg.AuthToken)
	mux.Handle("/gate", gateHandler)
	mux.Handle("/gate/", gateHandler)

	// MCP endpoints handler wrapper
	mcpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP, country := gate.ResolveClientIP(r)
		// Stamp a server-controlled identity for downstream MCP tool handlers.
		// Set overwrites any client-supplied values with the sanitized peer identity.
		r.Header.Set("X-2CFA-Client-IP", clientIP)
		r.Header.Set("X-2CFA-Client-Country", country)

		sanitizedURI := auth.SanitizeURL(r.URL.RequestURI(), cfg.AuthToken)
		log.Printf("[REQ] %s %s from %s [%s]", r.Method, sanitizedURI, clientIP, country)

		cleanPath := strings.TrimRight(r.URL.Path, "/")

		// Direct routing for SSE stream:
		// Handles: /sse, /sse/, /mcp/<TOKEN>/sse, /mcp/<TOKEN>/sse/
		// Or any GET request requesting text/event-stream (e.g. ChatGPT connecting directly to /mcp/<TOKEN>)
		if strings.HasSuffix(cleanPath, "/sse") || cleanPath == "/sse" ||
			(r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/event-stream") && !strings.Contains(cleanPath, "/message")) {
			sseSrv.SSEHandler().ServeHTTP(w, r)
			return
		}

		// Direct routing for SSE Message endpoint
		if strings.Contains(cleanPath, "/message") {
			sseSrv.MessageHandler().ServeHTTP(w, r)
			return
		}

		// Handle /mcp/<TOKEN>/... prefix rewriting for Streamable HTTP clients
		if strings.HasPrefix(r.URL.Path, "/mcp/") {
			trimmedPath := strings.TrimPrefix(r.URL.Path, "/mcp/")
			if idx := strings.Index(trimmedPath, "/"); idx != -1 {
				r.URL.Path = trimmedPath[idx:]
			} else {
				r.URL.Path = "/"
			}
			if r.URL.RawPath != "" {
				r.URL.RawPath = r.URL.Path
			}
		}

		// Fallback to Streamable HTTP transport
		streamableSrv.ServeHTTP(w, r)
	})

	// Route all other requests through MCP handler
	mux.Handle("/", mcpHandler)

	// Wrap entire mux with Auth Middleware
	authMW := auth.NewMiddleware(cfg.AuthToken)
	authenticatedHandler := authMW.Authenticate(mux)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      authenticatedHandler,
		ReadTimeout:  300 * time.Second,
		WriteTimeout: 300 * time.Second,
		IdleTimeout:  600 * time.Second,
	}

	return &Server{
		config:    cfg,
		mcpServer: mcpSrv,
		sseServer: sseSrv,
		gateMgr:   gateMgr,
		httpSrv:   srv,
	}, nil
}

// HealthResponse represents the zero-leak health check output.
type HealthResponse struct {
	Status string `json:"status"`
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	resp := HealthResponse{
		Status: "ok",
	}

	_ = json.NewEncoder(w).Encode(resp)
}

// Start launches the HTTP server.
func (s *Server) Start() error {
	log.Printf("Starting 2cfa-mcp Server on port %d...", s.config.Port)
	log.Printf("Workspace root: %s", s.config.WorkspacePath)
	if s.config.Enable2FAGate {
		log.Printf("2FA Gate: ENABLED (Google Authenticator required. Unlock via in-chat 'unlock_gate')")
	} else {
		log.Printf("2FA Gate: DISABLED (Default Token-only direct connection)")
	}

	return s.httpSrv.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	log.Println("Shutting down 2cfa-mcp Server gracefully...")
	return s.httpSrv.Shutdown(ctx)
}
