#!/usr/bin/env bash

# ==============================================================================
# 2cfa-mcp Background Daemon & Cloudflare Tunnel Supervisor
# Supports: Linux VPS, Android Termux (ARM64), Raspberry Pi
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Load .env configuration if present
if [ -f "${ROOT_DIR}/.env" ]; then
    echo "[INFO] Loading environment variables from .env"
    export $(grep -v '^#' "${ROOT_DIR}/.env" | xargs)
fi

PORT="${PORT:-8080}"
AUTH_TOKEN="${AUTH_TOKEN:-}"
WORKSPACE_PATH="${WORKSPACE_PATH:-${ROOT_DIR}/workspace}"
EXEC_TIMEOUT="${EXEC_TIMEOUT:-120}"
ENABLE_2FA_GATE="${ENABLE_2FA_GATE:-false}"
TOTP_SECRET="${TOTP_SECRET:-}"

if [ -z "${AUTH_TOKEN}" ]; then
    echo "[ERROR] AUTH_TOKEN is not set! Please set AUTH_TOKEN in .env or environment."
    exit 1
fi

mkdir -p "${WORKSPACE_PATH}"

BINARY="${ROOT_DIR}/build/2cfa-mcp"
if [ ! -f "${BINARY}" ]; then
    if [ -f "${ROOT_DIR}/build/2cfa-mcp-linux-arm64" ]; then
        BINARY="${ROOT_DIR}/build/2cfa-mcp-linux-arm64"
    elif [ -f "${ROOT_DIR}/build/2cfa-mcp-linux-amd64" ]; then
        BINARY="${ROOT_DIR}/build/2cfa-mcp-linux-amd64"
    fi
fi

if [ ! -f "${BINARY}" ]; then
    echo "[ERROR] Binary not found at ${BINARY}. Please run 'make build' or 'make build-linux-arm64' first."
    exit 1
fi

chmod +x "${BINARY}"

echo "=========================================================================="
echo " Starting 2cfa-mcp Daemon Supervisor"
echo " Binary:    ${BINARY}"
echo " Port:      ${PORT}"
echo " Workspace: ${WORKSPACE_PATH}"
echo " 2FA Gate:  ${ENABLE_2FA_GATE}"
echo "=========================================================================="

# Android Termux Wake Lock Check
if command -v termux-wake-lock >/dev/null 2>&1; then
    echo "[INFO] Termux detected! Acquiring wake-lock to prevent CPU sleep..."
    termux-wake-lock
fi

LOG_FILE="${ROOT_DIR}/2cfa-mcp.log"

start_server() {
    while true; do
        echo "[INFO] Starting 2cfa-mcp server instance at $(date)..." >> "${LOG_FILE}"
        "${BINARY}" \
            -port="${PORT}" \
            -token="${AUTH_TOKEN}" \
            -workspace="${WORKSPACE_PATH}" \
            -timeout="${EXEC_TIMEOUT}" \
            -2fa="${ENABLE_2FA_GATE}" \
            -totp-secret="${TOTP_SECRET}" >> "${LOG_FILE}" 2>&1 || true
        echo "[WARNING] Server crashed or stopped. Restarting in 3 seconds..." >> "${LOG_FILE}"
        sleep 3
    done
}

case "$1" in
    start)
        nohup bash -c "$(declare -f start_server); start_server" >/dev/null 2>&1 &
        echo "[SUCCESS] 2cfa-mcp daemon started in background. Logs: ${LOG_FILE}"
        ;;
    stop)
        pkill -f "2cfa-mcp" || true
        echo "[SUCCESS] 2cfa-mcp daemon stopped."
        ;;
    status)
        if pgrep -f "2cfa-mcp" >/dev/null; then
            echo "[STATUS] 2cfa-mcp is RUNNING (PID: $(pgrep -f "2cfa-mcp" | tr '\n' ' '))"
        else
            echo "[STATUS] 2cfa-mcp is STOPPED"
        fi
        ;;
    cloudflared)
        if ! command -v cloudflared >/dev/null 2>&1; then
            echo "[ERROR] cloudflared is not installed. Install via: pkg install cloudflared / apt install cloudflared"
            exit 1
        fi
        echo "[INFO] Launching Cloudflare Quick Tunnel for port ${PORT}..."
        cloudflared tunnel --url "http://localhost:${PORT}"
        ;;
    *)
        echo "Usage: $0 {start|stop|status|cloudflared}"
        exit 1
        ;;
esac
