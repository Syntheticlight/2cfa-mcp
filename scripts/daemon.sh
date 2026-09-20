#!/usr/bin/env bash

# ==============================================================================
# 2cfa-mcp Background Daemon & Cloudflare Tunnel Supervisor
# Supports: Linux VPS, Android Termux (ARM64), Raspberry Pi
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Function to load/reload .env dynamically
load_env() {
    if [ -f "${ROOT_DIR}/.env" ]; then
        set -a
        . "${ROOT_DIR}/.env"
        set +a
    fi
}

load_env

PORT="${PORT:-2232}"
AUTH_TOKEN="${AUTH_TOKEN:-}"
WORKSPACE_PATH="${WORKSPACE_PATH:-${ROOT_DIR}/workspace}"
EXEC_TIMEOUT="${EXEC_TIMEOUT:-120}"

if [ -z "${AUTH_TOKEN}" ]; then
    echo "[ERROR] AUTH_TOKEN is not set! Please set AUTH_TOKEN in .env or environment."
    exit 1
fi

mkdir -p "${WORKSPACE_PATH}"

BINARY="${ROOT_DIR}/build/2cfa-mcp"
if [ ! -f "${BINARY}" ]; then
    if [ -f "${ROOT_DIR}/build/2cfa-mcp-android-arm64" ]; then
        BINARY="${ROOT_DIR}/build/2cfa-mcp-android-arm64"
    elif [ -f "${ROOT_DIR}/build/2cfa-mcp-linux-arm64" ]; then
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

# Android Termux Environment Setup & Wake Lock Check
if [ -n "${PREFIX}" ] && [ -d "${PREFIX}/bin" ]; then
    export PATH="${PREFIX}/bin:${PATH}"
elif [ -d "/data/data/com.termux/files/usr/bin" ]; then
    export PATH="/data/data/com.termux/files/usr/bin:${PATH}"
fi

LOG_FILE="${ROOT_DIR}/2cfa-mcp.log"
PID_FILE="${ROOT_DIR}/2cfa-mcp.pid"

start_supervisor_loop() {
    if command -v termux-wake-lock >/dev/null 2>&1; then
        echo "[INFO] Termux detected! Acquiring wake-lock to prevent CPU sleep..." >> "${LOG_FILE}"
        termux-wake-lock
    fi

    while true; do
        # Dynamically reload .env on every restart iteration so 2FA changes take effect immediately
        load_env
        echo "[INFO] Starting 2cfa-mcp server instance at $(date)..." >> "${LOG_FILE}"

        # Do NOT pass -2fa or -totp-secret flags: binary natively loads .env as single source of truth!
        "${BINARY}" \
            -port="${PORT:-2232}" \
            -token="${AUTH_TOKEN}" \
            -workspace="${WORKSPACE_PATH:-${ROOT_DIR}/workspace}" \
            -timeout="${EXEC_TIMEOUT:-120}" >> "${LOG_FILE}" 2>&1 || true

        echo "[WARNING] Server crashed or stopped. Restarting in 3 seconds..." >> "${LOG_FILE}"
        sleep 3
    done
}

case "$1" in
    run-supervisor)
        start_supervisor_loop
        ;;
    start)
        if [ -f "${PID_FILE}" ]; then
            OLD_PID=$(cat "${PID_FILE}" 2>/dev/null || true)
            if [ -n "${OLD_PID}" ] && kill -0 "${OLD_PID}" 2>/dev/null; then
                echo "[INFO] 2cfa-mcp daemon supervisor is already running (PID: ${OLD_PID})."
                exit 0
            fi
        fi

        echo "=========================================================================="
        echo " Starting 2cfa-mcp Daemon Supervisor"
        echo " Binary:    ${BINARY}"
        echo " Port:      ${PORT}"
        echo " Workspace: ${WORKSPACE_PATH}"
        echo " Logs:      ${LOG_FILE}"
        echo "=========================================================================="

        nohup "${BASH_SOURCE[0]}" run-supervisor >/dev/null 2>&1 &
        SPID=$!
        echo "${SPID}" > "${PID_FILE}"
        echo "[SUCCESS] 2cfa-mcp daemon started in background (Supervisor PID: ${SPID})."
        ;;
    stop)
        if [ -f "${PID_FILE}" ]; then
            SPID=$(cat "${PID_FILE}" 2>/dev/null || true)
            if [ -n "${SPID}" ]; then
                kill "${SPID}" 2>/dev/null || true
            fi
            rm -f "${PID_FILE}"
        fi
        pkill -f "2cfa-mcp" || true

        if command -v termux-wake-unlock >/dev/null 2>&1; then
            echo "[INFO] Releasing Termux wake-lock..."
            termux-wake-unlock 2>/dev/null || true
        fi
        echo "[SUCCESS] 2cfa-mcp daemon stopped."
        ;;
    status)
        IS_RUNNING=false
        if [ -f "${PID_FILE}" ]; then
            SPID=$(cat "${PID_FILE}" 2>/dev/null || true)
            if [ -n "${SPID}" ] && kill -0 "${SPID}" 2>/dev/null; then
                IS_RUNNING=true
                echo "[STATUS] 2cfa-mcp Supervisor is RUNNING (PID: ${SPID})"
            fi
        fi

        PROC_PIDS=$(pgrep -f "2cfa-mcp" 2>/dev/null | tr '\n' ' ' || true)
        if [ -n "${PROC_PIDS}" ]; then
            IS_RUNNING=true
            echo "[STATUS] 2cfa-mcp Processes: ${PROC_PIDS}"
        fi

        if [ "${IS_RUNNING}" = false ]; then
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
    update)
        echo "=========================================================================="
        echo " 2cfa-mcp Safe Open-Source Updater"
        echo "=========================================================================="
        ARCH=""
        if [ -n "${PREFIX}" ] || [ -d "/data/data/com.termux/files/usr/bin" ]; then
            ARCH="android-arm64"
        else
            UNAME_M=$(uname -m)
            case "${UNAME_M}" in
                x86_64|amd64) ARCH="linux-amd64" ;;
                aarch64|arm64) ARCH="linux-arm64" ;;
                *) echo "[ERROR] Unsupported architecture: ${UNAME_M}"; exit 1 ;;
            esac
        fi

        TARGET_ASSET="2cfa-mcp-${ARCH}"
        DOWNLOAD_URL="https://github.com/Syntheticlight/2cfa-mcp/releases/latest/download/${TARGET_ASSET}"
        LATEST_API="https://api.github.com/repos/Syntheticlight/2cfa-mcp/releases/latest"
        TMP_FILE="${ROOT_DIR}/build/${TARGET_ASSET}.tmp"

        echo "[INFO] Platform/Architecture: ${ARCH}"

        # Newer binaries expose -version. Compare against the latest release tag
        # before downloading so a source-built/security-patched binary cannot be
        # accidentally downgraded to an older GitHub Release.
        CURRENT_VERSION=$("${BINARY}" -version 2>/dev/null | tail -n 1 | tr -d '\r' || true)
        LATEST_VERSION=$(curl -sSL -f "${LATEST_API}" 2>/dev/null | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1 || true)

        if [ -n "${CURRENT_VERSION}" ] && [ -n "${LATEST_VERSION}" ]; then
            if [ "${CURRENT_VERSION}" = "${LATEST_VERSION}" ]; then
                echo "[INFO] Already running latest release ${CURRENT_VERSION}; nothing to update."
                exit 0
            fi

            LOWEST_VERSION=$(printf '%s\n%s\n' "${LATEST_VERSION}" "${CURRENT_VERSION}" | sort -V | head -n 1)
            if [ "${LOWEST_VERSION}" = "${LATEST_VERSION}" ]; then
                echo "[ERROR] Refusing downgrade: installed ${CURRENT_VERSION}, latest published release is older (${LATEST_VERSION})."
                echo "[ERROR] Publish a newer release before using the updater."
                exit 1
            fi
        fi

        echo "[INFO] Downloading latest release from GitHub: ${DOWNLOAD_URL}"

        mkdir -p "${ROOT_DIR}/build"
        if ! curl -sSL -f -o "${TMP_FILE}" "${DOWNLOAD_URL}"; then
            echo "[ERROR] Download failed. Please check network connectivity or GitHub release availability."
            rm -f "${TMP_FILE}"
            exit 1
        fi

        FILE_SIZE=$(wc -c < "${TMP_FILE}" | tr -d " ")
        if [ "${FILE_SIZE}" -lt 1000000 ]; then
            echo "[ERROR] Downloaded file too small (${FILE_SIZE} bytes). Aborting."
            rm -f "${TMP_FILE}"
            exit 1
        fi

        chmod +x "${TMP_FILE}"

        # Defense in depth: if both binaries expose versions, verify the
        # downloaded asset itself is not older than the installed binary.
        DOWNLOADED_VERSION=$("${TMP_FILE}" -version 2>/dev/null | tail -n 1 | tr -d '\r' || true)
        if [ -n "${CURRENT_VERSION}" ] && [ -n "${DOWNLOADED_VERSION}" ]; then
            LOWEST_VERSION=$(printf '%s\n%s\n' "${DOWNLOADED_VERSION}" "${CURRENT_VERSION}" | sort -V | head -n 1)
            if [ "${DOWNLOADED_VERSION}" != "${CURRENT_VERSION}" ] && [ "${LOWEST_VERSION}" = "${DOWNLOADED_VERSION}" ]; then
                echo "[ERROR] Downloaded asset ${DOWNLOADED_VERSION} is older than installed ${CURRENT_VERSION}; aborting."
                rm -f "${TMP_FILE}"
                exit 1
            fi
        fi

        mv -f "${TMP_FILE}" "${BINARY}"
        echo "[SUCCESS] Updated ${BINARY} successfully${DOWNLOADED_VERSION:+ to ${DOWNLOADED_VERSION}}."

        if pgrep -f "2cfa-mcp" >/dev/null || [ -f "${PID_FILE}" ]; then
            echo "[INFO] Restarting 2cfa-mcp daemon..."
            $0 stop
            sleep 1
            $0 start
        else
            echo "[INFO] Update complete. Run '$0 start' when ready."
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|status|update|cloudflared}"
        exit 1
        ;;
esac
