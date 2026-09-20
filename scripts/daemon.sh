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
        # AUTH_TOKEN stays in the environment; never place secrets in argv where
        # they can be exposed through ps or /proc/<pid>/cmdline.
        "${BINARY}" \
            -port="${PORT:-2232}" \
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
        TMP_FILE="${ROOT_DIR}/build/${TARGET_ASSET}.tmp"

        echo "[INFO] Platform/Architecture: ${ARCH}"
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

        CHECKSUM_URL="https://github.com/Syntheticlight/2cfa-mcp/releases/latest/download/SHA256SUMS"
        CHECKSUM_FILE="${ROOT_DIR}/build/SHA256SUMS.tmp"
        if ! curl -sSL -f -o "${CHECKSUM_FILE}" "${CHECKSUM_URL}"; then
            echo "[ERROR] Release checksum manifest is missing. Refusing unverified update."
            rm -f "${TMP_FILE}" "${CHECKSUM_FILE}"
            exit 1
        fi

        EXPECTED_SHA=$(awk -v asset="${TARGET_ASSET}" '$2 == asset || $2 == ("*" asset) {print $1; exit}' "${CHECKSUM_FILE}")
        if [ -z "${EXPECTED_SHA}" ]; then
            echo "[ERROR] No checksum found for ${TARGET_ASSET}. Aborting."
            rm -f "${TMP_FILE}" "${CHECKSUM_FILE}"
            exit 1
        fi

        if command -v sha256sum >/dev/null 2>&1; then
            ACTUAL_SHA=$(sha256sum "${TMP_FILE}" | awk '{print $1}')
        elif command -v shasum >/dev/null 2>&1; then
            ACTUAL_SHA=$(shasum -a 256 "${TMP_FILE}" | awk '{print $1}')
        else
            echo "[ERROR] No SHA-256 utility found (sha256sum/shasum). Refusing unverified update."
            rm -f "${TMP_FILE}" "${CHECKSUM_FILE}"
            exit 1
        fi

        if [ "${ACTUAL_SHA}" != "${EXPECTED_SHA}" ]; then
            echo "[ERROR] SHA-256 mismatch for ${TARGET_ASSET}. Aborting update."
            rm -f "${TMP_FILE}" "${CHECKSUM_FILE}"
            exit 1
        fi

        rm -f "${CHECKSUM_FILE}"
        chmod +x "${TMP_FILE}"
        mv -f "${TMP_FILE}" "${BINARY}"
        echo "[SUCCESS] Updated ${BINARY} successfully (SHA-256 verified)."

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
