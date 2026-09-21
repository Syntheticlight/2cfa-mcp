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
SERVER_PID_FILE="${ROOT_DIR}/2cfa-mcp.server.pid"
MAX_LOG_BYTES="${MAX_LOG_BYTES:-10485760}" # 10 MiB, keep one rotated copy

pid_matches() {
    local pid="${1:-}"
    local marker="${2:-}"
    [ -n "${pid}" ] || return 1
    kill -0 "${pid}" 2>/dev/null || return 1

    # Guard against stale PID-file reuse when ps can expose command arguments.
    if command -v ps >/dev/null 2>&1; then
        local args
        args=$(ps -p "${pid}" -o args= 2>/dev/null || true)
        if [ -n "${args}" ]; then
            case "${args}" in
                *"${marker}"*) return 0 ;;
                *) return 1 ;;
            esac
        fi
    fi
    return 0
}

rotate_log_if_needed() {
    [ -f "${LOG_FILE}" ] || return 0
    LOG_SIZE=$(wc -c < "${LOG_FILE}" 2>/dev/null | tr -d " " || echo 0)
    if [ "${LOG_SIZE:-0}" -ge "${MAX_LOG_BYTES}" ]; then
        cp -f "${LOG_FILE}" "${LOG_FILE}.1" 2>/dev/null || true
        : > "${LOG_FILE}"
    fi
}

start_supervisor_loop() {
    local SERVER_PID=""

    cleanup_supervisor() {
        trap - INT TERM EXIT
        if [ -n "${SERVER_PID}" ] && pid_matches "${SERVER_PID}" "2cfa-mcp"; then
            kill "${SERVER_PID}" 2>/dev/null || true
            wait "${SERVER_PID}" 2>/dev/null || true
        fi
        rm -f "${SERVER_PID_FILE}"

        if command -v termux-wake-unlock >/dev/null 2>&1; then
            termux-wake-unlock 2>/dev/null || true
        fi
    }

    trap 'cleanup_supervisor; exit 0' INT TERM
    trap cleanup_supervisor EXIT

    if command -v termux-wake-lock >/dev/null 2>&1; then
        echo "[INFO] Termux detected! Acquiring wake-lock to prevent CPU sleep..." >> "${LOG_FILE}"
        termux-wake-lock
    fi

    while true; do
        # Dynamically reload .env on every restart iteration so 2FA changes take effect immediately.
        # Secrets stay in the environment/.env and are never placed in argv.
        load_env
        echo "[INFO] Starting 2cfa-mcp server instance at $(date)..." >> "${LOG_FILE}"

        rotate_log_if_needed
        "${BINARY}" \
            -port="${PORT:-2232}" \
            -workspace="${WORKSPACE_PATH:-${ROOT_DIR}/workspace}" \
            -timeout="${EXEC_TIMEOUT:-120}" >> "${LOG_FILE}" 2>&1 &
        SERVER_PID=$!
        echo "${SERVER_PID}" > "${SERVER_PID_FILE}"

        # Keep long-running installations from growing a single log forever.
        while kill -0 "${SERVER_PID}" 2>/dev/null; do
            sleep 60
            rotate_log_if_needed
        done
        wait "${SERVER_PID}" 2>/dev/null || true
        rm -f "${SERVER_PID_FILE}"
        SERVER_PID=""

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
            if pid_matches "${SPID}" "daemon.sh run-supervisor"; then
                kill "${SPID}" 2>/dev/null || true
                # Give the supervisor trap a moment to terminate its exact child.
                for _ in 1 2 3 4 5 6 7 8 9 10; do
                    kill -0 "${SPID}" 2>/dev/null || break
                    sleep 0.2
                done
            fi
            rm -f "${PID_FILE}"
        fi

        # Fallback for a stale/missing supervisor PID file: terminate only the
        # exact server PID recorded by the supervisor, never a broad pkill.
        if [ -f "${SERVER_PID_FILE}" ]; then
            SERVER_PID=$(cat "${SERVER_PID_FILE}" 2>/dev/null || true)
            if pid_matches "${SERVER_PID}" "2cfa-mcp"; then
                kill "${SERVER_PID}" 2>/dev/null || true
            fi
            rm -f "${SERVER_PID_FILE}"
        fi

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
            if pid_matches "${SPID}" "daemon.sh run-supervisor"; then
                IS_RUNNING=true
                echo "[STATUS] 2cfa-mcp Supervisor is RUNNING (PID: ${SPID})"
            fi
        fi

        if [ -f "${SERVER_PID_FILE}" ]; then
            SERVER_PID=$(cat "${SERVER_PID_FILE}" 2>/dev/null || true)
            if pid_matches "${SERVER_PID}" "2cfa-mcp"; then
                IS_RUNNING=true
                echo "[STATUS] 2cfa-mcp Server is RUNNING (PID: ${SERVER_PID})"
            fi
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
