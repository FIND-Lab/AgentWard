#!/usr/bin/env bash
set -euo pipefail

PLUGIN_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_NAME="agent-ward"

FORCE=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --force|-f)
            FORCE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--force|-f]"
            exit 1
            ;;
    esac
done

echo "===== AgentWard Setup ====="
echo "Installing/updating AgentWard from: ${PLUGIN_DIR}"
[[ "${FORCE}" == "true" ]] && echo "[--force mode enabled]"
echo ""

# Step 1: Uninstall existing plugin
if openclaw plugins inspect "${PLUGIN_NAME}" >/dev/null 2>&1; then
    echo "[1/3] Existing installation found."
    
    if [[ "${FORCE}" == "true" ]]; then
        echo "[--force] Skipping confirmation, proceeding with uninstall..."
        confirm="y"
    else
        read -rp "Uninstall previous version of ${PLUGIN_NAME}? [y/N] " confirm
    fi
    
    if [[ "${confirm,,}" == "y" ]]; then
        echo "Uninstalling ${PLUGIN_NAME}..."
        if ! openclaw plugins uninstall "${PLUGIN_NAME}" --force 2>/dev/null; then
            echo "Uninstall failed or plugin not found, continuing..."
        fi
        echo "Done."
    else
        echo "Skipped uninstall."
        exit 1
    fi
else
    echo "[1/3] No existing installation found."
fi

# Step 2: Remove leftover directory if present
INSTALL_PATH="$(openclaw plugins inspect "${PLUGIN_NAME}" 2>/dev/null | grep -i 'Source:' | sed 's/^Source:[[:space:]]*\(.*\)\/[^/]*$/\1\//' || true)"
INSTALL_PATH="${INSTALL_PATH/#\~/$HOME}" # Expand ~ to home directory
if [[ -n "${INSTALL_PATH}" && -d "${INSTALL_PATH}" ]]; then
    echo "[2/3] Removing leftover directory: ${INSTALL_PATH}"
    rm -rf "${INSTALL_PATH}"
else
    echo "[2/3] No leftover directory to clean."
fi

# Step 3: Install with security bypass (this plugin uses child_process for
# proactive channel notifications, which triggers the built-in scanner)
echo "[3/3] Installing ${PLUGIN_NAME}..."
openclaw plugins install "${PLUGIN_DIR}" --dangerously-force-unsafe-install

echo ""
echo "===== Setup Complete ====="
