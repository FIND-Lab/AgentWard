#!/usr/bin/env bash
set -euo pipefail

PLUGIN_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_NAME="agent-ward"
OPENCLAW_CONFIG="${HOME}/.openclaw/openclaw.json"

FORCE=false
UNINSTALL_ONLY=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --force|-f)
            FORCE=true
            shift
            ;;
        --uninstall-only|-u)
            UNINSTALL_ONLY=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--force|-f] [--uninstall-only|-u]"
            exit 1
            ;;
    esac
done

echo "===== AgentWard Setup ====="
echo "Installing/updating AgentWard from: ${PLUGIN_DIR}"
[[ "${FORCE}" == "true" ]] && echo "[--force mode enabled]"
[[ "${UNINSTALL_ONLY}" == "true" ]] && echo "[--uninstall-only mode enabled]"
echo ""

# Step 1: Uninstall previous install (CLI-managed; avoids leaving stale config entries)
echo "[1/1] Uninstalling previous ${PLUGIN_NAME} (if any)..."
if [[ "${FORCE}" == "true" ]]; then
    # Skip interactive prompt inside `plugins uninstall`
    openclaw plugins uninstall "${PLUGIN_NAME}" --force || true
else
    # Let OpenClaw prompt if it finds a managed install/config entry.
    # If it's not installed/managed, uninstall exits non-zero; ignore that case.
    openclaw plugins uninstall "${PLUGIN_NAME}" || true
fi

if [[ "${UNINSTALL_ONLY}" == "true" ]]; then
    echo ""
    echo "===== Uninstall Complete ====="
    exit 0
fi

# Step 2: Build runtime output required by OpenClaw 2026.5.3+
echo "[2/3] Building plugin runtime output..."
rm -rf "${PLUGIN_DIR}/dist"
npm install
npm run build

# Step 3: Install with security bypass (this plugin uses child_process for
# proactive channel notifications, which triggers the built-in scanner)
echo "[3/3] Installing ${PLUGIN_NAME}..."
openclaw plugins install "${PLUGIN_DIR}" --dangerously-force-unsafe-install --force

# Step 4: Re-apply runtime hook permissions that OpenClaw does not persist
# across uninstall/reinstall for local plugins.
echo "[4/4] Ensuring ${PLUGIN_NAME} hook permissions..."
node -e '
const fs = require("node:fs");
const path = process.argv[1];
const raw = fs.readFileSync(path, "utf8");
const cfg = JSON.parse(raw);
cfg.plugins ??= {};
cfg.plugins.entries ??= {};
cfg.plugins.entries["agent-ward"] ??= {};
cfg.plugins.entries["agent-ward"].enabled = true;
cfg.plugins.entries["agent-ward"].hooks ??= {};
cfg.plugins.entries["agent-ward"].hooks.allowConversationAccess = true;
fs.writeFileSync(path, JSON.stringify(cfg, null, 2) + "\n");
' "${OPENCLAW_CONFIG}"

echo "[4/4] Verifying ${PLUGIN_NAME} hook permissions..."
node -e '
const fs = require("node:fs");
const path = process.argv[1];
const raw = fs.readFileSync(path, "utf8");
const cfg = JSON.parse(raw);
const ok = cfg.plugins?.entries?.["agent-ward"]?.hooks?.allowConversationAccess === true;
if (!ok) {
  console.error("Verification failed: plugins.entries.agent-ward.hooks.allowConversationAccess is not true");
  process.exit(1);
}
' "${OPENCLAW_CONFIG}"

echo ""
echo "===== Setup Complete ====="
