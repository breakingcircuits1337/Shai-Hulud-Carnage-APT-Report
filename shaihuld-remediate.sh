#!/usr/bin/env bash
# ------------------------------------------------------------------
# Shai-Hulud / Carnage APT — Local Remediation & Vaccine Script
# 
# What this script does:
#   1. Detects the threat (LaunchAgent / systemd service / running procs)
#   2. Collects intel to a LOCAL report file only — nothing is sent anywhere
#   3. Defuses the deadman switch by killing all persistence mechanisms
#   4. Immunizes the host against re-infection
#   5. Optionally signals a local "clean" token to a GitHub-coordinated
#      safe-revocation endpoint (only if --revoke-endpoint is passed)
#
# Usage:
#   Solo (proactive):        ./shaihuld-remediate.sh
#   With safe revocation:    ./shaihuld-remediate.sh --revoke-endpoint <URL>
#   Silent/CI mode:          ./shaihuld-remediate.sh --silent
# ------------------------------------------------------------------

set -euo pipefail

# ── Args ────────────────────────────────────────────────────────────
REVOKE_ENDPOINT=""
SILENT=false

for arg in "$@"; do
  case $arg in
    --revoke-endpoint=*) REVOKE_ENDPOINT="${arg#*=}" ;;
    --revoke-endpoint)   shift; REVOKE_ENDPOINT="${1:-}" ;;
    --silent)            SILENT=true ;;
  esac
done

# ── Config ──────────────────────────────────────────────────────────
OS="$(uname -s)"
USER_HOME="${HOME}"
SCRIPT_NAME="gh-token-monitor"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
REPORT_DIR="${USER_HOME}/.local/share/ir-reports"
REPORT_FILE="${REPORT_DIR}/shai-hulud-${TIMESTAMP//:/}.txt"
THREAT_DETECTED=false
CLEAN_SIGNAL_TOKEN=""   # Set by GitHub out-of-band if using coordinated flow

CONFIG_DIR="${USER_HOME}/.config/${SCRIPT_NAME}"
PLIST_PATH="${USER_HOME}/Library/LaunchAgents/com.user.${SCRIPT_NAME}.plist"
SERVICE_PATH="${USER_HOME}/.config/systemd/user/${SCRIPT_NAME}.service"
BIN_PATH="${USER_HOME}/.local/bin/${SCRIPT_NAME}.sh"

log() { [[ "$SILENT" == false ]] && echo "$1" || true; }

# ── Ensure report dir exists ─────────────────────────────────────────
mkdir -p "$REPORT_DIR"
chmod 700 "$REPORT_DIR"

{
  echo "========================================"
  echo " Shai-Hulud IR Report"
  echo " Host:      $(hostname)"
  echo " User:      $(whoami)"
  echo " Timestamp: ${TIMESTAMP}"
  echo " OS:        ${OS}"
  echo "========================================"
  echo ""
} > "$REPORT_FILE"

log "[*] Shai-Hulud Remediation Script starting..."
log "[*] Report will be written to: $REPORT_FILE"

# ==========================================
# PHASE 1: DETECTION & LOCAL INTEL COLLECTION
# ==========================================
log ""
log "[PHASE 1] Detection & Intel Collection"

collect_file() {
  local label="$1"
  local path="$2"
  if [[ -f "$path" ]]; then
    echo "--- ${label} ---" >> "$REPORT_FILE"
    cat "$path" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    THREAT_DETECTED=true
    log "[!] Found: $path"
  fi
}

collect_file "Stolen Token"        "${CONFIG_DIR}/token"
collect_file "Destructive Handler" "${CONFIG_DIR}/handler"
collect_file "LaunchAgent Plist"   "${PLIST_PATH}"
collect_file "Systemd Service"     "${SERVICE_PATH}"
collect_file "Malware Binary"      "${BIN_PATH}"

# Check for running process
if pgrep -f "${SCRIPT_NAME}.sh" > /dev/null 2>&1; then
  THREAT_DETECTED=true
  echo "--- Running Process ---" >> "$REPORT_FILE"
  pgrep -a -f "${SCRIPT_NAME}.sh" >> "$REPORT_FILE" 2>/dev/null || true
  echo "" >> "$REPORT_FILE"
  log "[!] Active malware process detected in memory"
fi

# Record network connections if ss/lsof available
{
  echo "--- Active Network Connections (snapshot) ---"
  if command -v ss &>/dev/null; then
    ss -tp 2>/dev/null | grep -i "${SCRIPT_NAME}" || echo "none matching"
  elif command -v lsof &>/dev/null; then
    lsof -i -n -P 2>/dev/null | grep -i "${SCRIPT_NAME}" || echo "none matching"
  else
    echo "no network tools available"
  fi
  echo ""
} >> "$REPORT_FILE"

# ==========================================
# PHASE 2: DEFUSAL
# ==========================================
log ""
log "[PHASE 2] Defusal — Killing Persistence & Memory Residency"

# Stop & remove LaunchAgent (macOS)
if [[ "$OS" == "Darwin" && -f "$PLIST_PATH" ]]; then
  launchctl bootout "gui/$(id -u)" "${PLIST_PATH}" 2>/dev/null || true
  rm -f "${PLIST_PATH}"
  log "[+] LaunchAgent removed"
  echo "ACTION: LaunchAgent unloaded and removed" >> "$REPORT_FILE"
fi

# Stop & remove systemd service (Linux)
if [[ "$OS" == "Linux" && -f "$SERVICE_PATH" ]]; then
  systemctl --user stop "${SCRIPT_NAME}.service"  2>/dev/null || true
  systemctl --user disable "${SCRIPT_NAME}.service" 2>/dev/null || true
  rm -f "${SERVICE_PATH}"
  systemctl --user daemon-reload 2>/dev/null || true
  log "[+] Systemd service stopped and removed"
  echo "ACTION: Systemd service stopped and removed" >> "$REPORT_FILE"
fi

# Kill active process
if pgrep -f "${SCRIPT_NAME}.sh" > /dev/null 2>&1; then
  pkill -9 -f "${SCRIPT_NAME}.sh" 2>/dev/null || true
  log "[+] In-memory process killed"
  echo "ACTION: Process killed" >> "$REPORT_FILE"
fi

# Purge payload files
rm -f "${BIN_PATH}"
rm -rf "${CONFIG_DIR}"
log "[+] Payload files purged"
echo "ACTION: Payload files purged" >> "$REPORT_FILE"

# ==========================================
# PHASE 3: IMMUNIZATION
# ==========================================
log ""
log "[PHASE 3] Immunization"

# Re-create config dir as an immutable trap
mkdir -p "${CONFIG_DIR}"
if [[ "$OS" == "Darwin" ]]; then
  chflags uchg "${CONFIG_DIR}" 2>/dev/null || true
  log "[+] Config dir locked (macOS uchg flag)"
elif [[ "$OS" == "Linux" ]]; then
  chmod 000 "${CONFIG_DIR}"
  sudo chattr +i "${CONFIG_DIR}" 2>/dev/null || true
  log "[+] Config dir locked (chattr +i)"
fi
echo "ACTION: Immunization directory trap set" >> "$REPORT_FILE"

# NPM lifecycle hardening
if command -v npm &>/dev/null; then
  npm config set ignore-scripts true 2>/dev/null || true
  log "[+] npm lifecycle scripts disabled"
  echo "ACTION: npm ignore-scripts=true set" >> "$REPORT_FILE"
fi

# ==========================================
# PHASE 4: CLEAN SIGNAL TO SAFE-REVOCATION ENDPOINT
# ==========================================
# This phase ONLY runs if GitHub (or your IR coordinator) has given you
# a --revoke-endpoint URL out-of-band.  No credentials are sent —
# only a host fingerprint and a "clean" status flag so the coordinated
# revocation can safely fire without triggering the deadman switch.

if [[ -n "$REVOKE_ENDPOINT" ]]; then
  log ""
  log "[PHASE 4] Signaling clean status to safe-revocation endpoint..."

  PAYLOAD=$(cat <<EOF
{
  "status": "clean",
  "host_id": "$(hostname)-$(id -u)",
  "os": "${OS}",
  "timestamp": "${TIMESTAMP}",
  "threat_was_present": ${THREAT_DETECTED}
}
EOF
)

  HTTP_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" \
    "$REVOKE_ENDPOINT" 2>/dev/null || echo "000")

  if [[ "$HTTP_RESPONSE" == "200" || "$HTTP_RESPONSE" == "204" ]]; then
    log "[+] Safe-revocation endpoint acknowledged. GitHub will now revoke the zombie token."
    echo "ACTION: Clean signal sent to $REVOKE_ENDPOINT — response $HTTP_RESPONSE" >> "$REPORT_FILE"
  else
    log "[-] Endpoint returned $HTTP_RESPONSE — revocation may need to be triggered manually."
    echo "WARNING: Endpoint returned $HTTP_RESPONSE" >> "$REPORT_FILE"
  fi
else
  log ""
  log "[PHASE 4] No revocation endpoint provided."
  log "          → Manually revoke your GitHub tokens at: https://github.com/settings/tokens"
  echo "MANUAL ACTION REQUIRED: Revoke GitHub tokens at https://github.com/settings/tokens" >> "$REPORT_FILE"
fi

# ==========================================
# PHASE 5: SUMMARY
# ==========================================
echo "" >> "$REPORT_FILE"
echo "========================================"   >> "$REPORT_FILE"
echo " Remediation complete: $(date -u)"          >> "$REPORT_FILE"
echo " Threat detected: ${THREAT_DETECTED}"       >> "$REPORT_FILE"
echo "========================================"   >> "$REPORT_FILE"

chmod 600 "$REPORT_FILE"

log ""
log "========================================"
if [ "$THREAT_DETECTED" = true ]; then
  log "[!] THREAT NEUTRALIZED"
  log "    Review your local report: $REPORT_FILE"
  log "    Share with: security@github.com or your IR team"
else
  log "[+] No active threat found. Host is now immunized."
  log "    Report written to: $REPORT_FILE"
fi
log "========================================"

# Emit machine-readable exit status for the UI wrapper
if [ "$THREAT_DETECTED" = true ]; then
  exit 2   # Threat found and neutralized
else
  exit 0   # Clean / immunized
fi
