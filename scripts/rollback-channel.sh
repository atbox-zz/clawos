#!/usr/bin/env bash
# scripts/rollback-channel.sh
#
# Rollback: channel config / deployment reversal
#
# What this does:
#   1. 找出失敗的 channel（從 task result 或參數）
#   2. 從 ClawFS /config/channels/ 備份中還原前一版設定
#   3. 重啟受影響的 channel service
#   4. 驗證 channel 健康狀態
#   5. 記錄事件到 Vault
#
# 觸發條件：IPC task.failed 訊息中帶 rollback_name=rollback-channel

set -euo pipefail

CLAWOS_HOME="${CLAWOS_HOME:-/var/lib/clawos}"
LOG="${CLAWOS_HOME}/logs/rollback-channel.log"
CONFIG_DIR="${CLAWOS_HOME}/config/channels"
BACKUP_DIR="${CLAWOS_HOME}/backups/channels"
VAULT_DIR="${CLAWOS_HOME}/vault"
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)

mkdir -p "$(dirname "$LOG")"
exec >> "$LOG" 2>&1

log() { echo "[${TIMESTAMP}] $*"; }
die() { echo "[${TIMESTAMP}] ERROR: $*" >&2; exit 1; }

log "═══════════════════════════════════════════════"
log "ClawOS Channel Rollback started"
log "═══════════════════════════════════════════════"

ROLLED_BACK=0
FAILED=0

# ── 函數：還原單一 channel ────────────────────────────────────
rollback_channel() {
    local channel_type="$1"   # telegram | web-gateway
    local config_path="${CONFIG_DIR}/${channel_type}"
    local backup_path="${BACKUP_DIR}/${channel_type}"

    log "  Processing channel: $channel_type"

    # 找最新備份設定
    local latest_backup
    latest_backup=$(ls -t "${backup_path}"/*.json 2>/dev/null | head -1 || true)
    if [[ -z "$latest_backup" ]]; then
        log "    No config backup found for $channel_type — skipping"
        return 0
    fi

    log "    Backup config: $latest_backup"

    # 備份目前的設定
    if [[ -d "$config_path" ]]; then
        local save_dir="${backup_path}/pre-rollback-${TIMESTAMP}"
        mkdir -p "$save_dir"
        cp -r "${config_path}/." "$save_dir/" 2>/dev/null || true
        log "    Current config saved → $save_dir"
    fi

    # 驗證備份 JSON 格式
    if ! python3 -c "import json,sys; json.load(open('$latest_backup'))" 2>/dev/null; then
        log "    WARNING: backup JSON is invalid, skipping $channel_type"
        (( FAILED++ )) || true
        return 1
    fi

    # 還原設定
    mkdir -p "$config_path"
    cp "$latest_backup" "${config_path}/config.json"
    log "    ✓ Config restored for $channel_type"

    # 重啟 channel service（如果有對應的 systemd unit）
    local service="clawos-channel-${channel_type}"
    if systemctl list-unit-files --quiet "${service}.service" 2>/dev/null | grep -q "$service"; then
        log "    Restarting $service..."
        if systemctl restart "$service" 2>/dev/null; then
            sleep 2
            if systemctl is-active --quiet "$service"; then
                log "    ✓ $service restarted and healthy"
            else
                log "    WARNING: $service not active after restart"
                systemctl status "$service" --no-pager -l 2>/dev/null | tail -5 || true
                (( FAILED++ )) || true
                return 1
            fi
        else
            log "    WARNING: could not restart $service"
        fi
    else
        log "    No systemd unit '$service' found — config restored, manual restart may be needed"
    fi

    (( ROLLED_BACK++ )) || true
    return 0
}

# ── 還原所有有備份的 channels ──────────────────────────────────
if [[ -d "$BACKUP_DIR" ]]; then
    for channel_dir in "$BACKUP_DIR"/*/; do
        [[ -d "$channel_dir" ]] || continue
        channel_name=$(basename "$channel_dir")
        rollback_channel "$channel_name" || true
    done
else
    log "No channel backup directory at $BACKUP_DIR"
    log "Nothing to rollback."
fi

# ── 驗證 web-gateway 健康狀態 ────────────────────────────────
if systemctl is-active --quiet clawos-agent 2>/dev/null; then
    if curl -sf http://127.0.0.1:8080/health 2>/dev/null | grep -q '"ok"'; then
        log "Web gateway health check: PASS ✓"
    else
        log "Web gateway health check: FAIL (may need manual restart)"
    fi
fi

# ── 記錄到 Vault ──────────────────────────────────────────────
cat > "${VAULT_DIR}/rollback-channel-${TIMESTAMP}.json" << JSON
{
  "event":        "channel_rollback",
  "timestamp":    "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "triggered_by": "task.failed/rollback-channel",
  "rolled_back":  $ROLLED_BACK,
  "failed":       $FAILED,
  "status":       "$([ $FAILED -eq 0 ] && echo completed || echo partial)"
}
JSON

log "═══════════════════════════════════════════════"
log "Channel rollback complete: $ROLLED_BACK succeeded, $FAILED failed."
[[ $FAILED -gt 0 ]] && exit 1 || exit 0
