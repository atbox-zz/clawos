#!/usr/bin/env bash
# scripts/rollback-tool-update.sh
#
# Rollback: WASM tool update reversal
#
# What this does:
#   1. 找出失敗的 tool 名稱（從 task result 記錄）
#   2. 在備份目錄找到前一版的 tool.wasm
#   3. 替換回前一版 WASM binary
#   4. 重新載入 tool registry
#   5. 記錄事件到 Vault
#
# 觸發條件：IPC task.failed 訊息中帶 rollback_name=rollback-tool-update

set -euo pipefail

CLAWOS_HOME="${CLAWOS_HOME:-/var/lib/clawos}"
TOOLS_DIR="${CLAWOS_HOME}/tools"
BACKUP_DIR="${CLAWOS_HOME}/backups/tools"
LOG="${CLAWOS_HOME}/logs/rollback-tool-update.log"
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)

mkdir -p "$(dirname "$LOG")"
exec >> "$LOG" 2>&1

log() { echo "[${TIMESTAMP}] $*"; }
die() { echo "[${TIMESTAMP}] ERROR: $*" >&2; exit 1; }

log "═══════════════════════════════════════════════"
log "ClawOS Tool Update Rollback started"
log "═══════════════════════════════════════════════"

if [[ ! -d "$BACKUP_DIR" ]]; then
    log "No backup directory at $BACKUP_DIR — nothing to rollback."
    exit 0
fi

ROLLED_BACK=0
FAILED=0

# ── 遍歷每個有備份的 tool ─────────────────────────────────────
for tool_backup_dir in "$BACKUP_DIR"/*/; do
    tool_name=$(basename "$tool_backup_dir")
    tool_dir="${TOOLS_DIR}/${tool_name}"
    current_wasm="${tool_dir}/tool.wasm"

    # 找最新備份（依時間戳排序）
    latest_backup=$(ls -t "${tool_backup_dir}"*.wasm 2>/dev/null | head -1 || true)
    if [[ -z "$latest_backup" ]]; then
        log "  $tool_name: no .wasm backup found, skipping"
        continue
    fi

    log "  Rolling back $tool_name:"
    log "    backup: $latest_backup"
    log "    target: $current_wasm"

    # 備份現有版本（以防 rollback 本身也失敗）
    if [[ -f "$current_wasm" ]]; then
        FAILED_BACKUP="${tool_backup_dir}failed-${TIMESTAMP}.wasm"
        cp "$current_wasm" "$FAILED_BACKUP"
        log "    saved failing version → $FAILED_BACKUP"
    fi

    # 驗證備份 WASM 的 magic bytes（\0asm = WASM binary format）
    MAGIC=$(xxd -l 4 "$latest_backup" 2>/dev/null | awk '{print $2$3}' || true)
    if [[ "$MAGIC" != "0061736d" ]]; then
        log "    WARNING: $latest_backup does not look like a WASM binary (magic=$MAGIC), skipping"
        (( FAILED++ )) || true
        continue
    fi

    mkdir -p "$tool_dir"
    cp "$latest_backup" "$current_wasm"
    chmod 644 "$current_wasm"
    log "    ✓ restored $tool_name"
    (( ROLLED_BACK++ )) || true
done

# ── 通知 agent 重新載入 tool registry ────────────────────────
if [[ $ROLLED_BACK -gt 0 ]]; then
    RELOAD_MSG=$(cat << JSON
{"id":"rollback-reload-${TIMESTAMP}","version":1,"type":"admin.reload_tools",
 "from":"rollback-tool-update","to":"clawos-agent",
 "timestamp":$(date +%s000),"payload":{"reason":"tool_rollback"}}
JSON
)
    SOCK="/var/run/clawos/agent.sock"
    if [[ -S "$SOCK" ]]; then
        echo "$RELOAD_MSG" | socat - UNIX-CONNECT:"$SOCK" 2>/dev/null && \
            log "Agent notified to reload tool registry ✓" || \
            log "Warning: could not notify agent (will reload on next restart)"
    else
        log "IPC socket not found — agent will reload tools on next restart"
    fi
fi

# ── 記錄事件到 Vault ──────────────────────────────────────────
VAULT_DIR="${CLAWOS_HOME}/vault"
cat > "${VAULT_DIR}/rollback-tool-update-${TIMESTAMP}.json" << JSON
{
  "event":         "tool_update_rollback",
  "timestamp":     "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "triggered_by":  "task.failed/rollback-tool-update",
  "rolled_back":   $ROLLED_BACK,
  "failed":        $FAILED,
  "status":        "$([ $FAILED -eq 0 ] && echo completed || echo partial)"
}
JSON

log "═══════════════════════════════════════════════"
log "Tool rollback complete: $ROLLED_BACK succeeded, $FAILED failed."
[[ $FAILED -gt 0 ]] && exit 1 || exit 0
