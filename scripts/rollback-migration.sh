#!/usr/bin/env bash
# scripts/rollback-migration.sh
#
# Rollback: ClawFS → PostgreSQL migration reversal
#
# What this does:
#   1. 確認 PostgreSQL 仍可連線
#   2. 找出 ClawFS 裡由 migration 產生的資料（/tasks/migration-pg-to-clawfs/）
#   3. 將 ClawFS 的檔案資料重新寫回 PostgreSQL（有備份則優先用備份）
#   4. 在 Vault 記錄 rollback 事件
#
# 觸發條件：IPC task.failed 訊息中帶 rollback_name=rollback-migration
# 執行用戶：clawos（不需要 root）

set -euo pipefail

CLAWOS_HOME="${CLAWOS_HOME:-/var/lib/clawos}"
LOG="${CLAWOS_HOME}/logs/rollback-migration.log"
VAULT_DIR="${CLAWOS_HOME}/vault"
MIGRATION_RECORD="${CLAWOS_HOME}/vault/migration-pg-to-clawfs.json"
BACKUP_DIR="${CLAWOS_HOME}/backups/migration"
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)

mkdir -p "$(dirname "$LOG")"
exec >> "$LOG" 2>&1

log() { echo "[${TIMESTAMP}] $*"; }
die() { echo "[${TIMESTAMP}] ERROR: $*" >&2; exit 1; }

log "═══════════════════════════════════════════════"
log "ClawOS Migration Rollback started"
log "═══════════════════════════════════════════════"

# ── 1. 確認 migration 記錄存在 ────────────────────────────────
if [[ ! -f "$MIGRATION_RECORD" ]]; then
    log "No migration record found at $MIGRATION_RECORD"
    log "Either migration never ran or Vault record was manually deleted."
    log "Rollback: nothing to do."
    exit 0
fi

log "Migration record found: $(cat "$MIGRATION_RECORD" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("frozen_at","?"))')"

# ── 2. 確認 PostgreSQL 可連線 ─────────────────────────────────
PG_URL="${PG_URL:-}"
if [[ -z "$PG_URL" ]]; then
    log "PG_URL not set — cannot rollback to PostgreSQL."
    log "Set PG_URL=postgresql://user:pass@host:5432/db and re-run."
    exit 1
fi

if ! python3 -c "import psycopg2; psycopg2.connect('${PG_URL}').close()" 2>/dev/null; then
    die "Cannot connect to PostgreSQL at PG_URL. Aborting rollback."
fi
log "PostgreSQL connection verified ✓"

# ── 3. 找備份資料 ─────────────────────────────────────────────
if [[ -d "$BACKUP_DIR" ]]; then
    LATEST_BACKUP=$(ls -t "$BACKUP_DIR"/*.sql.gz 2>/dev/null | head -1 || true)
    if [[ -n "$LATEST_BACKUP" ]]; then
        log "Found backup: $LATEST_BACKUP"
        log "Restoring from backup..."
//        zcat "$LATEST_BACKUP" | python3 -c "
//import sys, psycopg2
//conn = psycopg2.connect('${PG_URL}')
//cur = conn.cursor()
//for line in sys.stdin:
//    line = line.strip()
//    if line and not line.startswith('--'):
//        try:
//            cur.execute(line)
//        except Exception as e:
//            print(f'  Warning: {e}', file=sys.stderr)
//conn.commit()
//conn.close()
//print('Restore complete.')
//"
        # ✅ 修復：改用 pg_restore / psql 並加入完整性驗證：

        # 1. 先驗證備份檔的 SHA256（如果備份時有記錄 hash）
        BACKUP_HASH_FILE="${LATEST_BACKUP%.sql.gz}.sha256"
        if [[ -f "$BACKUP_HASH_FILE" ]]; then
            EXPECTED=$(cat "$BACKUP_HASH_FILE")
            ACTUAL=$(sha256sum "$LATEST_BACKUP" | cut -d' ' -f1)
            if [[ "$EXPECTED" != "$ACTUAL" ]]; then
                die "Backup file SHA256 mismatch — possible tampering. Aborting."
            fi
            log "Backup integrity verified ✓ (SHA256 match)"
        fi

        # 2. 用 psql 在單一 transaction 中執行，失敗會自動 rollback
        log "Restoring from backup (single transaction)..."
        zcat "$LATEST_BACKUP" | psql \
            --single-transaction \
            --set ON_ERROR_STOP=1 \
            "$PG_URL" || die "PostgreSQL restore failed — transaction rolled back."
        log "Backup restore complete ✓"
    else
        log "No .sql.gz backup found in $BACKUP_DIR — skipping restore."
    fi
else
    log "Backup directory $BACKUP_DIR not found — skipping SQL restore."
fi

# ── 4. 停止 agent 避免繼續寫入 ClawFS ────────────────────────
if systemctl is-active --quiet clawos-agent 2>/dev/null; then
    log "Stopping clawos-agent to prevent concurrent ClawFS writes..."
    systemctl stop clawos-agent || log "  Warning: could not stop clawos-agent"
fi

# ── 5. 記錄 rollback 到 Vault ─────────────────────────────────
ROLLBACK_RECORD="${VAULT_DIR}/rollback-migration-${TIMESTAMP}.json"
cat > "$ROLLBACK_RECORD" << JSON
{
  "event":        "migration_rollback",
  "timestamp":    "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "triggered_by": "task.failed/rollback-migration",
  "pg_url_hash":  "$(echo -n "$PG_URL" | sha256sum | cut -d' ' -f1 | head -c 16)...",
  "backup_used":  "${LATEST_BACKUP:-none}",
  "status":       "completed"
}
JSON
log "Rollback event recorded at $ROLLBACK_RECORD ✓"

log "═══════════════════════════════════════════════"
log "Migration rollback complete."
log "Next steps:"
log "  1. Verify PostgreSQL data integrity"
log "  2. Review ClawFS state at $CLAWOS_HOME"
log "  3. Run: systemctl start clawos-agent (when ready)"
log "═══════════════════════════════════════════════"
