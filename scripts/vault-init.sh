#!/usr/bin/env bash
# scripts/vault-init.sh
# Freeze all P1 spec files into the ClawFS Vault.
# Run once after initial setup, before the P1→P2 gate.
# Idempotent: calling again with the same hashes is a no-op.
# Calling with different hashes exits non-zero (E002).

set -euo pipefail

# ── Usage ────────────────────────────────────────────────────
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    echo "Usage: bash scripts/vault-init.sh [--help]"
    echo ""
    echo "  scripts/vault-init.sh Freeze all P1 spec files into the ClawFS Vault. "
    echo ""
    echo "詳細說明: cat scripts/SCRIPTS.md | grep -A 30 '### `vault-init.sh`'"
    exit 0
fi

GREEN="\033[0;32m"; RED="\033[0;31m"; YELLOW="\033[0;33m"; NC="\033[0m"
ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
fail() { echo -e "  ${RED}✗${NC} $*"; exit 1; }
warn() { echo -e "  ${YELLOW}⚠${NC} $*"; }

VAULT_DIR="${VAULT_DIR:-/var/lib/clawos/vault}"
AGENT="${VAULT_AGENT:-preflight}"
CLAWFS_DB="${CLAWFS_DB:-/var/lib/clawos/clawfs.db}"

mkdir -p "${VAULT_DIR}"

echo "╔══════════════════════════════════════════╗"
echo "║  ClawOS Vault Initialisation             ║"
echo "║  Freezing P1 specifications              ║"
echo "╚══════════════════════════════════════════╝"
echo "  Vault: ${VAULT_DIR}"
echo "  Agent: ${AGENT}"
echo

freeze_spec() {
    local SPEC_ID="$1"
    local FILE_PATH="$2"

    [[ -f "${FILE_PATH}" ]] || { fail "${SPEC_ID}: file not found: ${FILE_PATH}"; return; }

    local SHA=$(sha256sum "${FILE_PATH}" | cut -d' ' -f1)
    local VAULT_FILE="${VAULT_DIR}/${SPEC_ID}.json"
    local NOW=$(date -u +%s000)
    local FROZEN_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    if [[ -f "${VAULT_FILE}" ]]; then
        # Already frozen — verify hash matches
        local STORED_SHA=$(python3 -c "import json; print(json.load(open('${VAULT_FILE}'))['sha256'])" 2>/dev/null || echo "")
        if [[ "${STORED_SHA}" == "${SHA}" ]]; then
            ok "${SPEC_ID}: already frozen (sha256 matches)"
            return
        else
            fail "E002 SPEC_HASH_MISMATCH: ${SPEC_ID} was frozen as ${STORED_SHA}, now ${SHA}. STOP."
        fi
    fi

    # Write vault entry
    python3 - <<EOF
import json, sys
entry = {
    "spec_id":   "${SPEC_ID}",
    "path":      "${FILE_PATH}",
    "sha256":    "${SHA}",
    "frozen_at": ${NOW},
    "frozen_at_iso": "${FROZEN_AT}",
    "signed_by": "${AGENT}",
    "phase":     "P1"
}
with open("${VAULT_FILE}", 'w') as f:
    json.dump(entry, f, indent=2)
print(f"  Vault entry written: ${SPEC_ID}")
EOF

    ok "${SPEC_ID}: frozen (${SHA:0:16}...)"

    # Also write to ClawFS SQLite vault table if DB exists
    if [[ -f "${CLAWFS_DB}" ]]; then
        sqlite3 "${CLAWFS_DB}" \
            "INSERT OR IGNORE INTO vault (spec_id, path, sha256, frozen_at, signed_by)
             VALUES ('${SPEC_ID}', '${FILE_PATH}', '${SHA}', ${NOW}, '${AGENT}');" 2>/dev/null || true
    fi
}

# ── Freeze all P1 specs ───────────────────────────────────────

echo "── P1 Specifications ────────────────────────────────────"
freeze_spec "P1.1-wit"             "wit/clawos.wit"
freeze_spec "P1.2-seccomp"         "specs/p1/seccomp-whitelist.json"
freeze_spec "P1.3-ebpf-structs"    "specs/p1/ebpf-event-structs.rs"
freeze_spec "P1.4-clawfs"          "specs/p1/clawfs-spec.json"
freeze_spec "P1.5-resource-quotas" "specs/p1/resource-quotas.json"
freeze_spec "P1.6-apparmor"        "specs/p1/apparmor-spec.json"
freeze_spec "P1.7-ipc-protocol"    "specs/p1/ipc-protocol.json"
freeze_spec "P1.8-api-surface"     "specs/p1/api-surface.json"

echo
echo "── Additional artifacts ─────────────────────────────────"
freeze_spec "VAULT-INIT-SCRIPT"    "scripts/vault-init.sh"
freeze_spec "CLAUDE-MD"            "CLAUDE.md"

echo
echo "── Summary ──────────────────────────────────────────────"
FROZEN_COUNT=$(ls "${VAULT_DIR}"/*.json 2>/dev/null | wc -l)
echo "  Frozen entries: ${FROZEN_COUNT}"
ls -la "${VAULT_DIR}/" | grep ".json" | awk '{print "  " $NF}'

echo
echo -e "  ${GREEN}Vault initialisation complete ✅${NC}"
echo "  Next: run 'bash scripts/preflight.sh' to verify all specs"
