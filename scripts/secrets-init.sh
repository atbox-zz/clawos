#!/usr/bin/env bash
# scripts/secrets-init.sh
# Bootstrap ClawOS secrets into the kernel keyring.
# Reads from .env or prompts interactively.
# Run as the clawos user (not root) so keys land in user keyring.

set -euo pipefail

# ── Usage ────────────────────────────────────────────────────
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    echo "Usage: bash scripts/secrets-init.sh [--help]"
    echo ""
    echo "  scripts/secrets-init.sh Bootstrap ClawOS secrets into the kernel keyring. "
    echo ""
    echo "詳細說明: cat scripts/SCRIPTS.md | grep -A 30 '### `secrets-init.sh`'"
    exit 0
fi

GREEN="\033[0;32m"; YELLOW="\033[0;33m"; RED="\033[0;31m"; NC="\033[0m"
ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $*"; }
skip() { echo -e "  ${YELLOW}–${NC} $*"; }

echo "╔══════════════════════════════════════════╗"
echo "║  ClawOS Secrets Init — Kernel Keyring    ║"
echo "╚══════════════════════════════════════════╝"
echo

# Check keyctl available
if ! command -v keyctl &>/dev/null; then
    echo -e "  ${RED}keyctl not found${NC} — install keyutils: apt install keyutils"
    exit 1
fi

# Show session keyring
KEYRING=$(keyctl describe @s 2>/dev/null | awk '{print $NF}' || echo "unknown")
echo "  Session keyring: ${KEYRING}"
echo

# Source .env if present
if [[ -f .env ]]; then
    set -a
    source .env
    set +a
    ok ".env loaded"
fi

# ── Helper: add key if var is set, else prompt ────────────────

add_key() {
    local KEY_NAME="$1"
    local ENV_VAR="$2"
    local PROMPT_MSG="$3"
    local OPTIONAL="${4:-false}"

    local VALUE="${!ENV_VAR:-}"

    if [[ -z "${VALUE}" ]]; then
        if [[ "${OPTIONAL}" == "true" ]]; then
            skip "${KEY_NAME}: not set (optional)"
            return
        fi
        read -r -s -p "  Enter ${PROMPT_MSG} (hidden): " VALUE
        echo
    fi

    if [[ -z "${VALUE}" ]]; then
        warn "${KEY_NAME}: empty — skipped"
        return
    fi

    # Check if key already exists
    if keyctl search @s user "${KEY_NAME}" &>/dev/null; then
        warn "${KEY_NAME}: already in keyring — updating"
        keyctl update "$(keyctl search @s user "${KEY_NAME}")" "${VALUE}"
    else
        keyctl add user "${KEY_NAME}" "${VALUE}" @s >/dev/null
    fi

    ok "${KEY_NAME}: set (${#VALUE} chars)"
}

# ── Required secrets ─────────────────────────────────────────

echo "── ClawFS Encryption Key ────────────────────────────────"
# Validate: must be 64 hex chars
if [[ -n "${CLAWFS_KEY:-}" ]]; then
    if [[ ! "${CLAWFS_KEY}" =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo -e "  ${RED}✗ CLAWFS_KEY must be 64 hex chars (32 bytes)${NC}"
        echo "  Generate: openssl rand -hex 32"
        exit 1
    fi
fi
add_key "clawfs-key" "CLAWFS_KEY" "ClawFS AES-256 key (64 hex chars)"

echo
echo "── LLM Provider API Key ─────────────────────────────────"
add_key "clawos-llm-api-key" "CLAWOS_LLM_API_KEY" "NEAR AI or OpenRouter API key"

echo
echo "── Search Provider Key ──────────────────────────────────"
add_key "clawos-search-key" "CLAWOS_SEARCH_KEY" "Brave Search / Tavily API key" "true"

echo
echo "── Telegram Bot Token ───────────────────────────────────"
add_key "telegram-bot-token" "TELEGRAM_BOT_TOKEN" "Telegram Bot Token from @BotFather" "true"

echo
echo "── Summary ──────────────────────────────────────────────"
echo "  Keys in session keyring (@s):"
keyctl list @s 2>/dev/null | grep "user:" | sed 's/^/    /' || echo "  (none)"

echo
echo "  Key persistence: session keyring (@s) — survives until logout"
echo "  For production persistence, link to user keyring:"
echo "    keyctl link @s @u"
echo
echo -e "  ${GREEN}Secrets initialised ✅${NC}"
echo "  Next: run 'bash scripts/preflight.sh' to verify"
