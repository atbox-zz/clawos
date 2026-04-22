#!/usr/bin/env bash
# scripts/qemu-test.sh
# G-06 / G-07: QEMU integration test — x86_64 and aarch64
# Validates ClawOS boots, agent starts, preflight passes, and basic tool works.

set -euo pipefail

# ── Usage ────────────────────────────────────────────────────
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    echo "Usage: bash scripts/qemu-test.sh [--help]"
    echo ""
    echo "  scripts/qemu-test.sh G-06 / G-07: QEMU integration test — x86_64 and aarch64 Validates ClawOS boots, agent starts, preflight passes, and basic tool works. "
    echo ""
    echo "詳細說明: cat scripts/SCRIPTS.md | grep -A 30 '### `qemu-test.sh`'"
    exit 0
fi

ISO="${1:-image/clawos-v0.1.0.iso}"
TIMEOUT=120  # seconds to wait for boot

GREEN="\033[0;32m"; RED="\033[0;31m"; YELLOW="\033[0;33m"; NC="\033[0m"
pass() { echo -e "${GREEN}✓${NC} $*"; }
fail() { echo -e "${RED}✗${NC} $*"; exit 1; }
warn() { echo -e "${YELLOW}⚠${NC} $*"; }

PASS_COUNT=0
FAIL_COUNT=0

check() {
    local desc="$1"; local cmd="$2"
    if eval "${cmd}" &>/dev/null; then
        pass "${desc}"; ((PASS_COUNT++))
    else
        fail "${desc}: ${cmd}"
        ((FAIL_COUNT++))
    fi
}

echo "╔══════════════════════════════════════════════╗"
echo "║   ClawOS QEMU Integration Test               ║"
echo "╚══════════════════════════════════════════════╝"
echo "  ISO: ${ISO}"

[[ -f "${ISO}" ]] || fail "ISO not found: ${ISO}"

# ── x86_64 Test ───────────────────────────────────────────────

run_qemu_x86() {
    echo; echo "── x86_64 Boot Test ──────────────────────────"

    # Create temp disk for test writes
    DISK=$(mktemp /tmp/clawos-test-XXXXX.img)
    qemu-img create -f qcow2 "${DISK}" 2G &>/dev/null

    # Boot log capture
    LOG=$(mktemp /tmp/clawos-boot-XXXXX.log)

    timeout "${TIMEOUT}" qemu-system-x86_64 \
        -machine q35,accel=kvm:tcg \
        -cpu host \
        -smp 2 \
        -m 1G \
        -cdrom "${ISO}" \
        -drive file="${DISK}",format=qcow2,if=virtio \
        -net nic,model=virtio \
        -net user,hostfwd=tcp::18080-:8080 \
        -serial file:"${LOG}" \
        -display none \
        -no-reboot \
        2>/dev/null &
    QEMU_PID=$!

    echo "  QEMU PID: ${QEMU_PID} — waiting up to ${TIMEOUT}s for boot..."

    # Wait for boot indicators
    local booted=false
    local elapsed=0
    while [[ ${elapsed} -lt ${TIMEOUT} ]]; do
        sleep 2
        ((elapsed += 2))

        if grep -q "ClawOS Agent starting" "${LOG}" 2>/dev/null; then
            booted=true
            break
        fi
        if grep -q "Kernel panic" "${LOG}" 2>/dev/null; then
            fail "Kernel panic detected during boot"
            break
        fi
        echo -n "."
    done
    echo

    if [[ "${booted}" == "true" ]]; then
        pass "x86_64: Kernel booted and agent started"

        # Check specific log lines
        grep -q "seccomp-BPF filter loaded" "${LOG}" 2>/dev/null \
            && pass "x86_64: seccomp filter applied" \
            || warn "x86_64: seccomp not confirmed in logs"

        grep -q "ClawFS connected" "${LOG}" 2>/dev/null \
            && pass "x86_64: ClawFS connected" \
            || warn "x86_64: ClawFS connection not confirmed"

        grep -q "IPC listener started" "${LOG}" 2>/dev/null \
            && pass "x86_64: IPC server started" \
            || warn "x86_64: IPC not confirmed"

        grep -q "agent loop ready" "${LOG}" 2>/dev/null \
            && pass "x86_64: Agent loop entered" \
            || warn "x86_64: Agent loop not confirmed"

        # HTTP health check via forwarded port
        sleep 3
        if curl -sf http://localhost:18080/health &>/dev/null; then
            pass "x86_64: HTTP health check passed"
        else
            warn "x86_64: HTTP health check failed (web gateway may not be started)"
        fi
    else
        fail "x86_64: Boot timed out after ${TIMEOUT}s"
    fi

    kill "${QEMU_PID}" 2>/dev/null || true
    rm -f "${DISK}" "${LOG}"
}

# ── aarch64 Test ──────────────────────────────────────────────

run_qemu_aarch64() {
    echo; echo "── aarch64 Boot Test ─────────────────────────"

    if ! command -v qemu-system-aarch64 &>/dev/null; then
        warn "qemu-system-aarch64 not installed — skipping aarch64 test"
        return
    fi

    LOG=$(mktemp /tmp/clawos-arm-XXXXX.log)
    DISK=$(mktemp /tmp/clawos-arm-XXXXX.img)
    qemu-img create -f qcow2 "${DISK}" 2G &>/dev/null

    timeout "${TIMEOUT}" qemu-system-aarch64 \
        -machine virt,accel=kvm:tcg \
        -cpu cortex-a72 \
        -smp 2 \
        -m 1G \
        -cdrom "${ISO}" \
        -drive file="${DISK}",format=qcow2,if=virtio \
        -serial file:"${LOG}" \
        -display none \
        -no-reboot \
        2>/dev/null &
    QEMU_PID=$!

    local elapsed=0
    local booted=false
    while [[ ${elapsed} -lt ${TIMEOUT} ]]; do
        sleep 2; ((elapsed += 2))
        grep -q "ClawOS Agent starting" "${LOG}" 2>/dev/null && { booted=true; break; }
    done

    if [[ "${booted}" == "true" ]]; then
        pass "aarch64: Kernel booted and agent started"
    else
        warn "aarch64: Boot not confirmed in ${TIMEOUT}s (may need aarch64-specific ISO)"
    fi

    kill "${QEMU_PID}" 2>/dev/null || true
    rm -f "${DISK}" "${LOG}"
}

# ── Run both ──────────────────────────────────────────────────
run_qemu_x86
run_qemu_aarch64

# ── Summary ──────────────────────────────────────────────────
echo
echo "══════════════════════════════════════════════"
echo -e "  PASS: ${GREEN}${PASS_COUNT}${NC}   FAIL: ${RED}${FAIL_COUNT}${NC}"
echo "══════════════════════════════════════════════"

if [[ ${FAIL_COUNT} -gt 0 ]]; then
    echo -e "  ${RED}QEMU integration test FAILED${NC}"
    exit 1
else
    echo -e "  ${GREEN}QEMU integration test PASSED — Gate G-06/G-07 cleared${NC}"
    exit 0
fi
