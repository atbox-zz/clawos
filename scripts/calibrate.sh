#!/usr/bin/env bash
# scripts/calibrate.sh
# P4: System-wide calibration — benchmark → measure → adjust
#
# Runs:
#   P4.1 seccomp whitelist pruning (strace verification)
#   P4.2 cgroup resource value tuning (memory + CPU + pids)
#   P4.3 eBPF ring buffer sizing
#   P4.7 XDP filter performance baseline

set -euo pipefail

# ── Usage ────────────────────────────────────────────────────
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    echo "Usage: bash scripts/calibrate.sh [--help]"
    echo ""
    echo "  scripts/calibrate.sh P4: System-wide calibration — benchmark → measure → adjust Runs: "
    echo ""
    echo "詳細說明: cat scripts/SCRIPTS.md | grep -A 30 '### `calibrate.sh`'"
    exit 0
fi

GREEN="\033[0;32m"; YELLOW="\033[0;33m"; RED="\033[0;31m"; NC="\033[0m"
ok()   { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}⚠${NC} $*"; }
fail() { echo -e "${RED}✗${NC} $*"; }
section() { echo; echo -e "\n${GREEN}═══ P4.$1 — $2 ═══${NC}"; }

CLAWOS_PID=$(pgrep -x clawos-agent 2>/dev/null | head -1 || echo "")
CALIBRATION_DIR="/var/lib/clawos/calibration"
REPORT_FILE="${CALIBRATION_DIR}/calibration-$(date +%Y%m%d-%H%M%S).json"
RESULT_JSON="{}"

mkdir -p "${CALIBRATION_DIR}"

# ──────────────────────────────────────────────────────────────
section "1" "seccomp Whitelist Pruning"
# ──────────────────────────────────────────────────────────────

if [[ -n "${CLAWOS_PID}" ]]; then
    echo "  Tracing PID ${CLAWOS_PID} for 30 seconds..."
    STRACE_OUT="${CALIBRATION_DIR}/strace-$(date +%s).txt"

    timeout 30 strace -p "${CLAWOS_PID}" \
        -f -e trace=all -o "${STRACE_OUT}" 2>/dev/null || true

    # Extract unique syscalls
    ACTUAL_SYSCALLS=$(grep -oP 'syscall\(\K[0-9]+' "${STRACE_OUT}" 2>/dev/null \
        | sort -un | wc -l || echo 0)

    # Compare with whitelist
    WHITELIST_COUNT=$(python3 -c "
import json
with open('specs/p1/seccomp-whitelist.json') as f:
    d = json.load(f)
total = sum(len(v['syscalls']) for v in d['categories'].values())
print(total)
" 2>/dev/null || echo "unknown")

    ok "Actual unique syscalls observed: ${ACTUAL_SYSCALLS}"
    ok "Whitelist entries: ${WHITELIST_COUNT}"

    if [[ "${ACTUAL_SYSCALLS}" != "unknown" ]] && \
       [[ "${WHITELIST_COUNT}" != "unknown" ]] && \
       [[ "${ACTUAL_SYSCALLS}" -lt "${WHITELIST_COUNT}" ]]; then
        warn "Whitelist may have $(( WHITELIST_COUNT - ACTUAL_SYSCALLS )) unused entries — review for pruning"
    fi

    RESULT_JSON=$(echo "${RESULT_JSON}" | python3 -c "
import json,sys
d=json.load(sys.stdin)
d['p4_1_seccomp']={'actual_syscalls':${ACTUAL_SYSCALLS},'whitelist_count':'${WHITELIST_COUNT}'}
print(json.dumps(d))
")
else
    warn "clawos-agent not running — skipping live strace. Run against a test workload."
fi

# ──────────────────────────────────────────────────────────────
section "2" "cgroup Resource Calibration"
# ──────────────────────────────────────────────────────────────

CGROUP_ROOT="/sys/fs/cgroup/clawos"

calibrate_slice() {
    local SLICE="$1"
    local PATH="${CGROUP_ROOT}/${SLICE}"
    [[ -d "${PATH}" ]] || { warn "${SLICE} cgroup not found"; return; }

    local MEM_CUR=$(cat "${PATH}/memory.current" 2>/dev/null || echo 0)
    local MEM_MAX=$(cat "${PATH}/memory.max"     2>/dev/null || echo "max")
    local PID_CUR=$(cat "${PATH}/pids.current"   2>/dev/null || echo 0)
    local PID_MAX=$(cat "${PATH}/pids.max"        2>/dev/null || echo "max")
    local CPU_STAT=$(cat "${PATH}/cpu.stat"      2>/dev/null | head -3 || echo "")

    local MEM_MB=$(( MEM_CUR / 1024 / 1024 ))
    echo "  ${SLICE}: memory=${MEM_MB}MB/${MEM_MAX}  pids=${PID_CUR}/${PID_MAX}"

    # Recommend adjustment if usage is consistently < 50% of max
    if [[ "${MEM_MAX}" != "max" ]]; then
        local UTIL=$(echo "${MEM_CUR} ${MEM_MAX}" | awk '{printf "%d", $1*100/$2}')
        if [[ "${UTIL}" -lt 40 ]]; then
            warn "  → memory utilisation ${UTIL}% — consider reducing memory.max"
        elif [[ "${UTIL}" -gt 85 ]]; then
            warn "  → memory utilisation ${UTIL}% — consider increasing memory.max"
        else
            ok "  → memory utilisation ${UTIL}% — within target range"
        fi
    fi
}

for slice in agent wasm ebpf clawfs; do
    calibrate_slice "${slice}"
done

# ──────────────────────────────────────────────────────────────
section "3" "eBPF Ring Buffer Sizing"
# ──────────────────────────────────────────────────────────────

# Check if eBPF maps exist
if command -v bpftool &>/dev/null; then
    RING_MAP=$(bpftool map list 2>/dev/null | grep "EVENTS" | head -1)
    if [[ -n "${RING_MAP}" ]]; then
        MAP_ID=$(echo "${RING_MAP}" | awk '{print $1}' | tr -d ':')
        RING_SIZE=$(bpftool map show id "${MAP_ID}" 2>/dev/null | grep "max_entries" | awk '{print $2}' || echo "?")
        ok "Ring buffer map found: size=${RING_SIZE} bytes"

        # Check for dropped events (key indicator of undersized buffer)
        DROPS=$(bpftool map dump id "${MAP_ID}" 2>/dev/null | grep -c "drop" || echo 0)
        if [[ "${DROPS}" -gt 0 ]]; then
            warn "Ring buffer drops detected: ${DROPS} — consider increasing to 8MB"
        else
            ok "No ring buffer drops detected — current size adequate"
        fi
    else
        warn "No EVENTS ring buffer found — is clawos-ebpf running?"
    fi
else
    warn "bpftool not available — skipping ring buffer check"
fi

# ──────────────────────────────────────────────────────────────
section "7" "XDP Network Filter Baseline"
# ──────────────────────────────────────────────────────────────

VETH="veth-clawos0"
if ip link show "${VETH}" &>/dev/null; then
    # Use ethtool to get packet stats
    RX_PACKETS=$(cat "/sys/class/net/${VETH}/statistics/rx_packets" 2>/dev/null || echo 0)
    TX_PACKETS=$(cat "/sys/class/net/${VETH}/statistics/tx_packets" 2>/dev/null || echo 0)
    RX_DROPPED=$(cat "/sys/class/net/${VETH}/statistics/rx_dropped" 2>/dev/null || echo 0)

    ok "Interface ${VETH}: RX=${RX_PACKETS} TX=${TX_PACKETS} DROPPED=${RX_DROPPED}"

    DROP_RATE=$(echo "${RX_DROPPED} ${RX_PACKETS}" | awk '{if($2>0) printf "%.2f", $1*100/$2; else print "0"}')
    if (( $(echo "${DROP_RATE} > 5.0" | bc -l 2>/dev/null || echo 0) )); then
        warn "Drop rate ${DROP_RATE}% — XDP filter may be too aggressive"
    else
        ok "Drop rate ${DROP_RATE}% — within acceptable range"
    fi
else
    warn "Interface ${VETH} not found — run scripts/setup-netns.sh first"
fi

# ──────────────────────────────────────────────────────────────
section "8" "Full System cargo test"
# ──────────────────────────────────────────────────────────────

echo "  Running cargo test --workspace..."
if cargo test --workspace --quiet 2>&1 | tee /tmp/test-output.txt; then
    PASS=$(grep -c "test.*ok" /tmp/test-output.txt || echo 0)
    ok "All tests passed (${PASS} tests)"
    RESULT_JSON=$(echo "${RESULT_JSON}" | python3 -c "
import json,sys
d=json.load(sys.stdin)
d['p4_8_tests']={'status':'passed','count':${PASS}}
print(json.dumps(d))
")
else
    FAIL=$(grep -c "FAILED" /tmp/test-output.txt || echo 0)
    fail "Tests failed (${FAIL} failures)"
    RESULT_JSON=$(echo "${RESULT_JSON}" | python3 -c "
import json,sys
d=json.load(sys.stdin)
d['p4_8_tests']={'status':'failed','failures':${FAIL}}
print(json.dumps(d))
")
fi

# ──────────────────────────────────────────────────────────────
# Write calibration report
# ──────────────────────────────────────────────────────────────

RESULT_JSON=$(echo "${RESULT_JSON}" | python3 -c "
import json,sys,time
d=json.load(sys.stdin)
d['timestamp']   = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
d['phase']       = 'P4'
d['hostname']    = '$(hostname)'
print(json.dumps(d, indent=2))
")

echo "${RESULT_JSON}" > "${REPORT_FILE}"

echo
echo "══════════════════════════════════════════════"
echo -e "  ${GREEN}Calibration report saved:${NC}"
echo "  ${REPORT_FILE}"
echo "══════════════════════════════════════════════"
