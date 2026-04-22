#!/usr/bin/env bash
# scripts/setup-cgroups.sh
# C-06: cgroup v2 resource limits for ClawOS processes
# Values from specs/p1/resource-quotas.json
#set -euo pipefail

# ── Usage ────────────────────────────────────────────────────
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    echo "Usage: bash scripts/setup-cgroups.sh [--help]"
    echo ""
    echo "  scripts/setup-cgroups.sh C-06: cgroup v2 resource limits for ClawOS processes "
    echo ""
    echo "詳細說明: cat scripts/SCRIPTS.md | grep -A 30 '### `setup-cgroups.sh`'"
    exit 0
fi

CGROUP_ROOT="/sys/fs/cgroup/clawos"

log()  { echo "[$(date -u +%H:%M:%S)] $*"; }
die()  { echo "[ERROR] $*" >&2; exit 1; }
cset() { echo "$2" > "$1" && log "  set ${1##*/cgroup*/} = $2"; }

[[ $EUID -eq 0 ]] || die "Must run as root"

# Verify cgroup v2
mountpoint -q /sys/fs/cgroup || die "/sys/fs/cgroup not mounted"
grep -q "cgroup2" /proc/mounts || die "cgroup v2 not available — check kernel config"

log "Setting up ClawOS cgroup hierarchy under ${CGROUP_ROOT}"

# ── Create subtree ───────────────────────────────────────────
for slice in agent wasm ebpf clawfs; do
    mkdir -p "${CGROUP_ROOT}/${slice}"
done

# Enable controllers at root and subtrees
echo "+memory +cpu +pids +io" > "${CGROUP_ROOT}/cgroup.subtree_control" 2>/dev/null || true
for slice in agent wasm ebpf clawfs; do
    echo "+memory +cpu +pids" > "${CGROUP_ROOT}/${slice}/cgroup.subtree_control" 2>/dev/null || true
done

log "Cgroup subtree created"

# ── Agent process slice ──────────────────────────────────────
log "[agent_process] Applying resource limits..."
AGENT="${CGROUP_ROOT}/agent"
cset "${AGENT}/memory.max"          "536870912"      # 512MB
cset "${AGENT}/memory.swap.max"     "0"
cset "${AGENT}/memory.high"         "419430400"      # 400MB soft
cset "${AGENT}/memory.min"          "67108864"       # 64MB guaranteed
cset "${AGENT}/cpu.max"             "50000 100000"   # 50% of one core
cset "${AGENT}/cpu.weight"          "512"
cset "${AGENT}/pids.max"            "128"

# IO limits — detect main disk device
DISK_DEV=$(lsblk -ndo MAJ:MIN $(findmnt -n -o SOURCE /) 2>/dev/null | head -1)
if [[ -n "${DISK_DEV}" ]]; then
    cset "${AGENT}/io.max" "${DISK_DEV} rbps=52428800 wbps=52428800 riops=1000 wiops=1000"
fi

# ── WASM worker slice ────────────────────────────────────────
log "[wasm_worker] Applying resource limits..."
WASM="${CGROUP_ROOT}/wasm"
cset "${WASM}/memory.max"           "134217728"      # 128MB per worker pool
cset "${WASM}/memory.swap.max"      "0"
cset "${WASM}/cpu.max"              "25000 100000"   # 25% of one core
cset "${WASM}/cpu.weight"           "256"
cset "${WASM}/pids.max"             "64"

# ── eBPF monitor slice ───────────────────────────────────────
log "[ebpf_monitor] Applying resource limits..."
EBPF="${CGROUP_ROOT}/ebpf"
cset "${EBPF}/memory.max"           "67108864"       # 64MB
cset "${EBPF}/memory.swap.max"      "0"
cset "${EBPF}/cpu.max"              "10000 100000"   # 10% of one core
cset "${EBPF}/cpu.weight"           "128"
cset "${EBPF}/pids.max"             "8"

# ── ClawFS daemon slice ──────────────────────────────────────
log "[clawfs_daemon] Applying resource limits..."
CLAWFS="${CGROUP_ROOT}/clawfs"
cset "${CLAWFS}/memory.max"         "268435456"      # 256MB
cset "${CLAWFS}/memory.swap.max"    "0"
cset "${CLAWFS}/cpu.max"            "30000 100000"   # 30%
cset "${CLAWFS}/cpu.weight"         "384"
cset "${CLAWFS}/pids.max"           "32"

# ── Global swappiness ────────────────────────────────────────
log "Setting system swappiness to 0..."
sysctl -w vm.swappiness=0 > /dev/null
echo "vm.swappiness=0" > /etc/sysctl.d/99-clawos.conf

# ── Validation ───────────────────────────────────────────────
log ""
log "=== Validation ==="
for slice in agent wasm ebpf clawfs; do
    ACTUAL_MEM=$(cat "${CGROUP_ROOT}/${slice}/memory.max")
    ACTUAL_PIDS=$(cat "${CGROUP_ROOT}/${slice}/pids.max")
    log "  ${slice}: memory.max=${ACTUAL_MEM} pids.max=${ACTUAL_PIDS}"
done

log ""
log "cgroup v2 setup complete. Join slices by writing PID to:"
log "  echo \$PID > ${CGROUP_ROOT}/agent/cgroup.procs"
log "  echo \$PID > ${CGROUP_ROOT}/wasm/cgroup.procs"
log "  echo \$PID > ${CGROUP_ROOT}/ebpf/cgroup.procs"
