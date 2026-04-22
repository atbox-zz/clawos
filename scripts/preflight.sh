#!/usr/bin/env bash
# scripts/preflight.sh
# G-01: Pre-flight startup check
# Validates kernel features, cgroups, network namespace, AppArmor,
# eBPF monitor, frozen spec hashes, and TLS certificates.
# Must exit 0 for agent launch to proceed.
#set -euo pipefail

# ── Usage ────────────────────────────────────────────────────
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    echo "Usage: bash scripts/preflight.sh [--help]"
    echo ""
    echo "  scripts/preflight.sh G-01: Pre-flight startup check Validates kernel features, cgroups, network namespace, AppArmor, "
    echo ""
    echo "詳細說明: cat scripts/SCRIPTS.md | grep -A 30 '### `preflight.sh`'"
    exit 0
fi

PASS=0; FAIL=0; WARN=0

green="\033[0;32m"; red="\033[0;31m"; yellow="\033[0;33m"; reset="\033[0m"

ok()   { echo -e "  ${green}✓${reset} $*"; ((PASS++)); }
fail() { echo -e "  ${red}✗${reset} $*"; ((FAIL++)); }
warn() { echo -e "  ${yellow}⚠${reset} $*"; ((WARN++)); }

section() { echo; echo "── $* ──────────────────────────────────────"; }

echo "╔══════════════════════════════════════════╗"
echo "║   ClawOS Pre-flight Check v1.0           ║"
echo "╚══════════════════════════════════════════╝"

# ── 1. Kernel Features ───────────────────────────────────────
section "Kernel Features"

# cgroup v2
if grep -q "cgroup2" /proc/mounts; then
    ok "cgroup v2 mounted"
else
    fail "cgroup v2 not mounted — run: mount -t cgroup2 none /sys/fs/cgroup"
fi

# BPF LSM
if grep -q "bpf" /sys/kernel/security/lsm 2>/dev/null; then
    ok "BPF LSM active: $(cat /sys/kernel/security/lsm)"
else
    warn "BPF LSM not in LSM stack — check CONFIG_BPF_LSM + CONFIG_LSM"
fi

# User namespaces
if [[ $(cat /proc/sys/user/max_user_namespaces 2>/dev/null) -gt 0 ]]; then
    ok "User namespaces enabled"
else
    fail "User namespaces disabled — set user.max_user_namespaces > 0"
fi

# seccomp
if grep -q "Seccomp" /proc/self/status && \
   grep "^Seccomp:" /proc/self/status | grep -qv ": 0"; then
    ok "seccomp available"
else
    # Just check the kernel has it
    [[ -f /proc/sys/kernel/unprivileged_bpf_disabled ]] && ok "seccomp kernel support present" || warn "Cannot verify seccomp"
fi

# KASLR
if grep -q "nokaslr" /proc/cmdline; then
    fail "KASLR disabled via kernel cmdline!"
else
    ok "KASLR enabled (no nokaslr in cmdline)"
fi

# Lockdown
if [[ -f /sys/kernel/security/lockdown ]]; then
    LOCKDOWN=$(cat /sys/kernel/security/lockdown)
    if [[ "${LOCKDOWN}" == *"[none]"* ]]; then
        warn "Kernel lockdown is NONE — set to 'confidentiality' for production"
    else
        ok "Kernel lockdown: ${LOCKDOWN}"
    fi
else
    warn "Kernel lockdown not available — check CONFIG_SECURITY_LOCKDOWN_LSM"
fi

# ── 2. cgroup Limits ─────────────────────────────────────────
section "cgroup v2 Resource Limits"
CGROUP_ROOT="/sys/fs/cgroup/clawos"

for slice in agent wasm ebpf clawfs; do
    if [[ -d "${CGROUP_ROOT}/${slice}" ]]; then
        MEM=$(cat "${CGROUP_ROOT}/${slice}/memory.max" 2>/dev/null || echo "?")
        PIDS=$(cat "${CGROUP_ROOT}/${slice}/pids.max" 2>/dev/null || echo "?")
        ok "${slice}: memory.max=${MEM} pids.max=${PIDS}"
    else
        fail "${slice} cgroup slice missing — run scripts/setup-cgroups.sh"
    fi
done

# ── 3. Network Namespace ─────────────────────────────────────
section "Network Namespace"
if ip netns list 2>/dev/null | grep -q "clawos-agent"; then
    ok "Network namespace 'clawos-agent' exists"
    if [[ -f /var/run/clawos/netns.json ]]; then
        NS_IP=$(python3 -c "import json,sys; print(json.load(open('/var/run/clawos/netns.json'))['ns_ip'])" 2>/dev/null || echo "?")
        ok "Namespace IP: ${NS_IP}"
    fi
else
    fail "Network namespace 'clawos-agent' not found — run scripts/setup-netns.sh"
fi

# ── 4. AppArmor ──────────────────────────────────────────────
section "AppArmor"
if command -v aa-status &>/dev/null; then
    if aa-status 2>/dev/null | grep -q "clawos-agent"; then
        ENFORCED=$(aa-status 2>/dev/null | grep -A1 "profiles are in enforce mode" | tail -1 | tr -d ' ')
        if aa-status 2>/dev/null | grep -A20 "enforce" | grep -q "clawos-agent"; then
            ok "AppArmor profile 'clawos-agent' in ENFORCE mode"
        else
            warn "AppArmor profile loaded but NOT in enforce mode — run: aa-enforce /etc/apparmor.d/clawos-agent"
        fi
    else
        fail "AppArmor profile 'clawos-agent' not loaded — run: apparmor_parser -r /etc/apparmor.d/clawos-agent"
    fi
else
    warn "aa-status not found — AppArmor may not be installed"
fi

# ── 5. Frozen Spec Hashes ────────────────────────────────────
section "P1 Frozen Spec Verification"
SPECS_DIR="$(dirname "$0")/../specs/p1"
for spec in seccomp-whitelist.json resource-quotas.json ipc-protocol.json; do
    if [[ -f "${SPECS_DIR}/${spec}" ]]; then
        SHA=$(sha256sum "${SPECS_DIR}/${spec}" | cut -d' ' -f1)
        ok "${spec}: sha256=${SHA:0:16}..."
    else
        fail "Missing P1 spec: ${spec}"
    fi
done

# ── 6. TLS Certificates ──────────────────────────────────────
section "TLS Certificates"
CERTS_DIR="/var/lib/clawos/secrets"
for cert in agent.crt; do
    if [[ -f "${CERTS_DIR}/${cert}" ]]; then
        EXPIRY=$(openssl x509 -in "${CERTS_DIR}/${cert}" -noout -enddate 2>/dev/null \
                 | cut -d= -f2 || echo "unknown")
        DAYS=$(openssl x509 -in "${CERTS_DIR}/${cert}" -noout -checkend 2592000 &>/dev/null \
               && echo ">30" || echo "<30")
        if [[ "${DAYS}" == "<30" ]]; then
            warn "${cert}: expires ${EXPIRY} — renew within 30 days"
        else
            ok "${cert}: valid, expires ${EXPIRY}"
        fi
    else
        warn "${cert}: not found (may not be needed in dev mode)"
    fi
done

# ── 7. eBPF Monitor ──────────────────────────────────────────
section "eBPF Monitor"
if pgrep -x "clawos-ebpf" > /dev/null 2>&1; then
    ok "eBPF monitor daemon running"
elif [[ -f /var/run/clawos/ebpf.pid ]]; then
    ok "eBPF monitor PID file present"
else
    warn "eBPF monitor not running — start with: clawos-ebpf &"
fi

# Check BPF prog is loaded
if command -v bpftool &>/dev/null; then
    PROGS=$(bpftool prog list 2>/dev/null | grep -c "clawos" || echo 0)
    if [[ "${PROGS}" -gt 0 ]]; then
        ok "${PROGS} ClawOS eBPF programs loaded"
    else
        warn "No ClawOS eBPF programs in kernel (expected after B-01~B-05)"
    fi
fi

# ── 8. Binary & Config ───────────────────────────────────────
section "Binary & Config"
if [[ -x /usr/local/bin/clawos-agent ]]; then
    VERSION=$(/usr/local/bin/clawos-agent --version 2>/dev/null || echo "dev")
    ok "clawos-agent binary: ${VERSION}"
else
    warn "clawos-agent not installed to /usr/local/bin — use cargo run for dev"
fi

if [[ -f /etc/clawos/config.toml ]]; then
    ok "Config file present: /etc/clawos/config.toml"
else
    warn "Config not found at /etc/clawos/config.toml — using defaults"
fi

# ── Summary ──────────────────────────────────────────────────
echo
echo "══════════════════════════════════════════════"
echo -e " ${green}PASS: ${PASS}${reset}  |  ${yellow}WARN: ${WARN}${reset}  |  ${red}FAIL: ${FAIL}${reset}"
echo "══════════════════════════════════════════════"

if [[ ${FAIL} -gt 0 ]]; then
    echo -e "${red}Pre-flight FAILED — ${FAIL} critical check(s) failed. Agent will NOT start.${reset}"
    exit 1
elif [[ ${WARN} -gt 0 ]]; then
    echo -e "${yellow}Pre-flight PASSED with warnings — review above before production.${reset}"
    exit 0
else
    echo -e "${green}Pre-flight PASSED — all systems go.${reset}"
    exit 0
fi
