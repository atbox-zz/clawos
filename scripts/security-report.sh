#!/usr/bin/env bash
# scripts/security-report.sh
# G-04 / P4.8: Automated security report generation
# Checks all layers: seccomp, AppArmor, eBPF, cgroup, namespace, TLS, binary hardening
#
# Exit codes:
#   0 = PASS (zero CRITICAL, HIGH have mitigations)
#   1 = FAIL (CRITICAL findings present)

set -euo pipefail

# ── Usage ────────────────────────────────────────────────────
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    echo "Usage: bash scripts/security-report.sh [--help]"
    echo ""
    echo "  scripts/security-report.sh G-04 / P4.8: Automated security report generation Checks all layers: seccomp, AppArmor, eBPF, cgroup, namespace, TLS, binary hardening "
    echo ""
    echo "詳細說明: cat scripts/SCRIPTS.md | grep -A 30 '### `security-report.sh`'"
    exit 0
fi

REPORT_DIR="/var/lib/clawos/security"
REPORT_FILE="${REPORT_DIR}/security-report-$(date +%Y%m%d-%H%M%S).txt"
CRITICAL=0; HIGH=0; MED=0; LOW=0; PASS=0

mkdir -p "${REPORT_DIR}"

GREEN="\033[0;32m"; YELLOW="\033[0;33m"; RED="\033[0;31m"; BLUE="\033[0;34m"; NC="\033[0m"
PASS_TAG="${GREEN}[PASS]${NC}"; HIGH_TAG="${RED}[HIGH]${NC}"
CRIT_TAG="${RED}[CRITICAL]${NC}"; MED_TAG="${YELLOW}[MED]${NC}"; LOW_TAG="${YELLOW}[LOW]${NC}"

check() {
    local level="$1"; local message="$2"; local detail="${3:-}"
    case "${level}" in
        CRITICAL) echo -e "  ${CRIT_TAG} ${message}"; [[ -n "${detail}" ]] && echo "           ${detail}"; ((CRITICAL++)) ;;
        HIGH)     echo -e "  ${HIGH_TAG} ${message}"; [[ -n "${detail}" ]] && echo "           ${detail}"; ((HIGH++)) ;;
        MED)      echo -e "  ${MED_TAG}  ${message}"; ((MED++)) ;;
        LOW)      echo -e "  ${LOW_TAG}  ${message}"; ((LOW++)) ;;
        PASS)     echo -e "  ${PASS_TAG} ${message}"; ((PASS++)) ;;
    esac
}

section() { echo; echo -e "${BLUE}── $1 $(printf '%.0s─' $(seq $((50 - ${#1}))))${NC}"; }

header() {
    echo "╔══════════════════════════════════════════════════╗"
    echo "║   ClawOS Security Report                         ║"
    echo "║   Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)          ║"
    echo "╚══════════════════════════════════════════════════╝"
}

header

# ── 1. Kernel Hardening ───────────────────────────────────────
section "Kernel Hardening"

# KASLR
if grep -q "nokaslr" /proc/cmdline; then
    check CRITICAL "KASLR disabled" "Add 'kaslr' to kernel cmdline"
else
    check PASS "KASLR enabled"
fi

# Kernel lockdown
LOCKDOWN=$(cat /sys/kernel/security/lockdown 2>/dev/null || echo "none")
if echo "${LOCKDOWN}" | grep -q "\[confidentiality\]"; then
    check PASS "Kernel lockdown: confidentiality"
elif echo "${LOCKDOWN}" | grep -q "\[integrity\]"; then
    check MED "Kernel lockdown: integrity (not confidentiality)"
else
    check HIGH "Kernel lockdown: none" "Set CONFIG_SECURITY_LOCKDOWN_LSM + lockdown=confidentiality"
fi

# Module signing
if [[ $(cat /proc/sys/kernel/modules_disabled 2>/dev/null) == "1" ]]; then
    check PASS "Kernel module loading disabled"
elif grep -q "CONFIG_MODULE_SIG_FORCE=y" /boot/config-$(uname -r) 2>/dev/null; then
    check PASS "Module signing enforced (MODULE_SIG_FORCE)"
else
    check HIGH "Module signing not enforced" "Rebuild kernel with MODULE_SIG_FORCE=y"
fi

# Kernel pointers hidden
KPTR=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo 0)
if [[ "${KPTR}" -ge 1 ]]; then
    check PASS "Kernel pointers restricted (kptr_restrict=${KPTR})"
else
    check MED "Kernel pointers exposed (kptr_restrict=0)" "Set sysctl kernel.kptr_restrict=2"
fi

# dmesg restriction
DMESG=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null || echo 0)
if [[ "${DMESG}" -eq 1 ]]; then
    check PASS "dmesg restricted to root"
else
    check LOW "dmesg unrestricted" "Set kernel.dmesg_restrict=1"
fi

# ── 2. seccomp ────────────────────────────────────────────────
section "seccomp-BPF"

AGENT_PID=$(pgrep -x clawos-agent 2>/dev/null | head -1 || echo "")
if [[ -n "${AGENT_PID}" ]]; then
    SECCOMP=$(grep "^Seccomp:" /proc/"${AGENT_PID}"/status 2>/dev/null | awk '{print $2}' || echo 0)
    if [[ "${SECCOMP}" -eq 2 ]]; then
        check PASS "clawos-agent seccomp mode: 2 (filter active)"
    elif [[ "${SECCOMP}" -eq 1 ]]; then
        check MED "clawos-agent seccomp mode: 1 (strict, not filter)"
    else
        check HIGH "clawos-agent seccomp NOT active" "apply_filter() failed or agent not hardened"
    fi
else
    check MED "clawos-agent not running — seccomp not verifiable"
fi

# Check whitelist spec is frozen
if [[ -f specs/p1/seccomp-whitelist.json ]]; then
    FROZEN=$(python3 -c "import json; d=json.load(open('specs/p1/seccomp-whitelist.json')); print(d.get('frozen', False))" 2>/dev/null || echo false)
    if [[ "${FROZEN}" == "True" ]]; then
        check PASS "seccomp whitelist spec is frozen (P1.2)"
    else
        check MED "seccomp whitelist not marked as frozen"
    fi
else
    check HIGH "specs/p1/seccomp-whitelist.json not found"
fi

# ── 3. AppArmor ──────────────────────────────────────────────
section "AppArmor MAC"

if command -v aa-status &>/dev/null; then
    ENFORCE=$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}' || echo 0)
    COMPLAIN=$(aa-status 2>/dev/null | grep "profiles are in complain mode" | awk '{print $1}' || echo 0)

    if aa-status 2>/dev/null | grep -A50 "enforce" | grep -q "clawos-agent"; then
        check PASS "clawos-agent AppArmor profile in ENFORCE mode"
    elif aa-status 2>/dev/null | grep -A50 "complain" | grep -q "clawos-agent"; then
        check HIGH "clawos-agent AppArmor in COMPLAIN mode (not enforce)" "Run: aa-enforce /etc/apparmor.d/clawos-agent"
    else
        check CRITICAL "clawos-agent has NO AppArmor profile" "Load: apparmor_parser -r /etc/apparmor.d/clawos-agent"
    fi
else
    check HIGH "AppArmor not installed or aa-status unavailable"
fi

# ── 4. Namespace Isolation ───────────────────────────────────
section "Namespace Isolation"

if ip netns list 2>/dev/null | grep -q "clawos-agent"; then
    check PASS "Network namespace 'clawos-agent' active"
else
    check HIGH "Network namespace not configured" "Run: scripts/setup-netns.sh"
fi

if [[ -n "${AGENT_PID}" ]]; then
    USERNS=$(readlink /proc/"${AGENT_PID}"/ns/user 2>/dev/null || echo "?")
    PIDNS=$(readlink /proc/"${AGENT_PID}"/ns/pid 2>/dev/null || echo "?")
    HOST_USER=$(readlink /proc/1/ns/user 2>/dev/null || echo "host")

    if [[ "${USERNS}" != "${HOST_USER}" ]]; then
        check PASS "clawos-agent in isolated User Namespace"
    else
        check HIGH "clawos-agent in HOST User Namespace" "C-03: user namespace not applied"
    fi
fi

# ── 5. cgroup Limits ─────────────────────────────────────────
section "cgroup v2 Resource Limits"

CGROUP_AGENT="/sys/fs/cgroup/clawos/agent"
if [[ -d "${CGROUP_AGENT}" ]]; then
    SWAP_MAX=$(cat "${CGROUP_AGENT}/memory.swap.max" 2>/dev/null || echo "?")
    if [[ "${SWAP_MAX}" == "0" ]]; then
        check PASS "Swap disabled for agent cgroup"
    else
        check MED "Swap not disabled (memory.swap.max=${SWAP_MAX})" "Set memory.swap.max=0"
    fi

    PIDS_MAX=$(cat "${CGROUP_AGENT}/pids.max" 2>/dev/null || echo "max")
    if [[ "${PIDS_MAX}" != "max" ]] && [[ "${PIDS_MAX}" -le 256 ]]; then
        check PASS "PID limit set: pids.max=${PIDS_MAX}"
    else
        check MED "PID limit too high or unset: ${PIDS_MAX}" "Set pids.max ≤ 256"
    fi
else
    check HIGH "clawos/agent cgroup not found" "Run: scripts/setup-cgroups.sh"
fi

# ── 6. TLS / Certificates ────────────────────────────────────
section "TLS & Secrets"

CERT_DIR="/var/lib/clawos/secrets"
if [[ -f "${CERT_DIR}/agent.crt" ]]; then
    DAYS=$(openssl x509 -in "${CERT_DIR}/agent.crt" -noout -checkend 604800 &>/dev/null && echo "ok" || echo "expiring")
    if [[ "${DAYS}" == "ok" ]]; then
        check PASS "TLS certificate valid (>7 days)"
    else
        check HIGH "TLS certificate expiring within 7 days" "Renew certificate immediately"
    fi

    KEY_BITS=$(openssl x509 -in "${CERT_DIR}/agent.crt" -noout -text 2>/dev/null | grep "Public-Key" | grep -oP '\d+' || echo 0)
    if [[ "${KEY_BITS}" -ge 2048 ]]; then
        check PASS "Certificate key size: ${KEY_BITS} bits"
    else
        check HIGH "Certificate key too weak: ${KEY_BITS} bits" "Use RSA-4096 or ECDSA P-256+"
    fi
else
    check LOW "No TLS certificate found (OK in dev)"
fi

# Check kernel keyring
if keyctl describe @s &>/dev/null; then
    check PASS "Kernel keyring accessible"
else
    check MED "Kernel keyring not accessible"
fi

# ── 7. Binary Hardening ──────────────────────────────────────
section "Binary Hardening"

AGENT_BIN=$(which clawos-agent 2>/dev/null || echo "")
if [[ -n "${AGENT_BIN}" ]]; then
    # PIE check
    if readelf -h "${AGENT_BIN}" 2>/dev/null | grep -q "DYN (Position-Independent Executable)"; then
        check PASS "Binary is PIE"
    else
        check MED "Binary is not PIE" "Build with -C link-arg=-pie"
    fi

    # RELRO check
    if readelf -l "${AGENT_BIN}" 2>/dev/null | grep -q "GNU_RELRO"; then
        check PASS "RELRO enabled"
    else
        check MED "RELRO not enabled" "Build with -z relro -z now"
    fi

    # Stack canary
    if readelf -s "${AGENT_BIN}" 2>/dev/null | grep -q "__stack_chk_fail"; then
        check PASS "Stack canary present"
    else
        check LOW "Stack canary not detected (may be statically stripped)"
    fi

    # Static check
    if ldd "${AGENT_BIN}" 2>&1 | grep -q "not a dynamic executable"; then
        check PASS "Binary is statically linked (musl)"
    else
        check LOW "Binary dynamically linked (OK in dev, use musl for production)"
    fi
else
    check LOW "clawos-agent not in PATH — run 'cargo install' or build first"
fi

# ── 8. eBPF Monitor ──────────────────────────────────────────
section "eBPF Security Monitor"

if pgrep -x "clawos-ebpf" &>/dev/null; then
    check PASS "eBPF monitor daemon running"
else
    check HIGH "eBPF monitor NOT running" "Start: clawos-ebpf &"
fi

if command -v bpftool &>/dev/null; then
    BPF_PROGS=$(bpftool prog list 2>/dev/null | grep -c "clawos" || echo 0)
    if [[ "${BPF_PROGS}" -ge 4 ]]; then
        check PASS "${BPF_PROGS} ClawOS eBPF programs loaded"
    elif [[ "${BPF_PROGS}" -gt 0 ]]; then
        check MED "Only ${BPF_PROGS}/4+ eBPF programs loaded"
    else
        check HIGH "No ClawOS eBPF programs in kernel"
    fi
fi

# ── Summary ───────────────────────────────────────────────────

echo
echo "══════════════════════════════════════════════════"
echo -e "  CRITICAL: ${RED}${CRITICAL}${NC}  HIGH: ${RED}${HIGH}${NC}  MED: ${YELLOW}${MED}${NC}  LOW: ${YELLOW}${LOW}${NC}  PASS: ${GREEN}${PASS}${NC}"
echo "══════════════════════════════════════════════════"

# Write machine-readable report
python3 - <<EOF
import json, time
report = {
    "timestamp":  time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    "phase":      "P4",
    "hostname":   "$(hostname)",
    "findings":   {"critical": ${CRITICAL}, "high": ${HIGH}, "med": ${MED}, "low": ${LOW}, "pass": ${PASS}},
    "gate_status": "PASS" if ${CRITICAL} == 0 else "FAIL",
    "note":       "HIGH findings require mitigation plan before Release Gate"
}
with open("${REPORT_FILE}", 'w') as f:
    json.dump(report, f, indent=2)
print(f"  Report: ${REPORT_FILE}")
EOF

if [[ "${CRITICAL}" -gt 0 ]]; then
    echo -e "  ${RED}GATE P4→RELEASE: BLOCKED — ${CRITICAL} CRITICAL finding(s)${NC}"
    exit 1
else
    echo -e "  ${GREEN}GATE P4→RELEASE: PASS (${HIGH} HIGH findings — attach mitigation plan)${NC}"
    exit 0
fi
