#!/usr/bin/env bash
# scripts/setup-netns.sh
# C-07: Network namespace + veth + iptables setup
# Creates an isolated veth pair for ClawOS agent ↔ ClawFS comms
# Run as root before launching clawos-agent.
set -euo pipefail

# ── Usage ────────────────────────────────────────────────────
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    echo "Usage: bash scripts/setup-netns.sh [--help]"
    echo ""
    echo "  scripts/setup-netns.sh C-07: Network namespace + veth + iptables setup "
    echo ""
    echo "詳細說明: cat scripts/SCRIPTS.md | grep -A 30 '### `setup-netns.sh`'"
    exit 0
fi

NS="clawos-agent"
VETH_HOST="veth-clawos0"
VETH_NS="veth-clawos1"
HOST_IP="10.100.0.1"
NS_IP="10.100.0.2"
CLAWFS_PORT="5432"  # PostgreSQL (phase 1-2) / SQLite IPC (phase 3)
PREFIX="24"

log() { echo "[$(date -u +%H:%M:%S)] $*"; }
die() { echo "[ERROR] $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Must run as root"

# ── 1. Create network namespace ──────────────────────────────
if ip netns list | grep -q "^${NS} "; then
    log "Network namespace '${NS}' already exists — recreating"
    ip netns del "${NS}" 2>/dev/null || true
fi

ip netns add "${NS}"
log "Created network namespace: ${NS}"

# ── 2. Create veth pair ──────────────────────────────────────
ip link del "${VETH_HOST}" 2>/dev/null || true
ip link add "${VETH_HOST}" type veth peer name "${VETH_NS}"
log "Created veth pair: ${VETH_HOST} <-> ${VETH_NS}"

# ── 3. Move one end into namespace ───────────────────────────
ip link set "${VETH_NS}" netns "${NS}"

# ── 4. Configure host side ───────────────────────────────────
ip addr add "${HOST_IP}/${PREFIX}" dev "${VETH_HOST}"
ip link set "${VETH_HOST}" up
log "Host veth configured: ${VETH_HOST} @ ${HOST_IP}/${PREFIX}"

# ── 5. Configure namespace side ──────────────────────────────
ip netns exec "${NS}" ip addr add "${NS_IP}/${PREFIX}" dev "${VETH_NS}"
ip netns exec "${NS}" ip link set "${VETH_NS}" up
ip netns exec "${NS}" ip link set lo up
log "Namespace veth configured: ${VETH_NS} @ ${NS_IP}/${PREFIX}"

# ── 6. iptables: restrict what namespace can reach ────────────
# Only allow namespace → host:CLAWFS_PORT (ClawFS/PostgreSQL)
# Everything else is dropped.

# Flush existing rules for this namespace's traffic
iptables -D FORWARD -i "${VETH_HOST}" -j CLAWOS_FILTER 2>/dev/null || true
iptables -F CLAWOS_FILTER 2>/dev/null || true
iptables -X CLAWOS_FILTER 2>/dev/null || true

iptables -N CLAWOS_FILTER

# Allow established/related
iptables -A CLAWOS_FILTER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow only ClawFS port from namespace IP
iptables -A CLAWOS_FILTER \
    -s "${NS_IP}" \
    -d "${HOST_IP}" \
    -p tcp \
    --dport "${CLAWFS_PORT}" \
    -m conntrack --ctstate NEW \
    -j ACCEPT

# Allow IPC socket traffic (via loopback in namespace, not here)

# Drop everything else from the namespace
iptables -A CLAWOS_FILTER \
    -s "${NS_IP}" \
    -j DROP

# Attach filter to FORWARD chain
iptables -I FORWARD -i "${VETH_HOST}" -j CLAWOS_FILTER

log "iptables rules applied — namespace restricted to TCP:${CLAWFS_PORT} only"

# ── 7. XDP program placeholder ───────────────────────────────
# B-04: XDP filter loaded separately via clawos-ebpf daemon
# This script just ensures the interface is up for XDP attachment
log "XDP attachment point ready on ${VETH_HOST}"

# ── 8. Write namespace info for agent startup ─────────────────
mkdir -p /var/run/clawos
cat > /var/run/clawos/netns.json <<EOF
{
  "namespace": "${NS}",
  "host_veth": "${VETH_HOST}",
  "ns_veth":   "${VETH_NS}",
  "host_ip":   "${HOST_IP}",
  "ns_ip":     "${NS_IP}",
  "clawfs_port": ${CLAWFS_PORT},
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

log "Network namespace setup complete."
log "  Host → Namespace: ${HOST_IP} → ${NS_IP}"
log "  Allowed traffic:  TCP ${NS_IP}:* → ${HOST_IP}:${CLAWFS_PORT} only"
log ""
log "Launch agent inside namespace:"
log "  ip netns exec ${NS} /usr/local/bin/clawos-agent"
