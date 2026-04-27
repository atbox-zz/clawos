#!/usr/bin/env bash
# scripts/tag-release.sh — E-01: Tag v0.1.0 after P4→RELEASE gate passes
set -euo pipefail

VERSION="${1:-0.1.0}"
GREEN="\033[0;32m"; RED="\033[0;31m"; YELLOW="\033[0;33m"; NC="\033[0m"
pass() { echo -e "${GREEN}✓${NC} $*"; }
fail() { echo -e "${RED}✗${NC} $*"; exit 1; }
warn() { echo -e "${YELLOW}⚠${NC} $*"; }

echo "╔══════════════════════════════════════════════╗"
echo "║   ClawOS Release Tag — v${VERSION}                 ║"
echo "╚══════════════════════════════════════════════╝"

# ── Pre-flight: verify all P4 gate blockers are resolved ──────
echo
echo "── Gate Check ────────────────────────────────"

SPEC="specs/p4/phase-spec.json"
[[ -f "$SPEC" ]] || fail "phase-spec.json not found"

python3 - << PYEOF
import json, sys
spec = json.load(open("${SPEC}"))
tasks = spec["tasks"]

gate_blockers = ["A-01","A-02","B-01","B-02","C-01","D-01","D-02","D-03"]
failed = []
for t in gate_blockers:
    status = tasks.get(t, {}).get("status", "missing")
    if status != "completed":
        failed.append(f"{t}: {status}")

if failed:
    print("GATE FAIL — blockers not completed:")
    for f in failed:
        print(f"  ✗ {f}")
    sys.exit(1)
else:
    print("GATE PASS — all blockers completed")
PYEOF

# ── Git tag ───────────────────────────────────────────────────
echo
echo "── Git Tag ───────────────────────────────────"

git rev-parse --git-dir > /dev/null 2>&1 || {
    warn "Not a git repo — initialising"
    git init
    git add -A
    git commit -m "ClawOS v${VERSION} — initial commit"
}

if git tag -l "v${VERSION}" | grep -q "v${VERSION}"; then
    warn "Tag v${VERSION} already exists"
    git tag -l "v${VERSION}" -n1
else
    # Try signed tag first, fall back to unsigned
    git tag -s "v${VERSION}" -m "ClawOS v${VERSION} — AI-Native OS" 2>/dev/null \
        || git tag    "v${VERSION}" -m "ClawOS v${VERSION} — AI-Native OS"
    pass "Tagged v${VERSION}"
fi

git tag -l "v${VERSION}" -n1

# ── Freeze vault entry ────────────────────────────────────────
echo
echo "── Vault Freeze ──────────────────────────────"
python3 - << PYEOF
import json, time, hashlib, os

ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
entry = {
    "tag": "v${VERSION}",
    "timestamp": ts,
    "gate_status": "PASS",
    "frozen": True
}
os.makedirs("/var/lib/clawos/vault", exist_ok=True)
path = "/var/lib/clawos/vault/release-tag-v${VERSION}.json"
json.dump(entry, open(path, "w"), indent=2)
sha = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
print(f"  Vault entry: {path}")
print(f"  SHA256:      {sha}")
PYEOF

pass "Release v${VERSION} tagged and frozen in vault"
