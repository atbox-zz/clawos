#!/usr/bin/env bash
# scripts/sign-release.sh — D-03: Sign release artifacts
# Runs after D-01 ISO build. SHA256 always; GPG if key available.
set -euo pipefail

VERSION="${1:-0.1.0}"
ISO="image/clawos-v${VERSION}.iso"
GREEN="\033[0;32m"; YELLOW="\033[0;33m"; RED="\033[0;31m"; NC="\033[0m"
pass() { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}⚠${NC} $*"; }
fail() { echo -e "${RED}✗${NC} $*"; exit 1; }

echo "╔══════════════════════════════════════════════╗"
echo "║   ClawOS Release Signing — v${VERSION}             ║"
echo "╚══════════════════════════════════════════════╝"

[[ -f "$ISO" ]] || fail "ISO not found: $ISO (run 'make iso' first)"

# ── SHA256 ────────────────────────────────────────────────────
echo
echo "── SHA256 Checksum ───────────────────────────"
sha256sum "$ISO" > "${ISO}.sha256"
sha256sum --check "${ISO}.sha256" --quiet && pass "SHA256 verified: $(cat ${ISO}.sha256 | awk '{print $1}')"

# ── GPG ───────────────────────────────────────────────────────
echo
echo "── GPG Signature ─────────────────────────────"
GPG_KEY=$(gpg --list-secret-keys --keyid-format LONG 2>/dev/null \
    | grep -E "^sec" | head -1 | awk '{print $2}' | cut -d/ -f2 || true)

if [[ -n "${GPG_KEY:-}" ]]; then
    gpg --armor --detach-sign --default-key "$GPG_KEY" "$ISO"
    gpg --verify "${ISO}.asc" "$ISO" && pass "GPG signature verified (key: $GPG_KEY)"
else
    warn "No GPG secret key found — skipping GPG signature"
    warn "To add GPG signing: gpg --gen-key && re-run this script"
fi

# ── Manifest ──────────────────────────────────────────────────
echo
echo "── Release Manifest ──────────────────────────"
import_ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
SHA=$(awk '{print $1}' "${ISO}.sha256")
SIZE=$(stat -c%s "$ISO" 2>/dev/null || stat -f%z "$ISO" 2>/dev/null)
SIZE_MB=$(( SIZE / 1048576 ))

MANIFEST_PATH="image/clawos-v${VERSION}-manifest.json"
python3 - << PYEOF
import json
manifest = {
    "version": "${VERSION}",
    "timestamp": "${import_ts}",
    "artifacts": {
        "iso": {
            "path": "${ISO}",
            "sha256": "${SHA}",
            "size_bytes": ${SIZE},
            "size_mb": ${SIZE_MB}
        }
    },
    "gpg_key": "${GPG_KEY:-none}",
    "gate_status": "PASS"
}
json.dump(manifest, open("${MANIFEST_PATH}", "w"), indent=2)
print(f"  Manifest: ${MANIFEST_PATH}")
print(f"  ISO size: ${SIZE_MB}MB")
print(f"  SHA256:   ${SHA}")
PYEOF

pass "Signing complete — ready for E-01 git tag"
echo
echo "  Artifacts:"
ls -lh "${ISO}" "${ISO}.sha256" $(ls "${ISO}.asc" 2>/dev/null || true) "$MANIFEST_PATH" 2>/dev/null \
    | awk '{print "  " $0}'
