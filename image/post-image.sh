#!/usr/bin/env bash
# image/post-image.sh
# G-06: Assemble ClawOS ISO after buildroot post-build
# Called by buildroot at the end of image generation.
# Output: clawos-v0.1.0.iso (< 128MB Gate P4 requirement)

set -euo pipefail
IMAGES="${BINARIES_DIR}"
OUTPUT_ISO="${IMAGES}/clawos-v0.1.0.iso"
VERSION="0.1.0"

log()  { echo "[post-image] $*"; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

log "Assembling ClawOS ${VERSION} ISO..."

# ── 1. Binary installation ─────────────────────────────────────
log "Installing ClawOS binaries into rootfs overlay..."

TARGET_ROOT="${BASE_DIR}/target"
BIN_DEST="${TARGET_ROOT}/usr/local/bin"

# Copy release binaries (pre-built by CI)
RELEASE_DIR="${BASE_DIR}/../../target/x86_64-unknown-linux-musl/release"
for bin in clawos-agent clawos-ebpf-userspace; do
    if [[ -f "${RELEASE_DIR}/${bin}" ]]; then
        install -m 755 "${RELEASE_DIR}/${bin}" "${BIN_DEST}/${bin}"
        log "  ✓ ${bin} ($(du -sh "${BIN_DEST}/${bin}" | cut -f1))"
    else
        log "  ⚠ ${bin} not found — building from source..."
        (cd "${BASE_DIR}/../.." && \
         cargo build --bin "${bin}" --target x86_64-unknown-linux-musl --release)
        install -m 755 "${RELEASE_DIR}/${bin}" "${BIN_DEST}/${bin}"
    fi
done

# Install scripts
for script in preflight setup-cgroups setup-netns calibrate security-report; do
    SRC="${BASE_DIR}/../../scripts/${script}.sh"
    if [[ -f "${SRC}" ]]; then
        install -m 755 "${SRC}" "${BIN_DEST}/clawos-${script}"
    fi
done

# ── 2. Config installation ─────────────────────────────────────
log "Installing configs..."

CONFIG_DEST="${TARGET_ROOT}/etc/clawos"
mkdir -p "${CONFIG_DEST}"
cp "${BASE_DIR}/../../specs/p1/"*.json "${CONFIG_DEST}/"

APPARMOR_DEST="${TARGET_ROOT}/etc/apparmor.d"
mkdir -p "${APPARMOR_DEST}"
cp "${BASE_DIR}/../../apparmor/clawos-agent" "${APPARMOR_DEST}/"

SYSTEMD_DEST="${TARGET_ROOT}/etc/systemd/system"
mkdir -p "${SYSTEMD_DEST}"
cp "${BASE_DIR}/../../scripts/clawos-agent.service" "${SYSTEMD_DEST}/"

# ── 3. WASM tools installation ─────────────────────────────────
log "Installing WASM tools..."
TOOLS_DEST="${TARGET_ROOT}/var/lib/clawos/tools"
mkdir -p "${TOOLS_DEST}"

for tool_dir in "${BASE_DIR}/../../tools"/*/; do
    tool_name=$(basename "${tool_dir}")
    if [[ -f "${tool_dir}/manifest.json" ]]; then
        mkdir -p "${TOOLS_DEST}/${tool_name}"
        cp "${tool_dir}/manifest.json" "${TOOLS_DEST}/${tool_name}/"
        if [[ -f "${tool_dir}/tool.wasm" ]]; then
            cp "${tool_dir}/tool.wasm" "${TOOLS_DEST}/${tool_name}/"
            log "  ✓ tool: ${tool_name} (wasm present)"
        else
            log "  ⚠ tool: ${tool_name} (no wasm yet — stub mode)"
        fi
    fi
done

# ── 4. Kernel config embedding ─────────────────────────────────
log "Embedding kernel config..."
cp "${BASE_DIR}/../../kernel/clawos-kernel.config" \
   "${TARGET_ROOT}/boot/clawos-kernel.config"

# ── 5. Size check (Gate P4: < 128MB) ──────────────────────────
log "Checking image sizes..."
ROOTFS_SIZE=$(du -sm "${IMAGES}/rootfs.ext4" 2>/dev/null | cut -f1 || echo 999)
log "  rootfs.ext4: ${ROOTFS_SIZE}MB"

if [[ "${ROOTFS_SIZE}" -gt 96 ]]; then
    die "rootfs.ext4 exceeds 96MB (${ROOTFS_SIZE}MB) — Gate P4 BLOCKED"
fi

# ── 6. Build ISO ───────────────────────────────────────────────
log "Building ISO with grub2..."
grub-mkrescue \
    -o "${OUTPUT_ISO}" \
    "${IMAGES}" \
    -- \
    --modules="normal boot linux ext2 squash4 loopback iso9660 part_gpt part_msdos fat zstd" \
    2>/dev/null

ISO_SIZE=$(du -sm "${OUTPUT_ISO}" | cut -f1)
log "ISO size: ${ISO_SIZE}MB"

if [[ "${ISO_SIZE}" -gt 128 ]]; then
    die "ISO exceeds 128MB (${ISO_SIZE}MB) — Gate P4 BLOCKED. Strip debug symbols and non-essential packages."
fi

# ── 7. SHA256 and sign ─────────────────────────────────────────
SHA=$(sha256sum "${OUTPUT_ISO}" | cut -d' ' -f1)
echo "${SHA}  clawos-v${VERSION}.iso" > "${IMAGES}/clawos-v${VERSION}.iso.sha256"
log "SHA256: ${SHA}"

# ── 8. Create release manifest ────────────────────────────────
cat > "${IMAGES}/release-manifest.json" <<EOF
{
  "version":     "${VERSION}",
  "build_date":  "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "kernel":      "6.6 LTS",
  "arch":        "x86_64",
  "iso_size_mb": ${ISO_SIZE},
  "sha256":      "${SHA}",
  "phase":       "P4→Release",
  "gate_status": "size_ok"
}
EOF

log "✅ ClawOS ${VERSION} ISO assembled: ${OUTPUT_ISO}"
log "   Size: ${ISO_SIZE}MB ✓ (< 128MB gate)"
