#!/usr/bin/env bash
# scripts/install.sh
#
# ClawOS P4 — 安裝腳本（含 security-patch audit #4 所需設定）
#
# 此腳本完成以下工作：
#   1. 前置條件檢查（系統、依賴、Rust toolchain）
#   2. 建立 clawos 系統帳號
#   3. Kernel keyring 初始化（ClawFS 加密金鑰 + Gateway bearer token）
#   4. 目錄與權限配置
#   5. 編譯所有元件（agent、eBPF、WASM tools）
#   6. 安裝 system service（systemd）
#   7. 系統資源設定（cgroups、netns、AppArmor）
#   8. preflight 驗證
#
# 執行方式：
#   sudo bash scripts/install.sh
#
# 環境變數（可覆寫預設值）：
#   CLAWOS_USER          服務帳號名稱（預設 clawos）
#   CLAWOS_HOME          資料目錄（預設 /var/lib/clawos）
#   INSTALL_PREFIX       binary 安裝位置（預設 /usr/local/bin）
#   SKIP_BUILD           設為 1 跳過 cargo build（已有 binary 時使用）
#   SKIP_KEYRING         設為 1 跳過 keyring 初始化（CI/容器環境）
#   BUILD_TARGET         Rust target（預設 x86_64-unknown-linux-musl）

set -euo pipefail

# ── 顯示說明（--help）────────────────────────────────────────
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    echo "Usage: sudo bash scripts/install.sh [OPTIONS]"
    echo ""
    echo "  ClawOS P4 一鍵安裝腳本（含 security-patch audit #4 所需設定）"
    echo ""
    echo "環境變數（可覆寫預設值）："
    echo "  CLAWOS_USER=clawos          服務帳號名稱"
    echo "  CLAWOS_HOME=/var/lib/clawos 資料目錄"
    echo "  INSTALL_PREFIX=/usr/local/bin  Binary 安裝位置"
    echo "  BUILD_TARGET=x86_64-unknown-linux-musl  Rust 編譯目標"
    echo "  SKIP_BUILD=0    設為 1 跳過 cargo build（已有 binary 時使用）"
    echo "  SKIP_KEYRING=0  設為 1 跳過 keyring 初始化（CI/容器環境）"
    echo ""
    echo "範例："
    echo "  sudo bash scripts/install.sh"
    echo "  sudo SKIP_BUILD=1 bash scripts/install.sh"
    echo "  sudo SKIP_BUILD=1 SKIP_KEYRING=1 bash scripts/install.sh"
    echo ""
    echo "詳細說明: cat scripts/SCRIPTS.md"
    exit 0
fi

# ── 顏色 ──────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log()  { echo -e "${GREEN}[$(date -u +%H:%M:%S)] $*${RESET}"; }
warn() { echo -e "${YELLOW}[WARN] $*${RESET}" >&2; }
die()  { echo -e "${RED}[ERROR] $*${RESET}" >&2; exit 1; }

# ── 設定 ──────────────────────────────────────────────────────
CLAWOS_USER="${CLAWOS_USER:-clawos}"
CLAWOS_HOME="${CLAWOS_HOME:-/var/lib/clawos}"
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local/bin}"
BUILD_TARGET="${BUILD_TARGET:-x86_64-unknown-linux-musl}"
SKIP_BUILD="${SKIP_BUILD:-0}"
SKIP_KEYRING="${SKIP_KEYRING:-0}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── 整體進度追蹤 ──────────────────────────────────────────────
TOTAL_STEPS=10
CURRENT_STEP=0
progress() {
    (( CURRENT_STEP++ )) || true
}

# ── 0. Root 檢查 ──────────────────────────────────────────────
progress "環境檢查"
[[ $EUID -eq 0 ]] || die "install.sh 必須以 root 執行（sudo bash scripts/install.sh）"

log "安裝根目錄: $REPO_ROOT"
log "服務帳號:   $CLAWOS_USER"
log "資料目錄:   $CLAWOS_HOME"

# ── 1. 前置條件 ───────────────────────────────────────────────
progress "前置條件檢查"

check_cmd() {
    command -v "$1" &>/dev/null || die "缺少必要指令: $1  (請先安裝 $2)"
}

check_cmd cargo    "Rust toolchain — https://rustup.rs"
check_cmd git      "git"
check_cmd openssl  "openssl"
check_cmd keyctl   "keyutils (apt install keyutils / yum install keyutils)"
check_cmd aa-status "apparmor-utils (apt install apparmor-utils)"
check_cmd ip       "iproute2"
check_cmd systemctl "systemd"

# Rust target — 顯示即時下載進度
if rustup target list --installed 2>/dev/null | grep -q "$BUILD_TARGET"; then
    log "Rust target $BUILD_TARGET 已安裝 ✓"
else
    log "正在下載 Rust target: $BUILD_TARGET"
    log "  （檔案較大，視網路速度需要 30 秒～數分鐘，請稍候…）"
    # 不重定向 stdout/stderr，讓 rustup 的下載進度直接顯示在終端
    rustup target add "$BUILD_TARGET" || die "rustup target add 失敗"
    log "Rust target $BUILD_TARGET 安裝完成 ✓"
fi

# musl linker
if [[ "$BUILD_TARGET" == *musl* ]]; then
    if command -v x86_64-linux-musl-gcc &>/dev/null; then
        log "musl-tools 已安裝 ✓"
    else
        log "安裝 musl-tools..."
        if command -v apt-get &>/dev/null; then
            apt-get install -y musl-tools 2>&1 | grep -E "^(Get|Setting|Unpacking|Selecting)" || true
        elif command -v yum &>/dev/null; then
            yum install -y musl-tools || true
        else
            die "找不到套件管理器，請手動安裝 musl-tools 後重試"
        fi
        command -v x86_64-linux-musl-gcc &>/dev/null || \
            die "musl-tools 安裝後仍找不到 x86_64-linux-musl-gcc"
        log "musl-tools 安裝完成 ✓"
    fi
fi

# kernel keyring 支援
if grep -q "CONFIG_KEYS=y" /boot/config-"$(uname -r)" 2>/dev/null; then
    log "Kernel keyring (CONFIG_KEYS) ✓"
else
    warn "無法確認 CONFIG_KEYS=y，若 keyctl 呼叫失敗請檢查 kernel 設定"
fi

log "前置條件全部通過 ✓"

# ── 2. 系統帳號 ───────────────────────────────────────────────
progress "建立系統帳號 ($CLAWOS_USER)"

if ! id "$CLAWOS_USER" &>/dev/null; then
    useradd --system \
            --home-dir "$CLAWOS_HOME" \
            --no-create-home \
            --shell /sbin/nologin \
            --comment "ClawOS AI Agent" \
            "$CLAWOS_USER"
    log "已建立帳號: $CLAWOS_USER"
else
    log "帳號已存在: $CLAWOS_USER（略過）"
fi

# ── 3. 目錄結構 ───────────────────────────────────────────────
progress "建立目錄結構"

DIRS=(
    "$CLAWOS_HOME"
    "$CLAWOS_HOME/vault"
    "$CLAWOS_HOME/tasks"
    "$CLAWOS_HOME/tools"
    "$CLAWOS_HOME/security"
    "$CLAWOS_HOME/calibration"
    "$CLAWOS_HOME/scripts"
    "$CLAWOS_HOME/workspace"
    "/var/run/clawos"
    "/var/log/clawos"
)

for d in "${DIRS[@]}"; do
    mkdir -p "$d"
    chown "$CLAWOS_USER:$CLAWOS_USER" "$d"
    chmod 750 "$d"
    log "  $d"
done

# IPC socket 目錄（只有 clawos user 可存取）
mkdir -p /run/clawos
chown "$CLAWOS_USER:$CLAWOS_USER" /run/clawos
chmod 700 /run/clawos

# Rollback scripts 目錄 — 安裝真實實作（非 placeholder）
mkdir -p "$CLAWOS_HOME/scripts"
for script in rollback-migration rollback-tool-update rollback-channel; do
    src="$SCRIPT_DIR/${script}.sh"
    dst="$CLAWOS_HOME/scripts/${script}.sh"
    if [[ -f "$src" ]]; then
        install -m 755 "$src" "$dst"
        chown "$CLAWOS_USER:$CLAWOS_USER" "$dst"
        log "  ✓ $script.sh 已安裝"
    else
        log "  WARNING: $src 不存在，建立 placeholder（功能受限）"
        cat > "$dst" << ROLLBACK_EOF
#!/usr/bin/env bash
# ${script}.sh — PLACEHOLDER (real script missing from distribution)
echo "[$(date -u +%H:%M:%S)] WARNING: ${script} placeholder called — no action" >> /var/log/clawos/rollback.log
exit 1
ROLLBACK_EOF
        chmod 755 "$dst"
        chown "$CLAWOS_USER:$CLAWOS_USER" "$dst"
    fi
done
log "Rollback scripts 安裝完成"

# ── 4. Kernel Keyring 初始化（FIX H-02 / FIX C-03）────────────
progress "Kernel Keyring 初始化"

if [[ "$SKIP_KEYRING" == "1" ]]; then
    warn "SKIP_KEYRING=1，跳過 keyring 設定（僅限 CI/測試環境）"
    warn "正式部署前必須手動設定 clawfs-key 和 clawos-gateway-token"
else
    # 切換到 clawos user 的 session keyring
    # 這樣 key 只屬於該 user，其他 user 讀不到

    # ── ClawFS 加密金鑰（FIX H-02）─────────────────────────────
    if keyctl search @u user clawfs-key &>/dev/null; then
        log "clawfs-key 已存在於 keyring（略過重新產生）"
        log "  若要輪換金鑰請執行: sudo -u $CLAWOS_USER keyctl update \$(keyctl search @u user clawfs-key) \$(openssl rand -hex 32)"
    else
        CLAWFS_KEY=$(openssl rand -hex 32)
        # 將 key 加入 clawos user 的 user keyring
        su - "$CLAWOS_USER" -s /bin/bash -c \
            "keyctl add user clawfs-key '$CLAWFS_KEY' @u" &>/dev/null
        # 設定 key 只有擁有者可讀（不可被其他程序搜尋）
        KEY_ID=$(su - "$CLAWOS_USER" -s /bin/bash -c \
            "keyctl search @u user clawfs-key")
        su - "$CLAWOS_USER" -s /bin/bash -c \
            "keyctl setperm $KEY_ID 0x3f000000"
        log "clawfs-key 已產生並存入 keyring（32 bytes AES-256）"
        # 清除 shell 歷史中的金鑰
        unset CLAWFS_KEY
    fi

    # ── Web Gateway Bearer Token（FIX C-03）─────────────────────
    if keyctl search @u user clawos-gateway-token &>/dev/null; then
        log "clawos-gateway-token 已存在於 keyring（略過重新產生）"
    else
        GATEWAY_TOKEN=$(openssl rand -base64 48 | tr -d '\n/')
        su - "$CLAWOS_USER" -s /bin/bash -c \
            "printf '%s' '$GATEWAY_TOKEN' | keyctl padd user clawos-gateway-token @u"
        TOKEN_ID=$(su - "$CLAWOS_USER" -s /bin/bash -c \
            "keyctl search @u user clawos-gateway-token")
        su - "$CLAWOS_USER" -s /bin/bash -c \
            "keyctl setperm $TOKEN_ID 0x3f000000"
        log "clawos-gateway-token 已產生並存入 keyring"
        log ""
        log "  ${YELLOW}請將以下 token 儲存到安全的地方（只顯示一次）：${RESET}"
        log "  ${BOLD}GATEWAY_TOKEN = $GATEWAY_TOKEN${RESET}"
        log ""
        unset GATEWAY_TOKEN
    fi
fi

# ── 5. 編譯 ───────────────────────────────────────────────────
progress "編譯 ClawOS"

cd "$REPO_ROOT"

if [[ "$SKIP_BUILD" == "1" ]]; then
    warn "SKIP_BUILD=1，跳過編譯"
else
    # ── 進度顯示函數 ────────────────────────────────────────────
    # cargo build 直接輸出到終端（不重定向），讓編譯訊息即時顯示
    build_with_progress() {
        local label="$1"; shift
        log "▶ 開始編譯: $label"
        log "  （首次編譯需要下載 crates，視網路速度可能需要數分鐘）"
        echo "  ─────────────────────────────────────────────────────"
        # 直接執行，讓 cargo 的 Compiling / Downloading 訊息顯示在終端
        "$@"
        local exit_code=$?
        echo "  ─────────────────────────────────────────────────────"
        if [[ $exit_code -eq 0 ]]; then
            log "✓ 編譯完成: $label"
        else
            die "✗ 編譯失敗: $label（exit code $exit_code）"
        fi
        return $exit_code
    }

    # ── Agent + eBPF userspace ──────────────────────────────────
    build_with_progress "clawos-agent + clawos-ebpf-userspace" \
        cargo build \
            -p clawos-agent \
            -p clawos-ebpf-userspace \
            --target "$BUILD_TARGET" \
            --release

    # ── eBPF kernel programs ────────────────────────────────────
    log "▶ 編譯 eBPF kernel programs（需要 bpf-linker）..."
    if cargo build \
            -p clawos-ebpf \
            --target bpfel-unknown-none \
            --release 2>&1; then
        log "✓ eBPF kernel programs 編譯完成"
    else
        warn "✗ eBPF build 失敗（可能缺少 bpf-linker）"
        warn "  安裝: cargo install bpf-linker"
        warn "  繼續安裝其他元件..."
    fi

    # ── WASM tools ──────────────────────────────────────────────
    log "▶ 編譯 WASM tools..."
    WASM_OK=0
    WASM_FAIL=0
    for tool in web-search file-read summarise; do
        log "  編譯 $tool..."
        if (cd "tools/$tool" && \
            cargo build --target wasm32-wasi --release 2>&1); then
            WASM_SRC="target/wasm32-wasi/release/${tool//-/_}.wasm"
            if [[ -f "$WASM_SRC" ]]; then
                mkdir -p "$CLAWOS_HOME/tools/$tool"
                cp "$WASM_SRC" "$CLAWOS_HOME/tools/$tool/tool.wasm"
                chown -R "$CLAWOS_USER:$CLAWOS_USER" "$CLAWOS_HOME/tools/$tool"
                log "  ✓ $tool → $CLAWOS_HOME/tools/$tool/tool.wasm"
                (( WASM_OK++ )) || true
            fi
        else
            warn "  ✗ $tool WASM build 失敗（略過）"
            (( WASM_FAIL++ )) || true
        fi
    done
    log "WASM tools: $WASM_OK 成功, $WASM_FAIL 失敗"
fi

# ── 6. 安裝 Binaries ─────────────────────────────────────────
progress "安裝 Binaries"

RELEASE_DIR="target/$BUILD_TARGET/release"

for bin in clawos-agent clawos-ebpf-userspace; do
    if [[ -f "$RELEASE_DIR/$bin" ]]; then
        install -m 755 "$RELEASE_DIR/$bin" "$INSTALL_PREFIX/$bin"
        log "  $INSTALL_PREFIX/$bin"
    else
        warn "  $bin binary 不存在（$RELEASE_DIR/$bin），略過"
    fi
done

# 安裝 scripts
for script in preflight.sh setup-netns.sh setup-cgroups.sh; do
    if [[ -f "scripts/$script" ]]; then
        install -m 755 "scripts/$script" "$INSTALL_PREFIX/clawos-${script%.sh}"
        log "  $INSTALL_PREFIX/clawos-${script%.sh}"
    fi
done

# ── 7. Systemd Service ────────────────────────────────────────
progress "安裝 Systemd Service"

cat > /etc/systemd/system/clawos-agent.service << SERVICE_EOF
[Unit]
Description=ClawOS AI Agent
After=network.target
Wants=clawos-ebpf.service

[Service]
Type=exec
User=${CLAWOS_USER}
Group=${CLAWOS_USER}
WorkingDirectory=${CLAWOS_HOME}
ExecStart=/bin/ip netns exec clawos-agent ${INSTALL_PREFIX}/clawos-agent
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=clawos-agent

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=${CLAWOS_HOME} /run/clawos /var/log/clawos

[Install]
WantedBy=multi-user.target
SERVICE_EOF

cat > /etc/systemd/system/clawos-ebpf.service << SERVICE_EOF
[Unit]
Description=ClawOS eBPF Monitor
After=network.target
Before=clawos-agent.service

[Service]
Type=exec
User=root
ExecStart=${INSTALL_PREFIX}/clawos-ebpf-userspace
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=clawos-ebpf

[Install]
WantedBy=multi-user.target
SERVICE_EOF

systemctl daemon-reload
log "systemd service 已安裝"
log "  啟動: sudo systemctl enable --now clawos-agent clawos-ebpf"

# ── 8. 系統資源設定 ───────────────────────────────────────────
progress "系統資源設定"

log "設定 cgroup v2..."
bash "$SCRIPT_DIR/setup-cgroups.sh"

log "設定 network namespace..."
bash "$SCRIPT_DIR/setup-netns.sh"

log "載入 AppArmor profile..."
if command -v apparmor_parser &>/dev/null; then
    apparmor_parser -r "$REPO_ROOT/apparmor/clawos-agent" 2>/dev/null && \
        log "AppArmor profile 已載入" || \
        warn "AppArmor profile 載入失敗（可能需要 enforce mode）"
else
    warn "apparmor_parser 不存在，跳過 AppArmor 設定"
fi

# ── 9. Preflight 驗證 ─────────────────────────────────────────
progress "Preflight 驗證"

if [[ -f "$SCRIPT_DIR/preflight.sh" ]]; then
    bash "$SCRIPT_DIR/preflight.sh" || warn "部分 preflight 檢查失敗，請檢查上方輸出"
else
    warn "preflight.sh 不存在，跳過驗證"
fi

# ── 完成 ──────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}${GREEN}  ClawOS 安裝完成 ✓${RESET}"
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo "  下一步："
echo "  1. 啟動 eBPF monitor:  sudo systemctl enable --now clawos-ebpf"
echo "  2. 啟動 agent:         sudo systemctl enable --now clawos-agent"
echo "  3. 查看 log:           sudo journalctl -fu clawos-agent"
echo "  4. 互動式 shell:       sudo -u $CLAWOS_USER ip netns exec clawos-agent clawsh"
echo ""
echo -e "  ${YELLOW}重要提醒：${RESET}"
echo "  - Gateway bearer token 請妥善保存（已顯示在上方 keyring 初始化步驟）"
echo "  - 若需輪換 clawfs-key，必須先備份所有加密資料再執行輪換"
echo "  - 正式上線前請執行 P4 gate: make gate-p4"
echo ""
