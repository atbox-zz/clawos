# ClawOS P4 — Scripts 使用說明

> 目錄：`clawos-patched/scripts/`

---

## 快速導覽

| 腳本 | 用途 | 需要 root | 執行時機 |
|------|------|-----------|----------|
| `install.sh` | 一鍵完整安裝 | ✅ | 首次部署 |
| `setup-cgroups.sh` | 建立 cgroup v2 資源限制 | ✅ | 首次 / 重設 |
| `setup-netns.sh` | 建立網路命名空間 + veth | ✅ | 首次 / 重設 |
| `secrets-init.sh` | 初始化 kernel keyring 金鑰 | ❌（clawos user）| 首次 / 金鑰輪換 |
| `vault-init.sh` | 凍結 P1 spec 到 Vault | ❌ | P1→P2 gate 前 |
| `preflight.sh` | 啟動前環境驗證 | ❌ | 每次啟動前 |
| `security-report.sh` | 產生安全稽核報告 | ✅ | P4 gate |
| `benchmark.sh` | 效能基準測試 | ❌ | P4 gate |
| `calibrate.sh` | 系統全面校準 | ❌ | P4 gate |
| `qemu-test.sh` | QEMU 整合測試 | ✅ | P4 gate / CI |

---

## 建議執行順序

```
首次安裝：
  1. install.sh          ← 自動呼叫下方 2~4
  2. setup-cgroups.sh
  3. setup-netns.sh
  4. secrets-init.sh

上線前驗證：
  5. vault-init.sh
  6. preflight.sh
  7. security-report.sh
  8. benchmark.sh
  9. qemu-test.sh
```

---

## 各腳本詳細說明

---

### `install.sh` — 一鍵安裝

```bash
sudo bash scripts/install.sh
```

**功能：** 完整安裝流程，自動執行步驟 1～9。

**環境變數（可覆寫）：**

| 變數 | 預設值 | 說明 |
|------|--------|------|
| `CLAWOS_USER` | `clawos` | 系統服務帳號名稱 |
| `CLAWOS_HOME` | `/var/lib/clawos` | 資料目錄 |
| `INSTALL_PREFIX` | `/usr/local/bin` | Binary 安裝位置 |
| `BUILD_TARGET` | `x86_64-unknown-linux-musl` | Rust 編譯目標 |
| `SKIP_BUILD` | `0` | 設為 `1` 跳過 cargo build |
| `SKIP_KEYRING` | `0` | 設為 `1` 跳過 keyring（CI 用）|

**範例：**
```bash
# 標準安裝
sudo bash scripts/install.sh

# 已有 binary，跳過編譯
sudo SKIP_BUILD=1 bash scripts/install.sh

# CI 環境（跳過 keyring）
sudo SKIP_BUILD=1 SKIP_KEYRING=1 bash scripts/install.sh

# 自訂目錄
sudo CLAWOS_HOME=/opt/clawos bash scripts/install.sh
```

**前置需求：** `cargo`、`rustup`、`keyctl`、`openssl`、`aa-status`、`ip`、`systemctl`、`x86_64-linux-musl-gcc`

---

### `setup-cgroups.sh` — cgroup v2 資源限制

```bash
sudo bash scripts/setup-cgroups.sh
```

**功能：** 在 `/sys/fs/cgroup/clawos/` 建立四個 slice：`agent`、`wasm`、`ebpf`、`clawfs`，並套用 `specs/p1/resource-quotas.json` 定義的資源上限。

**資源限制（P1.5 frozen）：**

| Slice | 記憶體上限 | CPU 上限 | PID 上限 |
|-------|-----------|---------|---------|
| agent | 512 MB | 50% | 128 |
| wasm | 256 MB | 25% | 32 |
| ebpf | 64 MB | 10% | 16 |
| clawfs | 256 MB | 25% | 32 |

**需求：** kernel 必須掛載 cgroup v2（`grep cgroup2 /proc/mounts`）

---

### `setup-netns.sh` — 網路命名空間

```bash
sudo bash scripts/setup-netns.sh
```

**功能：** 建立 `clawos-agent` netns + veth pair，設定 iptables 規則，只允許 agent 連線到 ClawFS（`10.100.0.1:5432`）和 HTTPS（`443`）。

**網路拓樸：**
```
Host         veth-clawos0 (10.100.0.1)
               │
               │ veth pair
               │
clawos-agent netns
             veth-clawos1 (10.100.0.2)
```

**重建 netns（清除舊設定）：**
```bash
sudo ip netns del clawos-agent 2>/dev/null || true
sudo bash scripts/setup-netns.sh
```

---

### `secrets-init.sh` — Kernel Keyring 初始化

```bash
# 以 clawos user 執行（不要用 root，key 會存在 root keyring）
sudo -u clawos bash scripts/secrets-init.sh
```

**功能：** 將以下金鑰存入 kernel session keyring：

| Key 名稱 | 用途 | 來源 |
|----------|------|------|
| `clawfs-key` | ClawFS AES-256-GCM 加密 | 自動產生 / `.env` |
| `clawos-gateway-token` | Web Gateway Bearer Token | 自動產生 / `.env` |
| `clawos-llm-api-key` | LLM API 金鑰 | `.env` 必填 |

**使用 `.env` 預填：**
```bash
# 建立 .env（不要 commit 到 git！）
cat > .env << 'ENV'
CLAWFS_KEY=<64 hex chars>
CLAWOS_GATEWAY_TOKEN=<your-token>
CLAWOS_LLM_API_KEY=<your-api-key>
ENV

sudo -u clawos bash scripts/secrets-init.sh
```

**金鑰輪換：**
```bash
# 輪換 clawfs-key（注意：舊資料無法用新 key 解密，需先備份）
sudo -u clawos keyctl update \
    $(sudo -u clawos keyctl search @u user clawfs-key) \
    $(openssl rand -hex 32)
```

---

### `vault-init.sh` — Vault 凍結 P1 Specs

```bash
bash scripts/vault-init.sh
```

**功能：** 計算 `specs/p1/` 下所有 8 個規格檔案的 SHA256，凍結到 `vault/` 目錄（write-once，RULE-002）。**P1→P2 gate 前必須執行一次。**

**凍結的規格：**
```
P1.1  wit/clawos.wit
P1.2  specs/p1/seccomp-whitelist.json
P1.3  specs/p1/ebpf-event-structs.rs
P1.4  specs/p1/clawfs-spec.json
P1.5  specs/p1/resource-quotas.json
P1.6  specs/p1/apparmor-spec.json
P1.7  specs/p1/ipc-protocol.json
P1.8  specs/p1/api-surface.json
```

**重新凍結（spec 修改後）：**
```bash
# 必須先通過 dual-agent review（RULE-003）
# 手動刪除 vault 記錄後重新凍結
rm vault/<spec-id>.json
bash scripts/vault-init.sh
```

---

### `preflight.sh` — 啟動前驗證

```bash
bash scripts/preflight.sh
```

**功能：** 驗證 ClawOS 啟動所需的全部環境條件，輸出 PASS/FAIL 逐項報告。

**檢查項目：**
- Kernel 版本 ≥ 5.15
- cgroup v2 掛載
- `clawos-agent` netns 存在
- AppArmor enforce mode（`clawos-agent` profile）
- eBPF LSM hooks 已載入
- Vault 8 個 P1 spec 雜湊驗證
- `clawfs-key` 在 keyring 存在
- IPC socket 目錄權限 `700`

**若 preflight 失敗：**
```bash
# 查看詳細錯誤
bash scripts/preflight.sh 2>&1 | grep FAIL

# 常見修復
sudo bash scripts/setup-cgroups.sh   # cgroup 問題
sudo bash scripts/setup-netns.sh     # netns 問題
sudo apparmor_parser -r apparmor/clawos-agent  # AppArmor 問題
```

---

### `security-report.sh` — 安全稽核報告

```bash
sudo bash scripts/security-report.sh
```

**功能：** 執行 P4 安全稽核，輸出報告到 `/var/lib/clawos/security/security-report-<date>.json`，並凍結到 Vault（`security-report-p4`）。P4→Release gate 的必要步驟。

**稽核項目：**
- seccomp-BPF 白名單有效性
- AppArmor profile enforce 狀態
- eBPF LSM hooks 覆蓋率
- cgroup 資源限制實際生效驗證
- IPC socket 權限
- ClawFS 加密設定
- Binary hardening（PIE、RELRO、stack canary）
- Web Gateway TLS 設定

**報告格式：**
```json
{
  "gate_status": "PASS",
  "generated_at": 1234567890,
  "findings": [],
  "checks_passed": 12,
  "checks_failed": 0
}
```

---

### `benchmark.sh` — 效能基準測試

```bash
bash scripts/benchmark.sh
```

**功能：** 對比 ClawOS 與 IronClaw baseline 的效能，必須達到 ≥ 80% 才能通過 P4 gate。報告輸出到 `/var/lib/clawos/calibration/benchmark-report-<date>.json`。

**測試項目：**
- LLM query 延遲（p50 / p95 / p99）
- ClawFS 向量搜尋吞吐量
- WASM tool 啟動時間
- IPC 訊息延遲
- 端到端 chat 回應時間

**環境變數：**
```bash
# 指定 baseline 數據
BASELINE_FILE=/path/to/ironclaw-baseline.json bash scripts/benchmark.sh

# 只跑特定測試
BENCH_FILTER=llm bash scripts/benchmark.sh
```

---

### `calibrate.sh` — 系統校準

```bash
bash scripts/calibrate.sh
```

**功能：** 根據當前硬體自動調整 `config/config.toml` 的效能參數（LLM timeout、WASM 記憶體上限、HNSW ef_search 等），讓系統在不同硬體上都能達到最佳表現。

**選項：**
```bash
# 只顯示建議，不寫入設定
bash scripts/calibrate.sh --dry-run

# 強制重新校準（忽略已有設定）
bash scripts/calibrate.sh --force
```

---

### `qemu-test.sh` — QEMU 整合測試

```bash
sudo bash scripts/qemu-test.sh
```

**功能：** 在 QEMU VM 內啟動完整 ClawOS，驗證 ISO 開機、agent 啟動、preflight 通過、基本 tool 呼叫正常。P4→Release gate 必要步驟。

**需求：** `qemu-system-x86_64`、已建置的 ISO（`image/clawos-v0.1.0.iso`）

**選項：**
```bash
# 指定 ISO 路徑
ISO=image/clawos-custom.iso sudo bash scripts/qemu-test.sh

# 保留 VM 不關機（除錯用）
KEEP_VM=1 sudo bash scripts/qemu-test.sh
```

**測試結果：** 寫入 `/tmp/clawos-qemu-test-result`（`PASS` 或 `FAIL: <reason>`）

---

## Troubleshooting

### `keyctl: Key not found`
```bash
# 重新初始化 keyring
sudo -u clawos bash scripts/secrets-init.sh
```

### `cgroup: Permission denied`
```bash
sudo bash scripts/setup-cgroups.sh
```

### `AppArmor: profile not found`
```bash
sudo apparmor_parser -r apparmor/clawos-agent
sudo aa-enforce /etc/apparmor.d/clawos-agent
```

### `netns: Cannot open network namespace`
```bash
sudo bash scripts/setup-netns.sh
```

### `cargo build` 失敗（musl linker）
```bash
sudo apt-get install musl-tools
rustup target add x86_64-unknown-linux-musl
```
