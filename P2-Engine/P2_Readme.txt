P2 Engine — 全部落地的東西：
clawos-agent — 完整 Agent 骨架

agent/mod.rs — Agent Loop：分類 → 排程 → 執行 → 回覆，含 heartbeat + routine engine stub
agent/memory.rs — 滑動視窗對話記憶（VecDeque，20 turn）
agent/tool_registry.rs — 掃描 ClawFS tools dir，驗證 WIT world，capability check
router/mod.rs — Intent 分類器（slash command / JSON tool call / keyword / LLM fallback）+ 完整 tests
scheduler/mod.rs — 優先序 BinaryHeap + tokio dispatch loop + cgroup slot 管理
worker/mod.rs — WASM 工具執行引擎（wasmtime Component Model，host function stubs）
ipc/mod.rs — Unix socket NDJSON server，實作 P1.7 協議全部訊息類型
config/mod.rs — Config loader（TOML + .env），P1.4 vector_dims 驗證

clawfs — Storage layer 完整

crypto.rs — AES-256-GCM encrypt/decrypt，key source: keyring/env/file + 完整 tests
vault.rs — Write-once SHA256 vault，RULE-002/003/E002 執行，完整 tests（包含 tamper detection）
search.rs — Hybrid Search：FTS5 + cosine vector（linear scan）→ RRF fusion，tests

Security & Infra

clawos-seccomp — 完整 whitelist 實作 + forbidden syscall 驗證 tests
clawos-ns — pivot_root + User Namespace UID map + veth netns
clawos-ebpf — kernel-side tracepoints（execve/openat）+ LSM hooks skeleton
kernel/clawos-kernel.config — 完整 hardened kernel options
apparmor/clawos-agent — enforce mode profile + WASM worker sub-profile

CI/CD

.github/workflows/ci.yml — lint → test → security audit → musl static binary → preflight sim
.cargo/config.toml — bpf/musl/aarch64 cross-compile targets + aliases

下一步（P3）： 把真實的 IronClaw tools-src WASM 工具、channel 重新打包進 tools/ 目錄，替換掉 worker 裡的 stub，連接真實 LLM provider。