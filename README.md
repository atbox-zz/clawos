# ClawOS — AI-Native Operating System

> Linux 6.6 LTS + IronClaw Agent Loop as an OS service

ClawOS rebuilds the IronClaw AI agent stack as a hardened OS layer. 
Instead of running agents inside Docker containers talking to PostgreSQL, 
ClawOS runs them as first-class kernel citizens: 
isolated by namespaces, restrained by cgroups, watched by eBPF, 
and speaking to a purpose-built encrypted filesystem (ClawFS).

---

## Architecture

```
Layer 8  Voice Layer          Qwen3-TTS (optional --features voice)
Layer 7  ClawOS Shell         AI-native CLI
Layer 6  Agent Runtime        IronClaw Agent Loop as OS service
Layer 5  WASM Kernel Bridge   userspace daemon + kernel ABI bridge (WIT)
Layer 4  eBPF AI Monitor      syscall/file/network/anomaly monitoring
Layer 3  ClawFS               SQLite + HNSW vectors + AES-256-GCM
Layer 2  Hardened Kernel      Linux 6.6 LTS + seccomp + LSM + KASLR + cgroup v2
Layer 1  Hardware Trust       TPM 2.0 + Secure Boot
```

## Quick Start (development)

```bash
# Prerequisites: Rust 1.85+, libseccomp-dev, sqlite3-dev, bpftool
git clone https://github.com/atbox-zz/clawos
cd clawos

# Setup system resources (run as root)
sudo scripts/setup-cgroups.sh
sudo scripts/setup-netns.sh
sudo apparmor_parser -r apparmor/clawos-agent

# Run pre-flight check
scripts/preflight.sh

# Start eBPF monitor (requires root)
sudo target/release/clawos-ebpf-userspace &

# Start agent (inside network namespace)
export CLAWFS_KEY=$(openssl rand -hex 32)
export CLAWOS_LOG=clawos=info
ip netns exec clawos-agent cargo run -p clawos-agent
```

## Build

```bash
# Development build
cargo build --workspace

# Production: static x86_64 binary
cargo build-release-x86

# eBPF programs
cargo build-ebpf

# All tests
cargo test-all

# Security + lint gate (P2 requirement)
cargo lint
```

## Phase Status

| Phase | Description | Status |
|-------| ---------------------------------------|--------|
| P1    | Freeze 8 core specs                    | ✅ Complete |
| P2    | Engine skeleton (Rust)                 | ✅ Complete |
| P3    | Fill data (tools, channels, migration) | 🔄 In progress |
| P4    | Calibrate (perf, security, ISO)        | ⏳ Pending |

## P1 Frozen Specs

All specs in `specs/p1/` are frozen. Modifications require dual-agent review (Security + Core Dev) + version bump.

| Spec | File | Status |
|------| i---------------------------------|--------|
| P1.1 | `wit/clawos.wit`                  | ✅ Frozen |
| P1.2 | `specs/p1/seccomp-whitelist.json` | ✅ Frozen |
| P1.3 | `specs/p1/ebpf-event-structs.rs`  | ✅ Frozen |
| P1.4 | `specs/p1/clawfs-spec.json`       | ✅ Frozen |
| P1.5 | `specs/p1/resource-quotas.json`   | ✅ Frozen |
| P1.6 | `specs/p1/apparmor-spec.json`     | ✅ Frozen |
| P1.7 | `specs/p1/ipc-protocol.json`      | ✅ Frozen |
| P1.8 | `specs/p1/api-surface.json`       | ✅ Frozen |

## Workspace Structure

```
crates/
  clawos-agent/        Main agent loop, router, scheduler, worker, IPC
  clawfs/              AI filesystem: SQLite + HNSW + AES-256-GCM + vault
  clawos-llm/          LLM provider abstraction + injection guard
  clawos-ebpf/         eBPF kernel programs (no_std)
  clawos-ebpf-userspace/ eBPF loader + anomaly engine + Prometheus metrics
  clawos-seccomp/      seccomp-BPF whitelist enforcement
  clawos-ns/           Namespace isolation (user + PID + mount)
  clawos-voice/        Qwen3-TTS integration (optional)

tools/
  web-search/          Web search WASM tool (Brave/Tavily)
  file-read/           ClawFS file read WASM tool
  summarise/           LLM-powered summarisation WASM tool
  shell-exec/          Restricted command runner (disabled by default)

channels/
  telegram/            Telegram bot channel
  web-gateway/         HTTP REST + SSE + WebSocket gateway (axum)

specs/p1/              8 frozen P1 specifications
wit/                   WIT interface definitions (clawos-tool, clawos-channel)
kernel/                Linux 6.6 kernel config
apparmor/              AppArmor profiles
scripts/               Setup, calibration, security, benchmark, QEMU test
migrations/            PostgreSQL → ClawFS migration script
image/                 Buildroot config + ISO assembly scripts
tests/                 Integration tests
```

## Security Model

- **seccomp-BPF**: strict allowlist (P1.2), `SIGKILL` on violation
- **AppArmor**: enforce mode, WASM workers in sub-profile
- **eBPF LSM**: kernel-level hooks for file/network policy
- **cgroup v2**: per-process memory (512MB), CPU (50%), PID (128) limits
- **User Namespace**: UID 0 inside → UID 65534 (nobody) on host
- **Network Namespace**: isolated veth, only ClawFS port allowed out
- **Vault**: SHA256-signed frozen spec store, write-once
- **Voice layer**: runs outside sandbox (needs audio hardware)

## License

Apache-2.0 OR MIT
