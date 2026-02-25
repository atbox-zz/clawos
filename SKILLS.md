---
name: clawos
description: >
  Use this skill when building, extending, or operating ClawOS — an AI-Native Operating System
  based on nearai/ironclaw and Linux Kernel 6.6 LTS.
  
Triggers include: any mention of "ClawOS", "IronClaw kernel", "eBPF agent",
  "ClawFS", "AI OS", "Kernel Agent", seccomp/namespace/cgroup hardening for
  AI workloads, or WASM sandbox kernel integration. Also use when planning or
  executing multi-phase AI agent workflows for OS-level Rust projects.
version: 1.0.0
license: Apache-2.0 / MIT (inherited from nearai/ironclaw)
authors:
  - ClawOS Project (Claude/Anthropic assisted)
date: 2026-02-23
---

# ClawOS — AI 任務計劃規格書

## Overview

ClawOS is an AI-Native Operating System built on **Linux Kernel 6.6 LTS**,
integrating the **IronClaw AI Agent engine** (nearai/ironclaw) directly at the
kernel layer. Unlike traditional OSes that only manage hardware resources,
ClawOS embeds the AI Agent runtime, security sandbox, and tool ecosystem into
the Kernel itself, making AI workloads **first-class OS citizens**.

**Project Stats:** 47 Tasks · 8 AI Agents · 24 Weeks · 7 Security Layers · 4 Phases

---

## Target Architecture (7 Layers)

```
Layer 7  ClawOS Shell       AI-native CLI, replaces bash/zsh
Layer 6  Agent Runtime      IronClaw Agent Loop embedded as OS service
Layer 5  WASM Kernel Bridge WASM sandbox → userspace daemon + kernel ABI bridge
Layer 4  eBPF AI Monitor    Kernel-level monitoring: syscall/file/network/anomaly
Layer 3  ClawFS             AI-aware FS: vector index + AES-256-GCM encryption
Layer 2  Hardened Kernel    Linux 6.6 LTS + seccomp-BPF + LSM + KASLR + cgroup v2
Layer 1  Hardware Trust     TPM 2.0 + Secure Boot + eBPF JIT + MODULE_SIG_FORCE
```

## IronClaw Source → ClawOS Component Mapping

| IronClaw Path         | ClawOS Component          | Migration Strategy                  |
|-----------------------|---------------------------|-------------------------------------|
| `src/agent/loop.rs`   | ClawOS Kernel Service     | Refactor as OS daemon + IPC         |
| `src/router/`         | ClawOS Router (userspace) | Keep architecture, remove PG dep    |
| `src/scheduler/`      | cgroup-aware Task Sched   | Integrate cgroup v2 PID tracking    |
| `src/worker/`         | Isolated Rust async worker| Each worker gets own cgroup slice   |
| `src/orchestrator/`   | Namespace Orchestrator    | Replace Docker with Linux namespaces|
| `channels-src/`       | ClawOS Channel WASM       | Repack under new WIT interface      |
| `tools-src/`          | ClawOS Tool Registry      | Integrate with ClawFS tool paths    |
| `wit/`                | ClawOS WIT v2.0           | Extend with Kernel ABI calls        |
| `migrations/`         | ClawFS Schema Migration   | SQLite + HNSW format                |
| `docker/`             | **Deprecated**            | Fully replaced by Linux namespaces  |

---

## Execution Methodology: 4-Phase Pipeline

> **Critical:** To prevent data mismatch or logic breaks between agents, always
> follow this strict order. A **Gate** must be passed before advancing phases.

```
P1 Build Standards → P2 Build Engine → P3 Fill Data → P4 Calibrate
   (Protocols)          (Logic)           (Content)      (Balance)
```

---

## Phase 1 — Build Standards (Protocols)

**Rule:** No code is written until ALL specifications are finalized and signed.

### Deliverables

| ID   | Deliverable                                           | Owner          |
|------|-------------------------------------------------------|----------------|
| P1.1 | WIT Interface Spec Book (WASM ↔ Kernel ABI)           | WASM Agent     |
| P1.2 | seccomp syscall whitelist JSON Schema (frozen)        | Security Agent |
| P1.3 | eBPF event struct format frozen (AnomalyEvent, etc.)  | eBPF Agent     |
| P1.4 | ClawFS path convention + Secrets encryption format    | FS Agent       |
| P1.5 | cgroup v2 resource quota standard values table        | Infra Agent    |
| P1.6 | AppArmor profile rule language spec                   | Security Agent |
| P1.7 | Inter-agent IPC protocol (format, error codes)        | Core Dev Agent |
| P1.8 | ClawOS public API Surface document (syscall interface)| Core Dev Agent |

### 🔒 Gate P1

```
All spec documents SHA256-signed and stored in ClawFS Vault.
No agent may proceed to P2 until this gate is cleared.
```

---

## Phase 2 — Build Engine (Logic)

**Rule:** Implement Rust engine logic per P1 specs. Do NOT populate business data.

### Deliverables

| ID   | Deliverable                                     | Owner              |
|------|-------------------------------------------------|--------------------|
| P2.1 | Kernel Config generation script (per P1.5)      | Kernel Engineer    |
| P2.2 | seccomp-BPF filter Rust implementation (P1.2)   | Security Agent     |
| P2.3 | eBPF Aya-rs program with P1.3 event struct hooks| eBPF Agent         |
| P2.4 | Namespace isolator Rust impl (per P1.1 ABI)     | Security Agent     |
| P2.5 | IronClaw Agent Loop → ClawOS Kernel Service     | Core Dev Agent     |
| P2.6 | WASM Runtime bridge (per P1.1 WIT spec)         | WASM Agent         |
| P2.7 | ClawFS Rust crate skeleton (per P1.4 spec)      | FS Engineer Agent  |
| P2.8 | AppArmor profile generator (per P1.6 rules)     | Security Agent     |

### 🔒 Gate P2

```bash
cargo build --release   # Must succeed
cargo clippy --all      # Must produce zero warnings
```

---

## Phase 3 — Fill Data (Content)

**Rule:** Engine is ready. Fill with real tool definitions, memory, config values.

### Deliverables

| ID   | Deliverable                                        | Owner          |
|------|----------------------------------------------------|----------------|
| P3.1 | IronClaw tool library migrated to ClawOS WASM fmt  | WASM Agent     |
| P3.2 | channels-src (Telegram/Slack) repackaged           | WASM Agent     |
| P3.3 | PostgreSQL migrations → ClawFS schema              | FS Agent       |
| P3.4 | Identity Files + Workspace initial data load       | Core Dev Agent |
| P3.5 | Prompt Injection defense pattern DB loaded         | Security Agent |
| P3.6 | Endpoint allowlist config values populated         | Security Agent |
| P3.7 | LLM Provider config (NEAR AI / OpenRouter bridge)  | Core Dev Agent |
| P3.8 | Secrets encryption key init (kernel keyring)       | Security Agent |

### 🔒 Gate P3

```bash
cargo test              # ALL tests must pass
# Security audit suite: seccomp, cgroup, ns, AppArmor tests = 100% pass
```

---

## Phase 4 — Calibrate (Balance)

**Rule:** System-wide balance: performance / security / functionality triangle.

### Deliverables

| ID   | Deliverable                                           | Owner               |
|------|-------------------------------------------------------|---------------------|
| P4.1 | seccomp whitelist pruning (strace-assisted)           | Security Agent      |
| P4.2 | cgroup resource value calibration (benchmark)         | Infra Agent         |
| P4.3 | eBPF Ring Buffer size tuning (avoid event loss)       | eBPF Agent          |
| P4.4 | WASM memory/CPU limit fine-tuning                     | WASM Agent          |
| P4.5 | ClawFS HNSW parameter tuning (ef_construction, M)     | FS Agent            |
| P4.6 | AppArmor profile refinement (remove over-restrictions)| Security Agent      |
| P4.7 | XDP filter performance test (packet/s baseline)       | eBPF Agent          |
| P4.8 | Full system integration test + Security Report        | DevOps Agent        |

### 🔒 Gate P4

```
Security Report: zero CRITICAL findings
  (HIGH findings must have attached mitigation plan)
Performance benchmark: ≥ 80% of original IronClaw baseline
QEMU integration test: x86_64 AND aarch64 both boot successfully
```

---

## Task Catalog — 47 Tasks / 7 Domains

### Domain A — Kernel Foundation

| ID   | Task                                                | Agent           | Week  |
|------|-----------------------------------------------------|-----------------|-------|
| A-01 | Linux 6.6 LTS custom kernel config compilation      | Kernel Engineer | W1-2  |
| A-02 | KASLR / SMEP / SMAP / Stack protection enable       | Kernel Engineer | W1-2  |
| A-03 | BPF_LSM + DEBUG_INFO_BTF compilation integration    | Kernel Engineer | W2-3  |
| A-04 | Minimal rootfs design (musl libc + static binary)   | Build Engineer  | W3-4  |
| A-05 | Kernel Module signing (MODULE_SIG_FORCE)            | Security Agent  | W3-4  |
| A-06 | Lockdown Mode integration (CONFIDENTIALITY)         | Security Agent  | W4    |

### Domain B — eBPF Monitoring & Security

| ID   | Task                                                | Agent           | Week  |
|------|-----------------------------------------------------|-----------------|-------|
| B-01 | eBPF framework setup with Aya-rs foundation         | eBPF Agent      | W3-4  |
| B-02 | Tracepoint hooks: syscall monitoring (execve/openat)| eBPF Agent      | W4-5  |
| B-03 | LSM hooks: file_open / socket_connect enforcement   | eBPF Agent      | W5-6  |
| B-04 | XDP network filter (TCP:5432 PostgreSQL only)       | eBPF Agent      | W5-6  |
| B-05 | Ring Buffer anomaly detection engine                | eBPF Agent      | W6-7  |
| B-06 | Prometheus metrics integration (eBPF → userspace)   | Observability   | W7-8  |
| B-07 | CO-RE (Compile Once, Run Everywhere) port           | eBPF Agent      | W7-8  |

### Domain C — seccomp / Namespace / cgroup Isolation

| ID   | Task                                                | Agent           | Week  |
|------|-----------------------------------------------------|-----------------|-------|
| C-01 | IronClaw process seccomp-BPF whitelist design       | Security Agent  | W4-5  |
| C-02 | strace-assisted actual syscall requirement analysis | Analysis Agent  | W4    |
| C-03 | User Namespace + UID mapping (65534 nobody)         | Security Agent  | W5-6  |
| C-04 | PID / Mount / Net / UTS namespace isolation scripts | Security Agent  | W5-6  |
| C-05 | pivot_root minimal rootfs switch implementation     | Build Engineer  | W6    |
| C-06 | cgroup v2: memory.max / cpu.max / pids.max config   | Infra Agent     | W6-7  |
| C-07 | Network namespace + veth + iptables rules           | Network Agent   | W6-7  |

### Domain D — IronClaw Core Engine Migration

| ID   | Task                                                | Agent           | Week  |
|------|-----------------------------------------------------|-----------------|-------|
| D-01 | IronClaw Agent Loop → ClawOS Kernel Service         | Core Dev Agent  | W6-8  |
| D-02 | Router / Scheduler → OS-level IPC replacement       | Core Dev Agent  | W7-9  |
| D-03 | Worker Pool → cgroup-isolated Rust async tasks      | Core Dev Agent  | W8-10 |
| D-04 | WASM Runtime (wasmtime) userspace daemon bridge     | WASM Agent      | W9-12 |
| D-05 | WIT interface → ClawOS syscall bridge               | WASM Agent      | W10-12 |
| D-06 | Tool Registry → ClawFS integration (tool-as-file)   | Core Dev Agent  | W11-13 |
| D-07 | Routines Engine → systemd timer / eBPF event trigger| Core Dev Agent  | W12-14 |
| D-08 | Heartbeat System → kernel watchdog integration      | Core Dev Agent  | W13-14 |

### Domain E — ClawFS File System

| ID   | Task                                                | Agent           | Week  |
|------|-----------------------------------------------------|-----------------|-------|
| E-01 | ClawFS design spec: vector index + AES-256-GCM      | FS Engineer     | W8-10 |
| E-02 | PostgreSQL + pgvector → embedded SQLite + HNSW      | FS Engineer     | W9-11 |
| E-03 | Hybrid Search (FTS5 + Vector) kernel layer impl     | FS Engineer     | W11-13 |
| E-04 | Workspace Filesystem API → POSIX-compatible iface   | FS Engineer     | W13-15 |
| E-05 | Secrets Vault: kernel keyring + AES-GCM integration | Security Agent  | W12-14 |
| E-06 | Identity Files → persistent kernel memory mechanism | Core Dev Agent  | W14-15 |

### Domain F — AppArmor / LSM Mandatory Access Control

| ID   | Task                                                | Agent           | Week  |
|------|-----------------------------------------------------|-----------------|-------|
| F-01 | ClawOS AppArmor Profile design and authoring        | Security Agent  | W5-7  |
| F-02 | aa-complain → aa-enforce gradual test flow          | Security Agent  | W7-9  |
| F-03 | eBPF LSM custom hooks (file/exec/socket)            | eBPF Agent      | W8-10 |
| F-04 | SELinux Policy alternative (optional)               | Security Agent  | W10-12 |
| F-05 | Lockdown Integrity verification (Module + kexec)    | Security Agent  | W11-13 |

### Domain G — Integration / Testing / Deployment

| ID   | Task                                                | Agent           | Week  |
|------|-----------------------------------------------------|-----------------|-------|
| G-01 | Pre-flight startup check script (Rust impl)         | DevOps Agent    | W14-15 |
| G-02 | systemd hardened unit full configuration            | DevOps Agent    | W14-16 |
| G-03 | Automated security audit test suite (cargo test)    | QA Agent        | W16-18 |
| G-04 | Security Report periodic generation script          | Observability   | W17-18 |
| G-05 | Buildroot minimal Linux image packaging             | Build Engineer  | W18-20 |
| G-06 | ClawOS ISO image build + QEMU validation            | Build Engineer  | W20-22 |
| G-07 | Hardware testing (x86_64 + aarch64)                 | QA Agent        | W21-23 |
| G-08 | Performance benchmark (vs standard Ubuntu LTS)      | QA Agent        | W22-24 |
| G-09 | ClawOS v0.1.0 Alpha release                         | Release Agent   | W24    |

---

## Agent Roster — 8 Agents

Each agent has a strict boundary of responsibility, IO format, and forbidden operations.

### 🔧 Kernel Engineer Agent

- **Responsibility:** Linux Kernel config, compilation, hardening options
- **Inputs:** `P1.5` resource quota spec
- **Outputs:** `.config`, build scripts
- **Tools:** `scripts/config`, `make`, `gcc-plugin`
- **Forbidden:** Modifying eBPF or Rust source code

### ⚡ eBPF Agent

- **Responsibility:** All eBPF kernel programs and userspace receivers
- **Inputs:** `P1.3` event struct definition
- **Outputs:** `.bpf.rs` files, Aya-rs programs
- **Tools:** `aya-rs`, `bpftool`, `bpf-linker`
- **Forbidden:** Modifying cgroup or seccomp configuration

### 🛡 Security Agent

- **Responsibility:** seccomp whitelist, AppArmor profiles, namespace isolation
- **Inputs:** `P1.2`, `P1.6` specs
- **Outputs:** seccomp BPF filter, AppArmor profile
- **Tools:** `libseccomp`, `aa-parser`, `strace`
- **Forbidden:** Touching WASM runtime or ClawFS
- **Special Power:** ONE VETO VOTE on all security-related decisions

### 🔵 Core Dev Agent

- **Responsibility:** Port IronClaw Rust engine logic without touching kernel layer
- **Inputs:** IronClaw `src/`, `P1.1` WIT spec
- **Outputs:** ClawOS Rust crates
- **Tools:** `cargo`, `rustfmt`, `clippy`
- **Forbidden:** Directly operating syscalls or eBPF maps

### 🟦 WASM Agent

- **Responsibility:** wasmtime integration, WIT interface impl, tool WASM packaging
- **Inputs:** `wit/*.wit` files, `tools-src/`
- **Outputs:** `.wasm` binaries, WASM bridge
- **Tools:** `wasm-tools`, `wasmtime`, `cargo-component`
- **Forbidden:** Modifying Kernel config

### 📁 FS Engineer Agent

- **Responsibility:** Design and implement ClawFS: vector index, encryption, POSIX iface
- **Inputs:** `P1.4` ClawFS spec
- **Outputs:** ClawFS Rust crate
- **Tools:** `sqlite`, `sqlcipher`, `usearch` (HNSW)
- **Forbidden:** Touching eBPF or seccomp

### 👁 Observability Agent

- **Responsibility:** Monitoring, alerting, logging pipeline, Security Reports
- **Inputs:** eBPF Ring Buffer, cgroup stats
- **Outputs:** Prometheus metrics, report scripts
- **Tools:** `prometheus`, `grafana`, `journalctl`
- **Forbidden:** Modifying any security policy

### 🚀 Build Engineer / DevOps Agent

- **Responsibility:** rootfs, ISO image builds, systemd units, CI/CD pipelines
- **Inputs:** All agent output artifacts
- **Outputs:** ClawOS `.iso`, systemd `.service` files
- **Tools:** `buildroot`, `qemu`, `docker`
- **Forbidden:** Modifying Kernel or Rust source code

---

## Conflict & Blocker Analysis

### HIGH Priority — Must resolve before advancing phases

| Conflict | Tasks | Resolution |
|----------|-------|------------|
| WASM memory safety model in kernel space conflicts with Rust ownership | P2.4 / D-04 | Use eBPF CO-RE + userspace WASM daemon; do NOT force wasmtime into kernel space |
| PostgreSQL dependency contradicts minimal rootfs | P3.3 / E-02 | Phase 3: replace with embedded SQLite + pgvector C library statically linked |
| seccomp whitelist vs Rust tokio async runtime syscall requirements | P2.2 / C-01 | Use strace to analyze tokio's actual syscalls (C-02) BEFORE finalizing whitelist |

### MED Priority — Must resolve within same phase

| Conflict | Tasks | Resolution |
|----------|-------|------------|
| eBPF LSM hook vs AppArmor rule conflict (double judgment) | B-03 / F-03 | Priority order: eBPF LSM DENY > AppArmor. Prevents mutual cancellation |
| User Namespace uid_map vs PostgreSQL connection auth | C-03 / D-01 | mTLS client certificate auth replaces uid-based auth; fully decoupled |
| cgroup v2 pids.max=64 vs Rust tokio thread pool | C-06 / D-03 | Profile actual thread count; set pids.max ≥ (tokio threads + WASM workers + buffer) |
| XDP filter vs WASM tool dynamic external HTTP requests | B-04 / D-06 | WASM tool HTTP proxied through host function; no direct network egress; XDP unchanged |
| WIT interface version vs channels-src WASM ABI incompatibility | P1.1 / D-05 | Freeze WIT version in Phase 1; channels-src repackaged per ClawOS WIT |

### LOW Priority — Monitor but non-blocking

| Conflict | Tasks | Resolution |
|----------|-------|------------|
| ClawFS vector dimension mismatch with IronClaw memory system | E-02 / E-03 | P1 spec defines unified vector dimension (default 1536 or 3072) |
| Buildroot static binary vs wasmtime JIT needs mprotect | G-05 / D-04 | seccomp explicitly allows mprotect(PROT_READ\|PROT_EXEC); already in C-01 whitelist |
| AppArmor enforce mode blocks eBPF program loading | F-02 / B-01 | AppArmor profile explicitly adds `capability bpf`; verify during complain mode test |
| Heartbeat System vs kernel watchdog timer precision | D-08 / G-02 | Heartbeat uses CLOCK_MONOTONIC; watchdog uses independent kernel timer |

---

## Gate Validation Checklist

### Gate P1 → P2 (Standards → Engine)

```
✅ WIT interface version frozen; WASM Agent cannot unilaterally modify
✅ seccomp syscall list SHA256-signed; Security Agent is sole authorized modifier
✅ eBPF event struct frozen; eBPF Agent and Observability Agent share same version
⚠️ BLOCKER: tokio version upgrade may introduce new syscalls → FIX: freeze Cargo.lock
⚠️ BLOCKER: cargo-component may not support target ABI → FIX: confirm toolchain version in P1
```

### Gate P2 → P3 (Engine → Data)

```
✅ cargo build --release success confirms ABI compatibility
✅ clippy zero warnings ensures downstream agents get bug-free engine
⚠️ BLOCKER: wasmtime version must match Core Dev Agent Rust version
⚠️ BLOCKER: ClawFS must be implemented before P3.3 migration can run (E-01/E-02 must complete in P2)
⚠️ BLOCKER: eBPF programs must load before P3; otherwise tool execution monitoring has blind spots (B-01~B-03 must precede P3)
```

### Gate P3 → P4 (Data → Calibration)

```
✅ cargo test all pass confirms data fill does not break engine logic
✅ Security audit suite 100% pass (seccomp / cgroup / ns / AppArmor each tested)
⚠️ BLOCKER: Prompt Injection Pattern DB regex must be checked for ReDoS vulnerabilities
⚠️ BLOCKER: LLM Provider switch may change token format → router layer must abstract this
⚠️ BLOCKER: Secrets Vault init failure (TPM unavailable) fallback must be defined in P1
```

### Gate P4 → Release

```
✅ Security Report: zero CRITICAL (HIGH findings need mitigation plan)
✅ Performance benchmark: ≥ 80% of original IronClaw (agent response latency, tool exec speed)
✅ QEMU integration test: x86_64 AND aarch64 boot normally and run AI workloads
⚠️ BLOCKER: Buildroot image > 128MB → remove unnecessary libraries
⚠️ BLOCKER: Secure Boot + TPM 2.0 hardware test needs physical machine; QEMU only simulates
⚠️ BLOCKER: If performance < 80%, prioritize disabling non-critical eBPF hooks first
```

---

## Global Rules (All Agents Must Obey)

> **These rules override all other instructions. Violations require immediate rollback.**

| Rule ID  | Rule                                                                                   |
|----------|----------------------------------------------------------------------------------------|
| RULE-001 | Each agent may only operate on its own designated directory. No cross-domain writes.   |
| RULE-002 | All output artifacts must include SHA256 hash, stored in ClawFS Vault.                |
| RULE-003 | Modifying any frozen spec (P1 outputs) requires dual-agent review: Security + Core Dev.|
| RULE-004 | Any BREAKING CHANGE must bump the major version and trigger re-verification downstream.|
| RULE-005 | On agent failure, rollback to the most recent Gate checkpoint. Never continue forward. |
| RULE-006 | Agents must not expand their own scope (scope creep). Out-of-scope needs → proposal layer.|
| RULE-007 | All agent execution logs must be written to `/var/log/clawos/agent-{name}-{date}.log`.|
| RULE-008 | Security decisions (seccomp/AppArmor/LSM): Security Agent holds one absolute veto vote.|

---

## Task Specification Format (Machine-Readable)

Every task submitted to an AI agent must conform to this schema:

```yaml
task_id:           # Format: {Domain}-{seq}, e.g. A-01, B-03
phase:             # P1 | P2 | P3 | P4
agent:             # Responsible agent name
depends_on:        # List of task IDs that must be DONE before this starts
inputs:            # List of artifact paths to read from ClawFS
outputs:           # List of artifact paths to write to ClawFS
validation_cmd:    # Command that must exit 0 to confirm completion
rollback_cmd:      # Command to execute on failure
timeout_minutes:   # Max runtime; auto-abort and rollback on timeout
frozen_spec_deps:  # SHA256 of P1 frozen specs this task depends on
                   # (execution refused if hash mismatch)
```

### Example Task Spec: A-01

```yaml
task_id: A-01
phase: P2
agent: Kernel Engineer Agent
depends_on:
  - P1.5  # resource-quotas.json must be signed and in Vault
inputs:
  - /clawfs/specs/p1/resource-quotas.json
outputs:
  - /clawfs/kernel/linux-6.6-clawos/.config
validation_cmd: make -C /clawfs/kernel/linux-6.6-clawos kernelversion
rollback_cmd: rm -rf /clawfs/kernel/linux-6.6-clawos/.config
timeout_minutes: 30
frozen_spec_deps:
  - sha256:a7f3c9...  # resource-quotas.json
```

---

## 24-Week Timeline

| Week   | Phase    | Milestone                                    | Key Output                         |
|--------|----------|----------------------------------------------|------------------------------------|
| W1–2   | P1       | Kernel Config confirmed, WIT v1.0 frozen     | `.config`, `wit/*.wit`, spec docs  |
| W3–4   | P1 → P2  | seccomp list finalized, rootfs design done   | `whitelist.json`, rootfs structure |
| W5–6   | P2       | eBPF hooks impl, namespace isolator complete | `ironclaw-ebpf.rs`, netns scripts  |
| W7–8   | P2       | AppArmor profile v1, Agent Loop migrated     | AppArmor profile                   |
| W9–10  | P2 → P3  | WASM bridge done, ClawFS skeleton ready      | `wasm-bridge` crate, `clawfs` crate|
| W11–12 | P3       | Tool library migrated, channels repackaged   | `*.wasm` tools, channel WASM       |
| W13–14 | P3 → P4  | Secrets Vault init, Routines Engine          | kernel keyring init                |
| W15–16 | P4       | Resource calibration, full `cargo test`      | calibration report                 |
| W17–18 | P4       | Security Report generated, perf baseline     | `security-report-*.txt`            |
| W19–20 | P4       | Buildroot image, ISO build                   | `clawos-v0.1.0.iso`                |
| W21–22 | Release  | QEMU validation, x86_64 + aarch64 test       | QA test report                     |
| W23–24 | Release  | **ClawOS v0.1.0 Alpha Release** 🎯           | GitHub Release, CHANGELOG          |

---

## Technology Stack — Locked Versions

> **Cargo.lock is frozen. No agent may upgrade versions unilaterally.**

| Technology       | Version    | Purpose                                    | Owner          |
|------------------|------------|--------------------------------------------|----------------|
| Linux Kernel     | 6.6 LTS    | Main kernel (full eBPF + BTF support)      | Kernel Engineer|
| Rust             | 1.85+      | IronClaw original requirement; keep aligned| Core Dev       |
| aya-rs           | 0.13+      | eBPF Rust framework (kernel + userspace)   | eBPF Agent     |
| wasmtime         | 27+        | WASM runtime (Component Model support)     | WASM Agent     |
| cargo-component  | 0.20+      | WASM Component Model packaging tool        | WASM Agent     |
| SQLite           | 3.47+      | ClawFS backend (FTS5 + vector extension)   | FS Engineer    |
| libseccomp       | 2.5+       | seccomp-BPF Rust bindings                  | Security Agent |
| AppArmor         | 3.1+       | LSM profile (enforce mode)                 | Security Agent |
| buildroot        | 2024.11+   | Minimal rootfs build                       | Build Engineer |
| QEMU             | 8.2+       | x86_64 + aarch64 integration testing       | QA Agent       |
| PostgreSQL       | 15+ (P1-2) | IronClaw original backend; replaced in P3  | FS Engineer    |
| pgvector         | 0.7+ (P1-2)| Vector search; replaced by usearch in P3   | FS Engineer    |

---

## Quick Reference: Key Kernel Config Options

```bash
# eBPF (required)
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_DEBUG_INFO_BTF=y       # CO-RE required
CONFIG_BPF_LSM=y

# Namespaces (required)
CONFIG_NAMESPACES=y
CONFIG_USER_NS=y
CONFIG_PID_NS=y
CONFIG_NET_NS=y
CONFIG_MNT_NS=y               # Mount namespace

# cgroup v2 (required)
CONFIG_CGROUPS=y
CONFIG_MEMCG=y
CONFIG_CGROUP_PIDS=y
CONFIG_CGROUP_BPF=y

# seccomp (required)
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y

# LSM stack (required)
CONFIG_SECURITY=y
CONFIG_SECURITY_APPARMOR=y
CONFIG_LSM="lockdown,yama,apparmor,bpf"

# Hardening (required)
CONFIG_RANDOMIZE_BASE=y       # KASLR
CONFIG_STACKPROTECTOR_STRONG=y
CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_MODULE_SIG=y
CONFIG_MODULE_SIG_FORCE=y
CONFIG_SECURITY_LOCKDOWN_LSM=y
```

---

## Quick Reference: seccomp Minimum Syscall Whitelist

```rust
// Core IronClaw process needs (verified via strace C-02)
let allowed = [
    // Memory
    "mmap", "munmap", "mprotect", "brk", "madvise",
    // File IO
    "read", "write", "open", "openat", "close", "stat", "fstat",
    // Process
    "exit", "exit_group", "getpid", "futex", "clone", "clone3",
    // Network (PostgreSQL only — port enforced by XDP)
    "socket", "connect", "recv", "send", "poll", "epoll_create1",
    "epoll_ctl", "epoll_wait",
    // Time
    "clock_gettime", "clock_nanosleep",
    // Signals
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
    // Misc
    "prctl", "getrandom", "eventfd2", "pipe2",
];
```

---

## References

- Source Repository: [github.com/nearai/ironclaw](https://github.com/nearai/ironclaw)
- License: Apache-2.0 / MIT
- Based on: ClawOS AI 任務計劃規格書 v1.0 (2026-02-23)
- Generated with: Claude (Anthropic) assistance
