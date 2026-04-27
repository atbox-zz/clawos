# ClawOS WASM Runtime Bridge

## Overview

The WASM Runtime bridge is a userspace daemon that connects WASM tools to 
the Linux Kernel 6.6 LTS ABI via the WIT (WebAssembly Interface Types) 
interface defined in P1.1.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ WASM Component (Tool)                                       │
│ - Memory: 256MB (configurable)                              │
│ - CPU: 5% via cgroup v2                                     │
│ - Network: Proxied through host functions                   │
└────────────────────┬────────────────────────────────────────┘
                     │ WIT Interface (wasm32 ABI)
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ Userspace Daemon (clawos-wasm-bridge)                       │
│ - wasmtime 27+ runtime                                      │
│ - WIT host function implementations                         │
│ - seccomp filter applied                                    │
│ - cgroup v2 resource limits                                 │
└────────────────────┬────────────────────────────────────────┘
                     │ POSIX Syscalls
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ Linux Kernel 6.6 LTS                                        │
│ - eBPF LSM hooks (monitoring)                               │
│ - AppArmor profiles (enforcement)                           │
│ - Namespace isolation (user, pid, net, mnt)                 │
└─────────────────────────────────────────────────────────────┘
```

## HIGH Conflict Resolution: Userspace Daemon vs Kernel Space

### Conflict (SKILLS.md line 342)

**WASM memory safety model in kernel space conflicts with Rust ownership semantics.**

### Resolution

**Use eBPF CO-RE + userspace WASM daemon; do NOT force wasmtime into kernel space.**

### Rationale

1. **Memory Safety**: WASM runtime in userspace maintains memory isolation between WASM components and kernel space
2. **Security**: seccomp filter limits daemon's syscall access to a minimal whitelist
3. **Monitoring**: eBPF LSM hooks monitor all daemon operations for security auditing
4. **Stability**: Kernel space crashes are avoided - userspace daemon failures are contained
5. **Maintainability**: Userspace code is easier to debug, test, and update

### Architecture Details

```
WASM Component → Userspace Daemon (wasmtime) → Kernel Syscalls
                      ↑
                      │ eBPF LSM Monitoring
                      │ AppArmor Enforcement
                      │ cgroup v2 Limits
```

### Security Layers

1. **WASM Sandbox (Layer 5a)**
   - Memory isolation: 256MB heap limit per WASM instance
   - CPU limit: 5% via cgroup v2 (50000/1000000)
   - No direct syscalls: All kernel access via WIT host functions
   - Capability-based access: Resources accessed via handles only

2. **seccomp-BPF Filter (Layer 5b)**
   - Applied to userspace daemon
   - Whitelist of ~40 allowed syscalls
   - Blocks dangerous syscalls: execve, fork, ptrace, mount, kexec_load, etc.

3. **cgroup v2 Resource Limits (Layer 5c)**
   - Memory: 256MB max per WASM instance
   - CPU: 5% quota (50000/1000000)
   - PIDs: 32 max per instance
   - No swap: memory.swap.max=0

4. **AppArmor Profile (Layer 5d)**
   - Restricts file access to ClawFS
   - Allows network to PostgreSQL (port 5432) only
   - Denies access to sensitive files (/root, /etc/shadow, /etc/passwd)

5. **eBPF LSM Monitoring (Layer 4)**
   - Monitors all file operations (open/read/write)
   - Monitors all network operations (socket/connect)
   - Monitors all process operations (execve/clone)
   - Anomaly detection triggers alerts

## WIT Interface Implementation

The bridge implements all host functions from P1.1 WIT specification:

### Filesystem Interface
- `open`, `mkdir`, `rmdir`, `unlink`, `rename`
- `stat`, `opendir`, `link`, `symlink`, `readlink`
- `chmod`, `chown`, `truncate`, `sync`

### Network Interface
- `socket`, `resolve`, `gethostname`
- Note: All network requests proxied through host function (no direct egress)

### Cgroup Interface
- `create`, `open`, `delete`
- `add_process`, `remove_process`
- Resource limits: memory, CPU, PIDs

### Memory Interface
- `allocate`, `get_usage`, `get_limit`
- Shared memory regions between WASM and kernel

### Device Interface
- `open`, `get_info`
- Block and character device access

### System Interface
- `get_info`, `get_time`, `sleep`
- `get_env`, `set_env`, `get_pid`, `get_ppid`, `exit`

### Logging Interface
- `log`, `debug`, `info`, `warn`, `error`
- All logs prefixed with `[WASM]` for identification

## Error Code Mapping

All errors map to P1.7 error codes:

| Code    | Name          | Description                            |
| --------| --------------| ---------------------------------------|
| 0       | SUCCESS       | Operation completed successfully       |
| 1       | EAGAIN        | Operation would block                  |
| 2       | EIO           | I/O error                              |
| 3       | ENOENT        | Entity not found                       |
| 4       | EPERM         | Permission denied                      |
| 5       | EPROTO        | Protocol error                         |
| 6       | ETIMEOUT      | Operation timeout                      |
| 7       | EINTERNAL     | Internal error (should be logged)      |
| 8       | EPANIC        | Unrecoverable error (trigger rollback) |
| 100-105 | WASM errors   | WASM-specific errors                   |
| 200-209 | ClawOS errors | ClawOS-specific errors                 |

## Resource Limits (P1.5)

Per WASM instance:
- Memory: 256MB max
- CPU: 5% quota (50000/1000000)
- PIDs: 32 max
- No swap: memory.swap.max=0
- OOM group kill: memory.oom.group=1

## Building

```bash
cd domains/wasm
cargo build --release
```

## Running

```bash
cargo run --release --bin clawos-wasm-daemon
```

## Testing

```bash
cargo test
```

## Dependencies

- wasmtime 27+ (Component Model support)
- wasmtime-wasi 27+
- cargo-component 0.20+
- libseccomp 2.5+
- cgroups-rs 0.3+
- tokio 1.40+
- tracing 0.1+

## References

- P1.1: WIT Interface Specification
- P1.5: cgroup v2 Resource Quotas
- P1.7: IPC Protocol
- SKILLS.md line 342: HIGH conflict resolution
