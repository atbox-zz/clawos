# ClawOS eBPF Agent

eBPF monitoring agent for ClawOS kernel-level observability using Aya-rs.

## Overview

This eBPF agent provides kernel-level monitoring for ClawOS with the following capabilities:

- **Syscall Tracing**: Monitor execve and openat syscalls
- **File Access Monitoring**: Track file operations via LSM hooks
- **Network Monitoring**: Monitor socket connections via LSM hooks
- **Cgroup Resource Monitoring**: Track resource usage via cgroup hooks

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                     Userspace (Rust)                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   main.rs    │  │  events.rs   │  │  Config      │      │
│  │  (Loader)    │  │  (Structs)   │  │  (Settings)  │      │
│  └──────┬───────┘  └──────────────┘  └──────────────┘      │
│         │                                                  │
│         │ Ring Buffer (1MB)                                │
│         │                                                  │
└─────────┼──────────────────────────────────────────────────┘
          │
          │ eBPF System Calls
          │
┌─────────┼──────────────────────────────────────────────────┐
│         │              Kernel Space (eBPF)                 │
│  ┌──────▼───────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ main.bpf.rs  │  │  events.rs   │  │  Maps        │      │
│  │ (eBPF Progs) │  │  (Structs)   │  │  (Storage)   │      │
│  └──────┬───────┘  └──────────────┘  └──────────────┘      │
│         │                                                  │
│  ┌──────▼──────────────────────────────────────────────┐   │
│  │                   Hooks                             │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │   │
│  │  │ Tracepoint  │  │     LSM     │  │   Cgroup    │  │   │
│  │  │  execve     │  │  file_open  │  │   skb_*     │  │   │
│  │  │  openat     │  │  socket_*   │  │             │  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  │   │
│  └─────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────┘
```

## Event Structures

All event structures follow the P1.3 specification:

| Event Type        | Size       | Description                    |
| ------------------| -----------| -------------------------------|
| AnomalyEvent      | 1056 bytes | Security and monitoring alerts |
| SyscallTraceEvent | 104 bytes  | System call tracing            |
| FileAccessEvent   | 304 bytes  | File access monitoring         |
| NetworkEvent      | 72 bytes   | Network activity monitoring    |
| CgroupEvent       | 304 bytes  | Cgroup resource monitoring     |

## Building

### Prerequisites

- Rust 1.70+
- Linux 6.6 LTS with BTF support
- clang, llvm
- bpf-linker
- bpftool

### Build Commands

```bash
# Build eBPF programs and userspace loader
cargo build --release

# Build only eBPF programs
cargo build --release --target bpfel-unknown-none

# Run tests
cargo test
```

## Running

```bash
# Run with default configuration
sudo ./target/release/clawos-ebpf

# Run with custom interface
sudo ./target/release/clawos-ebpf --iface eth1
```

## Configuration

The eBPF agent can be configured via the `CONFIG` map:

| Field                        | Type | Default | Description                   |
| -----------------------------| -----| --------| ------------------------------|
| enable_syscall_tracing       | u8   | 1       | Enable syscall monitoring     |
| enable_file_monitoring       | u8   | 1       | Enable file access monitoring |
| enable_network_monitoring    | u8   | 1       | Enable network monitoring     |
| enable_cgroup_monitoring     | u8   | 1       | Enable cgroup monitoring      |
| syscall_anomaly_threshold    | u32  | 1000    | Syscall anomaly threshold     |
| file_access_violation_mode   | u8   | 1       | File access violation mode    |
| network_suspicious_threshold | u32  | 100     | Network suspicious threshold  |

## CO-RE Support

This eBPF program uses CO-RE (Compile Once, Run Everywhere) with BTF type information:

- All structs use `#[repr(C, packed)]` for binary compatibility
- Field offsets verified at runtime using BTF
- Compatible with Linux 6.6 LTS and later

## Security Considerations

- All eBPF programs run with minimal privileges
- LSM hooks only monitor, do not enforce policies
- Ring buffer size limited to 1MB to prevent memory exhaustion
- Event validation in userspace prevents malformed data

## Troubleshooting

### eBPF Program Fails to Load

```bash
# Check BTF support
ls /sys/kernel/btf/vmlinux

# Check kernel version
uname -r

# Check eBPF verifier logs
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### Events Not Appearing

```bash
# Check ring buffer statistics
sudo bpftool prog show

# Check map statistics
sudo bpftool map show

# Check program attachment
sudo bpftool prog list
```

## Development

### Adding New Event Types

1. Define event struct in `src/events.rs`
2. Add event ID to `EventId` enum
3. Implement eBPF hook in `src/bpf/main.bpf.rs`
4. Add handler in `src/main.rs`
5. Update ring buffer size if needed

### Testing

```bash
# Run unit tests
cargo test

# Run integration tests (requires root)
sudo cargo test --test integration

# Check eBPF program with bpftool
sudo bpftool prog dump xlated name <program_name>
```

## References

- [Aya-rs Documentation](https://aya-rs.dev/)
- [BPF Type Format (BTF)](https://www.kernel.org/doc/html/latest/bpf/btf.html)
- [CO-RE (Compile Once, Run Everywhere)](https://nakryiko.com/posts/bpf-portability/)
- [Linux Kernel eBPF Documentation](https://www.kernel.org/doc/html/latest/bpf/index.html)

## License

Apache-2.0 OR MIT
