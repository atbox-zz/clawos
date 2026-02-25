# eBPF Aya-rs Implementation Summary

## Task Completion

**Task:** Implement eBPF Aya-rs program with P1.3 event struct hooks for kernel monitoring

**Status:** ✅ COMPLETED

**Date:** 2026-02-24

---

## Files Created

### 1. Cargo.toml
- **Path:** `domains/ebpf/Cargo.toml`
- **Dependencies:**
  - `aya = "0.13"` (with `build_bpf` feature)
  - `aya-log = "0.2"`
  - `tokio = "1"` (with full features)
  - `anyhow = "1"`
  - `thiserror = "1"`
  - `libc = "0.2"`
  - `bytes = "1"`
  - `aya-build = "0.1"` (build dependency)

### 2. Event Structures Module
- **Path:** `domains/ebpf/src/events.rs`
- **Content:**
  - All enums from P1.3 spec (EventType, SeverityCode, FileOperation, NetworkProtocol, NetworkDirection, CgroupMetricType)
  - All event structs (AnomalyEvent, SyscallTraceEvent, FileAccessEvent, NetworkEvent, CgroupEvent)
  - EventHeader and EventId discriminator
  - Helper methods for string conversion and enum parsing
  - Unit tests for size verification

### 3. Kernel Space eBPF Program
- **Path:** `domains/ebpf/src/bpf/main.bpf.rs`
- **Features:**
  - CO-RE support with BTF type information
  - Ring buffer for userspace communication (1MB)
  - Configuration map for runtime settings
  - Helper maps for tracking (SYSCALL_COUNTS, FILE_ACCESS_TRACKER, NETWORK_TRACKER, CGROUP_THRESHOLDS)

### 4. Tracepoint Hooks
- **execve enter/exit:** Monitor process execution
- **openat enter/exit:** Monitor file open operations
- **Syscall numbers:** 59 (execve), 257 (openat) for x86_64

### 5. LSM Hooks
- **file_open:** Monitor file access operations
  - Extracts inode, device_id, mode, path from kernel structures
  - Tracks permission results
- **socket_connect:** Monitor network connections
  - Supports IPv4 and IPv6
  - Extracts protocol, source/destination IP and port

### 6. Cgroup Hooks
- **cgroup_skb_ingress:** Monitor inbound network traffic
- **cgroup_skb_egress:** Monitor outbound network traffic
  - Extracts packet size and protocol
  - Maps protocol numbers to NetworkProtocol enum

### 7. Userspace Loader
- **Path:** `domains/ebpf/src/main.rs`
- **Features:**
  - Load and attach all eBPF programs
  - Configure programs via CONFIG map
  - Ring buffer receiver with event processing loop
  - Event handlers for all event types
  - Statistics reporting every 10 seconds
  - Graceful shutdown on Ctrl+C

### 8. Build Script
- **Path:** `domains/ebpf/build.rs`
- **Features:**
  - Compile eBPF programs with aya-build
  - Generate skeleton bindings
  - Apply compiler flags (-Wall, -Werror)

### 9. Supporting Files
- **domains/ebpf/src/lib.rs:** Library entry point
- **domains/ebpf/src/bpf/mod.rs:** BPF module declaration
- **domains/ebpf/src/bpf/main.rs:** Config struct for userspace
- **domains/ebpf/README.md:** Comprehensive documentation

---

## P1.3 Specification Compliance

### Event Structs
✅ All 5 event structs implemented with exact binary layout:
- AnomalyEvent: 1056 bytes
- SyscallTraceEvent: 104 bytes
- FileAccessEvent: 304 bytes
- NetworkEvent: 72 bytes
- CgroupEvent: 304 bytes

### Enums
✅ All enums implemented with correct values:
- EventType (7 variants)
- SeverityCode (5 variants)
- FileOperation (6 variants)
- NetworkProtocol (5 variants)
- NetworkDirection (3 variants)
- CgroupMetricType (8 variants)

### CO-RE Compatibility
✅ All structs use `#[repr(C, packed)]` for binary compatibility
✅ Fixed-size arrays for all string fields
✅ Proper alignment for all fields
✅ Version field in each event for future compatibility

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Userspace (Rust)                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   main.rs    │  │  events.rs   │  │  Config      │      │
│  │  (Loader)    │  │  (Structs)   │  │  (Settings)  │      │
│  └──────┬───────┘  └──────────────┘  └──────────────┘      │
│         │                                                     │
│         │ Ring Buffer (1MB)                                  │
│         │                                                     │
└─────────┼─────────────────────────────────────────────────────┘
          │
          │ eBPF System Calls
          │
┌─────────┼─────────────────────────────────────────────────────┐
│         │              Kernel Space (eBPF)                    │
│  ┌──────▼───────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ main.bpf.rs  │  │  events.rs   │  │  Maps        │      │
│  │ (eBPF Progs) │  │  (Structs)   │  │  (Storage)   │      │
│  └──────┬───────┘  └──────────────┘  └──────────────┘      │
│         │                                                     │
│  ┌──────▼──────────────────────────────────────────────┐    │
│  │                   Hooks                              │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │    │
│  │  │ Tracepoint  │  │     LSM     │  │   Cgroup    │ │    │
│  │  │  execve     │  │  file_open  │  │   skb_*     │ │    │
│  │  │  openat     │  │  socket_*   │  │             │ │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘ │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Features

### 1. Syscall Monitoring
- Trace execve syscalls (enter/exit)
- Trace openat syscalls (enter/exit)
- Capture syscall number, arguments, return value, duration
- Track process command name

### 2. File Access Monitoring
- LSM hook for file_open
- Extract file metadata (inode, device_id, mode, path)
- Track permission results (granted/denied)
- Monitor file operations

### 3. Network Monitoring
- LSM hook for socket_connect
- Cgroup hooks for skb ingress/egress
- Support IPv4 and IPv6
- Extract protocol, source/destination IP and port
- Track packet size

### 4. Cgroup Resource Monitoring
- Monitor network traffic per cgroup
- Track resource usage
- Alert on threshold exceeded

### 5. Ring Buffer Communication
- 1MB ring buffer for high-throughput event streaming
- Event ID discriminator for type identification
- Efficient binary format

### 6. Configuration
- Runtime configuration via CONFIG map
- Enable/disable monitoring features
- Configurable thresholds

---

## CO-RE Support

### Compile Once, Run Everywhere
- All structs use `#[repr(C, packed)]` for binary compatibility
- BTF type information for field offset verification
- Compatible with Linux 6.6 LTS and later

### Field Offset Verification
```rust
use aya::Btf;

fn verify_offsets() {
    let btf = Btf::from_sys_fs()?;
    assert_eq!(btf.field_offset("anomaly_event", "timestamp_ns")?, 4);
    assert_eq!(btf.field_offset("anomaly_event", "pid")?, 12);
}
```

---

## Security Considerations

1. **Minimal Privileges:** All eBPF programs run with minimal privileges
2. **Monitoring Only:** LSM hooks only monitor, do not enforce policies
3. **Memory Safety:** Ring buffer size limited to 1MB
4. **Event Validation:** Userspace validates all events
5. **No Dynamic Allocation:** All kernel-space structs use fixed-size arrays

---

## Testing

### Unit Tests
- Event struct size verification
- Enum conversion tests
- String parsing tests

### Integration Tests
- Load eBPF program
- Attach all hooks
- Generate test events
- Verify userspace parsing

---

## Build and Run

### Build
```bash
cargo build --release
```

### Run
```bash
sudo ./target/release/clawos-ebpf
```

### Verify
```bash
sudo bpftool prog show
sudo bpftool map show
```

---

## Next Steps

### Phase 2 Tasks (Not Implemented)
- XDP network filter (task B-04)
- Prometheus metrics integration (task B-06)

### Future Enhancements
- Add more syscall tracepoints
- Implement anomaly detection algorithms
- Add policy enforcement in LSM hooks
- Integrate with ClawFS for event storage
- Add real-time alerting

---

## References

- P1.3 Specification: `specs/p1/P1.3-ebpf-event-structs.md`
- Aya-rs Documentation: https://aya-rs.dev/
- BPF Type Format (BTF): https://www.kernel.org/doc/html/latest/bpf/btf.html
- CO-RE: https://nakryiko.com/posts/bpf-portability/

---

## License

Apache-2.0 OR MIT
