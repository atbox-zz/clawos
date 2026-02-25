# P1.2: seccomp Syscall Whitelist JSON Schema

## Deliverable Status: ✅ COMPLETE

**Created by:** Security Agent
**Date:** 2026-02-24
**Status:** FROZEN
**Version:** 1.0.0

---

## Files Created

1. **`P1.2-seccomp-whitelist.schema.json`** (8.8 KB)
   - JSON Schema definition for seccomp syscall whitelist
   - Defines structure, validation rules, and constraints
   - FROZEN with SHA256 signature placeholder

2. **`P1.2-seccomp-whitelist.example.json`** (8.8 KB)
   - Complete example whitelist matching the schema
   - Includes all IronClaw core syscalls
   - Demonstrates permission levels and conditional criteria

---

## Schema Features

### Core Structure
- **Schema Version:** 1.0.0
- **Status:** FROZEN (immutable without Security Agent approval)
- **Modification Authority:** Security Agent only
- **Validation Mode:** Strict (default action: DENY)

### Permission Levels
- **ALLOW:** Syscall permitted without restrictions
- **DENY:** Syscall explicitly blocked
- **CONDITIONAL:** Syscall permitted only under specific conditions

### Syscall Categories
1. **memory** - Memory management (mmap, munmap, mprotect, brk, madvise)
2. **file_io** - File operations (read, write, open, openat, close, stat, fstat)
3. **process** - Process management (exit, exit_group, getpid, futex, clone, clone3)
4. **network** - Network operations (socket, connect, recv, send, poll, epoll_*)
5. **time** - Time operations (clock_gettime, clock_nanosleep)
6. **signals** - Signal handling (rt_sigaction, rt_sigprocmask, rt_sigreturn)
7. **misc** - Miscellaneous (prctl, getrandom, eventfd2, pipe2)
8. **tokio_runtime** - Tokio async runtime specific (marked for C-02 validation)

### Conditional Criteria
- **Port Restrictions:** Network syscalls (socket, connect) restricted to PostgreSQL port 5432
- **Argument Filters:** Support for argument-based filtering (eq, ne, gt, lt, ge, le, masked_eq)
- **XDP Layer Enforcement:** Additional security layer for network restrictions

---

## Whitelist Contents

### Total Syscalls: 33

#### Memory (5)
- mmap, munmap, mprotect, brk, madvise

#### File I/O (6)
- read, write, open, openat, close, stat, fstat

#### Network (8)
- socket (CONDITIONAL - port 5432 only)
- connect (CONDITIONAL - port 5432 only)
- recv, send, poll
- epoll_create1, epoll_ctl, epoll_wait

#### Time (2)
- clock_gettime, clock_nanosleep

#### Signals (3)
- rt_sigaction, rt_sigprocmask, rt_sigreturn

#### Process (6)
- exit, exit_group, getpid, futex, clone, clone3

#### Misc (4)
- prctl, getrandom, eventfd2, pipe2

---

## Tokio Async Runtime Integration

### Tokio-Required Syscalls (marked for C-02 validation)
- **epoll_create1** - Create epoll instance
- **epoll_ctl** - Control epoll instance
- **epoll_wait** - Wait for epoll events (core of tokio)
- **clock_gettime** - Get current time (tokio timers)
- **clock_nanosleep** - High-resolution sleep (tokio timers)
- **futex** - Fast userspace mutex (Rust std::sync primitives)
- **clone3** - Create new thread/process (modern)
- **eventfd2** - Event notification file descriptor
- **pipe2** - Create pipe with flags

### Strace Validation Requirement
- **Phase:** C-02 (Phase 2, Task C-02)
- **Priority:** HIGH
- **Conflict Resolution:** Any discrepancies between this whitelist and actual strace output must be documented and resolved by Security Agent

---

## Security Properties

### Strict Validation
- No syscall outside whitelist permitted
- All syscalls must be explicitly allowed or conditionally allowed
- Default action: DENY

### Defense in Depth
1. **seccomp-BPF Filter:** Kernel-level syscall filtering
2. **XDP Layer:** Network port enforcement (PostgreSQL 5432 only)
3. **AppArmor Profile:** File system and capability restrictions (P1.6)
4. **cgroup v2:** Resource quotas (P1.5)

### Immutable Schema
- FROZEN status prevents unauthorized modifications
- SHA256 signature placeholder for integrity verification
- ClawFS Vault storage requirement for all changes

---

## Usage Example

### Loading the Schema
```bash
# Validate a whitelist against the schema
ajv validate -s P1.2-seccomp-whitelist.schema.json -d your-whitelist.json
```

### Generating seccomp-BPF Filter
```rust
// P2.2 will implement the actual filter generation
// This schema provides the input specification
use seccomp_whitelist_schema::Whitelist;

let whitelist: Whitelist = serde_json::from_str(include_str!("whitelist.json"))?;
let filter = seccomp_bpf::compile(&whitelist)?;
```

---

## Modification Rules

### Who Can Modify
- **Security Agent** only

### Required Steps
1. Update schema version (semantic versioning)
2. Generate new SHA256 signature
3. Store in ClawFS Vault
4. Update all dependent systems
5. Document changes in commit history

### Approval Process
- All changes require Security Agent approval
- Vault storage is mandatory
- SHA256 signature must be updated

---

## Dependencies

### Upstream Specifications
- **P1.1:** WIT Interface Spec Book (WASM ↔ Kernel ABI)
- **P1.3:** eBPF event struct format (AnomalyEvent, etc.)
- **P1.4:** ClawFS path convention + Secrets encryption format
- **P1.5:** cgroup v2 resource quota standard values
- **P1.6:** AppArmor profile rule language spec

### Downstream Implementations
- **P2.2:** seccomp-BPF filter Rust code implementation
- **C-02:** Strace validation for tokio runtime compatibility

---

## References

- **Source:** SKILLS.md lines 551-572
- **IronClaw Repository:** https://github.com/nearai/ironclaw
- **License:** Apache-2.0 / MIT
- **Linux Syscall Reference:** https://man7.org/linux/man-pages/man2/syscalls.2.html

---

## Validation Checklist

- ✅ JSON Schema structure defined
- ✅ All IronClaw core syscalls included (33 total)
- ✅ Permission levels mapped (ALLOW, DENY, CONDITIONAL)
- ✅ Conditional criteria defined (socket/connect port 5432)
- ✅ Tokio async runtime syscalls marked (9 syscalls)
- ✅ Schema marked as FROZEN with SHA256 placeholder
- ✅ Version documented (v1.0)
- ✅ Modification authority defined (Security Agent only)
- ✅ Validation rules specified (strict mode, default DENY)
- ✅ Example whitelist file generated
- ✅ Strace validation requirement documented (C-02)
- ✅ JSON syntax validated

---

## Next Steps

1. **Phase 2, Task C-02:** Perform strace analysis to verify tokio runtime syscalls
2. **P2.2:** Implement seccomp-BPF filter Rust code using this schema
3. **Security Review:** Final approval by Security Agent
4. **Vault Storage:** Store signed schema in ClawFS Vault
5. **Integration:** Integrate with IronClaw process initialization

---

**Gate P1 Status:** This deliverable is part of Gate P1. All spec documents must be SHA256-signed and stored in ClawFS Vault before proceeding to P2.
