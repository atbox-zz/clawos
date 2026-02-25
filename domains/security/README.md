# ClawOS Security Library

Security primitives for ClawOS: seccomp-BPF filtering, namespace isolation, and AppArmor integration.

## Overview

This crate provides the security foundation for ClawOS, implementing:

- **seccomp-BPF filtering**: Kernel-level syscall filtering based on P1.2 whitelist schema
- **Error code mapping**: P1.7 IPC protocol error codes with seccomp errno mapping
- **Conditional rules**: Port restrictions and argument-based filtering
- **Tokio runtime support**: Special handling for async runtime syscalls

## Features

- Parse and validate P1.2 seccomp whitelist JSON schema
- Generate BPF filters from ALLOW/DENY/CONDITIONAL rules
- Implement conditional criteria (port restrictions, argument filters)
- Error handling mapping to P1.7 error codes (0=SUCCESS, 1=EAGAIN, etc.)
- Support tokio async runtime syscalls from P1.2
- Linux 6.6 LTS seccomp features compatibility

## Usage

### Basic Example

```rust
use clawos_security::{SeccompFilter, Whitelist, SyscallRule, Permission, SyscallCategory};

let whitelist = Whitelist {
    schema_version: "1.0.0".to_string(),
    whitelist_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
    created_at: "2026-02-24T00:00:00Z".to_string(),
    created_by: "Security Agent".to_string(),
    syscalls: vec![
        SyscallRule {
            name: "read".to_string(),
            permission: Permission::Allow,
            category: Some(SyscallCategory::FileIo),
            conditions: None,
            notes: None,
            verified_by_strace: Some(true),
            tokio_required: Some(false),
        },
    ],
    metadata: None,
    signature: None,
    updated_at: None,
    updated_by: None,
};

let mut filter = SeccompFilter::new(whitelist)?;
filter.apply()?;
```

### Loading from JSON

```rust
use clawos_security::SeccompFilter;

let mut filter = SeccompFilter::from_json("path/to/whitelist.json")?;
filter.apply()?;
```

### Conditional Rules with Port Restrictions

```rust
use clawos_security::{Condition, PortRestriction};

SyscallRule {
    name: "socket".to_string(),
    permission: Permission::Conditional,
    category: Some(SyscallCategory::Network),
    conditions: Some(Condition {
        port_restriction: Some(PortRestriction {
            allowed_ports: vec![5432],
            description: Some("PostgreSQL database port only".to_string()),
        }),
        argument_filter: None,
        description: "Socket creation allowed only for PostgreSQL connections".to_string(),
    }),
    notes: None,
    verified_by_strace: Some(true),
    tokio_required: Some(false),
}
```

### Argument Filtering

```rust
use clawos_security::{Condition, ArgumentFilter, CompareOperator};

SyscallRule {
    name: "openat".to_string(),
    permission: Permission::Conditional,
    category: Some(SyscallCategory::FileIo),
    conditions: Some(Condition {
        port_restriction: None,
        argument_filter: Some(ArgumentFilter {
            arg_index: 1,
            operator: CompareOperator::Eq,
            value: 0,
            mask: None,
        }),
        description: "Only allow O_RDONLY".to_string(),
    }),
    notes: None,
    verified_by_strace: Some(true),
    tokio_required: Some(false),
}
```

## Error Codes

The library uses P1.7 IPC protocol error codes:

| Code | Name | Description |
|------|------|-------------|
| 0 | SUCCESS | Operation completed successfully |
| 1 | EAGAIN | Operation would block |
| 2 | EIO | I/O error |
| 3 | ENOENT | Entity not found |
| 4 | EPERM | Permission denied |
| 5 | EPROTO | Protocol error |
| 6 | ETIMEOUT | Operation timeout |
| 7 | EINTERNAL | Internal error |
| 8 | EPANIC | Unrecoverable error |

## Testing

Run tests with:

```bash
cargo test
```

Run the example:

```bash
cargo run --example seccomp_filter
```

## Dependencies

- `libseccomp` 2.5+ - seccomp-BPF bindings
- `serde` 1.0 - JSON serialization
- `serde_json` 1.0 - JSON parsing
- `thiserror` 1.0 - Error handling
- `log` 0.4 - Logging

## Security Considerations

- All whitelists must be created by the Security Agent
- seccomp filters are applied per-process and cannot be removed
- Default action is `SCMP_ACT_KILL_PROCESS` for security
- Conditional rules must have explicit conditions defined
- Port restrictions apply to socket/connect syscalls

## License

Apache-2.0 OR MIT

## References

- P1.2: seccomp syscall whitelist schema
- P1.7: IPC protocol error codes
- SKILLS.md: libseccomp version 2.5+ requirement
