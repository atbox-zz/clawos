use clawos_security::{SeccompFilter, Whitelist, SyscallRule, Permission, SyscallCategory, Condition, PortRestriction};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("ClawOS seccomp-BPF Filter Example");
    println!("===================================\n");

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
                notes: Some("Basic file read operation".to_string()),
                verified_by_strace: Some(true),
                tokio_required: Some(false),
            },
            SyscallRule {
                name: "write".to_string(),
                permission: Permission::Allow,
                category: Some(SyscallCategory::FileIo),
                conditions: None,
                notes: Some("Basic file write operation".to_string()),
                verified_by_strace: Some(true),
                tokio_required: Some(false),
            },
            SyscallRule {
                name: "mmap".to_string(),
                permission: Permission::Allow,
                category: Some(SyscallCategory::Memory),
                conditions: None,
                notes: Some("Memory mapping for Rust allocator".to_string()),
                verified_by_strace: Some(true),
                tokio_required: Some(false),
            },
            SyscallRule {
                name: "munmap".to_string(),
                permission: Permission::Allow,
                category: Some(SyscallCategory::Memory),
                conditions: None,
                notes: Some("Memory unmapping".to_string()),
                verified_by_strace: Some(true),
                tokio_required: Some(false),
            },
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
                    description: "Socket creation allowed only for PostgreSQL connections (port 5432)".to_string(),
                }),
                notes: Some("Network socket with port restriction".to_string()),
                verified_by_strace: Some(true),
                tokio_required: Some(false),
            },
            SyscallRule {
                name: "epoll_wait".to_string(),
                permission: Permission::Allow,
                category: Some(SyscallCategory::TokioRuntime),
                conditions: None,
                notes: Some("Tokio async runtime event polling".to_string()),
                verified_by_strace: Some(true),
                tokio_required: Some(true),
            },
            SyscallRule {
                name: "epoll_ctl".to_string(),
                permission: Permission::Allow,
                category: Some(SyscallCategory::TokioRuntime),
                conditions: None,
                notes: Some("Tokio async runtime event control".to_string()),
                verified_by_strace: Some(true),
                tokio_required: Some(true),
            },
        ],
        metadata: None,
        signature: None,
        updated_at: None,
        updated_by: None,
    };

    println!("Whitelist ID: {}", whitelist.whitelist_id);
    println!("Schema Version: {}", whitelist.schema_version);
    println!("Total Syscalls: {}\n", whitelist.syscalls.len());

    let tokio_syscalls = whitelist.get_tokio_syscalls();
    println!("Tokio Runtime Syscalls ({}):", tokio_syscalls.len());
    for syscall in tokio_syscalls {
        println!("  - {}", syscall.name);
    }
    println!();

    println!("Creating seccomp filter...");
    let mut filter = SeccompFilter::new(whitelist)?;
    println!("Filter created successfully!\n");

    println!("Syscall Rules:");
    for rule in filter.get_whitelist().syscalls {
        println!("  [{}] {} - {:?}", 
            match rule.permission {
                Permission::Allow => "ALLOW",
                Permission::Deny => "DENY",
                Permission::Conditional => "COND",
            },
            rule.name,
            rule.category
        );
    }
    println!();

    println!("Note: To actually apply the filter, call filter.apply()");
    println!("This will load the BPF program into the kernel.");
    println!("WARNING: Once applied, the filter cannot be removed for this process!");

    Ok(())
}
