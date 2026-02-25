// AppArmor Profile Generator for ClawOS
//
// This module implements the AppArmor profile rule language specification from P1.6,
// providing tools to generate, validate, and manage AppArmor profiles for all ClawOS
// components.
//
// Security Hierarchy (from P1.6 Section 2.1):
//   Layer 1: eBPF LSM (real-time anomaly detection, custom hooks, XDP filtering)
//   Layer 2: AppArmor (MAC, file confinement, capability restriction, network allowlist)
//   Layer 3: DAC (traditional Unix permissions)
//
// Each layer has veto power - if any layer denies, the operation is blocked.

use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// AppArmor profile security levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Strict isolation - minimal permissions, no capabilities
    Strict,
    /// Moderate restrictions - necessary capabilities granted
    Moderate,
    /// Permissive - for testing only
    Permissive,
}

impl fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityLevel::Strict => write!(f, "STRICT"),
            SecurityLevel::Moderate => write!(f, "MODERATE"),
            SecurityLevel::Permissive => write!(f, "PERMISSIVE"),
        }
    }
}

/// File permissions in AppArmor syntax
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FilePermission {
    /// Read
    Read,
    /// Write
    Write,
    /// Append
    Append,
    /// Create hard links
    Link,
    /// Lock
    Lock,
    /// Memory map (mmap)
    Mmap,
    /// Execute
    Execute,
    /// Inherit execute (execute in current profile)
    InheritExecute,
    /// Unconfined execute
    UnconfinedExecute,
    /// Unconfined execute with cleanup
    UnconfinedExecuteCleanup,
    /// Discrete profile execute
    DiscreteProfileExecute,
    /// Discrete profile execute with cleanup
    DiscreteProfileExecuteCleanup,
    /// Child profile execute
    ChildProfileExecute,
    /// Child profile execute with cleanup
    ChildProfileExecuteCleanup,
}

impl FilePermission {
    /// Convert to AppArmor syntax
    pub fn to_syntax(&self) -> &'static str {
        match self {
            FilePermission::Read => "r",
            FilePermission::Write => "w",
            FilePermission::Append => "a",
            FilePermission::Link => "l",
            FilePermission::Lock => "k",
            FilePermission::Mmap => "m",
            FilePermission::Execute => "x",
            FilePermission::InheritExecute => "ix",
            FilePermission::UnconfinedExecute => "Ux",
            FilePermission::UnconfinedExecuteCleanup => "ux",
            FilePermission::DiscreteProfileExecute => "Px",
            FilePermission::DiscreteProfileExecuteCleanup => "px",
            FilePermission::ChildProfileExecute => "Cx",
            FilePermission::ChildProfileExecuteCleanup => "cx",
        }
    }

    /// Parse from AppArmor syntax
    pub fn from_syntax(s: &str) -> Result<Self> {
        match s {
            "r" => Ok(FilePermission::Read),
            "w" => Ok(FilePermission::Write),
            "a" => Ok(FilePermission::Append),
            "l" => Ok(FilePermission::Link),
            "k" => Ok(FilePermission::Lock),
            "m" => Ok(FilePermission::Mmap),
            "x" => Ok(FilePermission::Execute),
            "ix" => Ok(FilePermission::InheritExecute),
            "Ux" => Ok(FilePermission::UnconfinedExecute),
            "ux" => Ok(FilePermission::UnconfinedExecuteCleanup),
            "Px" => Ok(FilePermission::DiscreteProfileExecute),
            "px" => Ok(FilePermission::DiscreteProfileExecuteCleanup),
            "Cx" => Ok(FilePermission::ChildProfileExecute),
            "cx" => Ok(FilePermission::ChildProfileExecuteCleanup),
            _ => anyhow::bail!("Invalid file permission: {}", s),
        }
    }
}

/// Network family types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkFamily {
    Unix,
    Inet,
    Inet6,
    Packet,
    Netlink,
    Ax25,
    Ipx,
    Netrom,
    Atmpvc,
    X25,
    Rose,
    Decnet,
    Netbeui,
    Security,
    Key,
    Ash,
    Econet,
    Atmsvc,
    Rds,
    Sna,
    Irida,
    Pppox,
    Wanpipe,
    Llc,
    Ib,
    Mpls,
    Can,
    Tipc,
    Bluetooth,
    Iucv,
    Rxrpc,
    Kcm,
    Qipcrtr,
    Smc,
    Xdp,
}

impl NetworkFamily {
    pub fn to_syntax(&self) -> &'static str {
        match self {
            NetworkFamily::Unix => "unix",
            NetworkFamily::Inet => "inet",
            NetworkFamily::Inet6 => "inet6",
            NetworkFamily::Packet => "packet",
            NetworkFamily::Netlink => "netlink",
            NetworkFamily::Ax25 => "ax25",
            NetworkFamily::Ipx => "ipx",
            NetworkFamily::Netrom => "netrom",
            NetworkFamily::Atmpvc => "atmpvc",
            NetworkFamily::X25 => "x25",
            NetworkFamily::Rose => "rose",
            NetworkFamily::Decnet => "decnet",
            NetworkFamily::Netbeui => "netbeui",
            NetworkFamily::Security => "security",
            NetworkFamily::Key => "key",
            NetworkFamily::Ash => "ash",
            NetworkFamily::Econet => "econet",
            NetworkFamily::Atmsvc => "atmsvc",
            NetworkFamily::Rds => "rds",
            NetworkFamily::Sna => "sna",
            NetworkFamily::Irida => "irda",
            NetworkFamily::Pppox => "pppox",
            NetworkFamily::Wanpipe => "wanpipe",
            NetworkFamily::Llc => "llc",
            NetworkFamily::Ib => "ib",
            NetworkFamily::Mpls => "mpls",
            NetworkFamily::Can => "can",
            NetworkFamily::Tipc => "tipc",
            NetworkFamily::Bluetooth => "bluetooth",
            NetworkFamily::Iucv => "iucv",
            NetworkFamily::Rxrpc => "rxrpc",
            NetworkFamily::Kcm => "kcm",
            NetworkFamily::Qipcrtr => "qipcrtr",
            NetworkFamily::Smc => "smc",
            NetworkFamily::Xdp => "xdp",
        }
    }
}

/// Network socket types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkType {
    Stream,
    Dgram,
    Seqpacket,
    Rdm,
    Raw,
}

impl NetworkType {
    pub fn to_syntax(&self) -> &'static str {
        match self {
            NetworkType::Stream => "stream",
            NetworkType::Dgram => "dgram",
            NetworkType::Seqpacket => "seqpacket",
            NetworkType::Rdm => "rdm",
            NetworkType::Raw => "raw",
        }
    }
}

/// Network protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Ip,
    Ipv6,
}

impl NetworkProtocol {
    pub fn to_syntax(&self) -> &'static str {
        match self {
            NetworkProtocol::Tcp => "tcp",
            NetworkProtocol::Udp => "udp",
            NetworkProtocol::Icmp => "icmp",
            NetworkProtocol::Icmpv6 => "icmpv6",
            NetworkProtocol::Ip => "ip",
            NetworkProtocol::Ipv6 => "ipv6",
        }
    }
}

/// Linux capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    Chown,
    DacOverride,
    DacReadSearch,
    Fowner,
    Fsetid,
    Kill,
    Setgid,
    Setuid,
    Setpcap,
    LinuxImmutable,
    NetBindService,
    NetBroadcast,
    NetAdmin,
    NetRaw,
    IpcLock,
    IpcOwner,
    SysModule,
    SysRawio,
    SysChroot,
    SysPtrace,
    SysPacct,
    SysAdmin,
    SysBoot,
    SysNice,
    SysResource,
    SysTime,
    SysTtyConfig,
    Mknod,
    Lease,
    AuditWrite,
    AuditControl,
    Setfcap,
    MacOverride,
    MacAdmin,
    Syslog,
    WakeAlarm,
    BlockSuspend,
    AuditRead,
    Perfmon,
    Bpf,
    CheckpointRestore,
}

impl Capability {
    pub fn to_syntax(&self) -> &'static str {
        match self {
            Capability::Chown => "chown",
            Capability::DacOverride => "dac_override",
            Capability::DacReadSearch => "dac_read_search",
            Capability::Fowner => "fowner",
            Capability::Fsetid => "fsetid",
            Capability::Kill => "kill",
            Capability::Setgid => "setgid",
            Capability::Setuid => "setuid",
            Capability::Setpcap => "setpcap",
            Capability::LinuxImmutable => "linux_immutable",
            Capability::NetBindService => "net_bind_service",
            Capability::NetBroadcast => "net_broadcast",
            Capability::NetAdmin => "net_admin",
            Capability::NetRaw => "net_raw",
            Capability::IpcLock => "ipc_lock",
            Capability::IpcOwner => "ipc_owner",
            Capability::SysModule => "sys_module",
            Capability::SysRawio => "sys_rawio",
            Capability::SysChroot => "sys_chroot",
            Capability::SysPtrace => "sys_ptrace",
            Capability::SysPacct => "sys_pacct",
            Capability::SysAdmin => "sys_admin",
            Capability::SysBoot => "sys_boot",
            Capability::SysNice => "sys_nice",
            Capability::SysResource => "sys_resource",
            Capability::SysTime => "sys_time",
            Capability::SysTtyConfig => "sys_tty_config",
            Capability::Mknod => "mknod",
            Capability::Lease => "lease",
            Capability::AuditWrite => "audit_write",
            Capability::AuditControl => "audit_control",
            Capability::Setfcap => "setfcap",
            Capability::MacOverride => "mac_override",
            Capability::MacAdmin => "mac_admin",
            Capability::Syslog => "syslog",
            Capability::WakeAlarm => "wake_alarm",
            Capability::BlockSuspend => "block_suspend",
            Capability::AuditRead => "audit_read",
            Capability::Perfmon => "perfmon",
            Capability::Bpf => "bpf",
            Capability::CheckpointRestore => "checkpoint_restore",
        }
    }
}

/// AppArmor rule types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AppArmorRule {
    /// Capability rule: capability <name>
    Capability {
        capabilities: Vec<Capability>,
        deny: bool,
    },
    /// File rule: <path> <permissions>
    File {
        path: String,
        permissions: HashSet<FilePermission>,
        deny: bool,
    },
    /// Network rule: network <family> <type> <protocol> [to <address> [port <port>]]
    Network {
        family: NetworkFamily,
        socket_type: Option<NetworkType>,
        protocol: Option<NetworkProtocol>,
        address: Option<String>,
        port: Option<u16>,
        deny: bool,
    },
    /// Mount rule: mount <options> <fstype> <source> -> <target>
    Mount {
        options: Vec<String>,
        fstype: Option<String>,
        source: String,
        target: String,
        deny: bool,
    },
    /// Ptrace rule: ptrace <access> peer=<profile>
    Ptrace {
        access: Vec<String>,
        peer: Option<String>,
        deny: bool,
    },
    /// Signal rule: signal <set> peer=<profile>
    Signal {
        signal_set: Vec<String>,
        peer: Option<String>,
        deny: bool,
    },
    /// Change profile rule: change_profile -> <target>
    ChangeProfile {
        target: String,
    },
    /// Include directive: #include <path>
    Include {
        path: String,
    },
    /// Comment
    Comment {
        text: String,
    },
}

impl AppArmorRule {
    /// Convert rule to AppArmor syntax
    pub fn to_syntax(&self) -> String {
        match self {
            AppArmorRule::Capability { capabilities, deny } => {
                let prefix = if *deny { "deny " } else { "" };
                if capabilities.len() == 1 {
                    format!("{}capability {},", prefix, capabilities[0].to_syntax())
                } else {
                    let caps: Vec<&str> = capabilities.iter().map(|c| c.to_syntax()).collect();
                    format!("{}capability {{{}}},", prefix, caps.join(", "))
                }
            }
            AppArmorRule::File { path, permissions, deny } => {
                let prefix = if *deny { "deny " } else { "" };
                let perms: Vec<&str> = permissions.iter().map(|p| p.to_syntax()).collect();
                format!("{}{} {},", prefix, path, perms.join(""))
            }
            AppArmorRule::Network { family, socket_type, protocol, address, port, deny } => {
                let prefix = if *deny { "deny " } else { "" };
                let mut parts = vec![prefix.to_string(), "network".to_string(), family.to_syntax().to_string()];
                
                if let Some(st) = socket_type {
                    parts.push(st.to_syntax().to_string());
                }
                if let Some(proto) = protocol {
                    parts.push(proto.to_syntax().to_string());
                }
                if let Some(addr) = address {
                    parts.push("to".to_string());
                    parts.push(addr.clone());
                }
                if let Some(p) = port {
                    parts.push("port".to_string());
                    parts.push(p.to_string());
                }
                
                format!("{},", parts.join(" "))
            }
            AppArmorRule::Mount { options, fstype, source, target, deny } => {
                let prefix = if *deny { "deny " } else { "" };
                let opts = if options.is_empty() {
                    String::new()
                } else {
                    format!("options=({})", options.join(","))
                };
                let fs = fstype.as_ref().map(|f| format!(" {}", f)).unwrap_or_default();
                format!("{}mount {} {} {} -> {},", prefix, opts, fs, source, target)
            }
            AppArmorRule::Ptrace { access, peer, deny } => {
                let prefix = if *deny { "deny " } else { "" };
                let access_str = if access.is_empty() {
                    String::new()
                } else {
                    format!("({})", access.join(","))
                };
                let peer_str = peer.as_ref().map(|p| format!(" peer={}", p)).unwrap_or_default();
                format!("{}ptrace {}{},", prefix, access_str, peer_str)
            }
            AppArmorRule::Signal { signal_set, peer, deny } => {
                let prefix = if *deny { "deny " } else { "" };
                let set_str = if signal_set.is_empty() {
                    String::new()
                } else {
                    format!("({})", signal_set.join(","))
                };
                let peer_str = peer.as_ref().map(|p| format!(" peer={}", p)).unwrap_or_default();
                format!("{}signal {}{},", prefix, set_str, peer_str)
            }
            AppArmorRule::ChangeProfile { target } => {
                format!("change_profile -> {},", target)
            }
            AppArmorRule::Include { path } => {
                format!("#include <{}>", path)
            }
            AppArmorRule::Comment { text } => {
                format!("# {}", text)
            }
        }
    }
}

/// AppArmor profile configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppArmorProfile {
    /// Profile name
    pub name: String,
    /// Security level
    pub security_level: SecurityLevel,
    /// Profile flags
    pub flags: Vec<String>,
    /// Profile rules
    pub rules: Vec<AppArmorRule>,
    /// Profile includes
    pub includes: Vec<String>,
    /// Owner (Security Agent)
    pub owner: String,
    /// Status (FROZEN, DRAFT, etc.)
    pub status: String,
}

impl AppArmorProfile {
    /// Create a new AppArmor profile
    pub fn new(name: String, security_level: SecurityLevel) -> Self {
        AppArmorProfile {
            name,
            security_level,
            flags: vec!["attach_disconnected".to_string()],
            rules: Vec::new(),
            includes: vec![
                "tunables/global".to_string(),
                "abstractions/base".to_string(),
            ],
            owner: "Security Agent".to_string(),
            status: "FROZEN".to_string(),
        }
    }

    /// Add a rule to the profile
    pub fn add_rule(&mut self, rule: AppArmorRule) {
        self.rules.push(rule);
    }

    /// Add multiple rules to the profile
    pub fn add_rules(&mut self, rules: Vec<AppArmorRule>) {
        self.rules.extend(rules);
    }

    /// Add an include directive
    pub fn add_include(&mut self, path: String) {
        self.includes.push(path);
    }

    /// Generate the AppArmor profile syntax
    pub fn generate(&self) -> String {
        let mut output = String::new();

        // Header comment
        output.push_str(&format!("# {} AppArmor Profile\n", self.name));
        output.push_str(&format!("# Security Level: {}\n", self.security_level));
        output.push_str(&format!("# Owner: {}\n", self.owner));
        output.push_str(&format!("# Status: {}\n", self.status));
        output.push_str("\n");

        // Includes
        for include in &self.includes {
            output.push_str(&format!("#include <{}>\n", include));
        }
        output.push_str("\n");

        // Profile declaration
        let flags_str = if self.flags.is_empty() {
            String::new()
        } else {
            format!(" flags=({})", self.flags.join(","))
        };
        output.push_str(&format!("profile {}{} {{\n", self.name, flags_str));

        // Rules
        for rule in &self.rules {
            let rule_syntax = rule.to_syntax();
            // Indent rules
            for line in rule_syntax.lines() {
                output.push_str(&format!("  {}\n", line));
            }
        }

        // Footer
        output.push_str("}\n");

        output
    }

    /// Validate the profile against EBNF grammar rules
    pub fn validate(&self) -> Result<()> {
        // Validate profile name
        let name_regex = Regex::new(r"^[a-zA-Z][a-zA-Z0-9_-]*$")?;
        if !name_regex.is_match(&self.name) {
            anyhow::bail!("Invalid profile name: {}", self.name);
        }

        // Validate each rule
        for rule in &self.rules {
            self.validate_rule(rule)?;
        }

        Ok(())
    }

    /// Validate a single rule
    fn validate_rule(&self, rule: &AppArmorRule) -> Result<()> {
        match rule {
            AppArmorRule::File { path, .. } => {
                // Validate path syntax
                if !path.starts_with('/') {
                    anyhow::bail!("File path must be absolute: {}", path);
                }
                // Check for valid path patterns
                let path_regex = Regex::new(r"^/[\w\-./\*\[\]\?\{\}]*$")?;
                if !path_regex.is_match(path) {
                    anyhow::bail!("Invalid file path pattern: {}", path);
                }
            }
            AppArmorRule::Network { address, port, .. } => {
                // Validate address format if present
                if let Some(addr) = address {
                    let ip_regex = Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")?;
                    let ipv6_regex = Regex::new(r"^::1$|^[0-9a-fA-F:]+$")?;
                    if !ip_regex.is_match(addr) && !ipv6_regex.is_match(addr) {
                        anyhow::bail!("Invalid network address: {}", addr);
                    }
                }
                // Validate port range
                if let Some(p) = port {
                    if *p == 0 || *p > 65535 {
                        anyhow::bail!("Invalid port number: {}", p);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// AppArmor profile generator for ClawOS components
pub struct AppArmorGenerator {
    /// PostgreSQL allowlist (TCP:5432 only)
    postgresql_allowlist: HashSet<(String, u16)>,
}

impl AppArmorGenerator {
    /// Create a new AppArmor generator
    pub fn new() -> Self {
        let mut postgresql_allowlist = HashSet::new();
        postgresql_allowlist.insert(("127.0.0.1".to_string(), 5432));
        postgresql_allowlist.insert(("::1".to_string(), 5432));

        AppArmorGenerator {
            postgresql_allowlist,
        }
    }

    /// Generate profile for clawos-agent-loop
    pub fn generate_agent_loop_profile(&self) -> AppArmorProfile {
        let mut profile = AppArmorProfile::new("clawos-agent-loop".to_string(), SecurityLevel::Moderate);
        
        // Add additional includes
        profile.add_include("abstractions/nameservice".to_string());
        profile.add_include("abstractions/openssl".to_string());
        profile.add_include("abstractions/perl".to_string());

        // Add header comment
        profile.add_rule(AppArmorRule::Comment {
            text: "Capability grants (minimum required principle)".to_string(),
        });

        // Capability grants
        profile.add_rule(AppArmorRule::Capability {
            capabilities: vec![Capability::NetBindService],
            deny: false,
        });
        profile.add_rule(AppArmorRule::Comment {
            text: "Load eBPF programs for monitoring".to_string(),
        });
        profile.add_rule(AppArmorRule::Capability {
            capabilities: vec![Capability::Bpf],
            deny: false,
        });
        profile.add_rule(AppArmorRule::Capability {
            capabilities: vec![Capability::DacReadSearch],
            deny: false,
        });
        profile.add_rule(AppArmorRule::Comment {
            text: "Override DAC for specific operations (MINIMAL)".to_string(),
        });
        profile.add_rule(AppArmorRule::Capability {
            capabilities: vec![Capability::DacOverride],
            deny: false,
        });

        // PostgreSQL network access (monitored by XDP)
        profile.add_rule(AppArmorRule::Comment {
            text: "PostgreSQL network access (monitored by XDP)".to_string(),
        });
        profile.add_rule(AppArmorRule::Network {
            family: NetworkFamily::Inet,
            socket_type: Some(NetworkType::Stream),
            protocol: Some(NetworkProtocol::Tcp),
            address: Some("127.0.0.1".to_string()),
            port: Some(5432),
            deny: false,
        });
        profile.add_rule(AppArmorRule::Network {
            family: NetworkFamily::Inet6,
            socket_type: Some(NetworkType::Stream),
            protocol: Some(NetworkProtocol::Tcp),
            address: Some("::1".to_string()),
            port: Some(5432),
            deny: false,
        });

        // Deny all other network access
        profile.add_rule(AppArmorRule::Comment {
            text: "Deny all other network access".to_string(),
        });
        profile.add_rule(AppArmorRule::Network {
            family: NetworkFamily::Inet,
            socket_type: Some(NetworkType::Stream),
            protocol: None,
            address: None,
            port: None,
            deny: true,
        });
        profile.add_rule(AppArmorRule::Network {
            family: NetworkFamily::Inet6,
            socket_type: Some(NetworkType::Stream),
            protocol: None,
            address: None,
            port: None,
            deny: true,
        });
        profile.add_rule(AppArmorRule::Network {
            family: NetworkFamily::Inet,
            socket_type: Some(NetworkType::Dgram),
            protocol: None,
            address: None,
            port: None,
            deny: true,
        });
        profile.add_rule(AppArmorRule::Network {
            family: NetworkFamily::Inet6,
            socket_type: Some(NetworkType::Dgram),
            protocol: None,
            address: None,
            port: None,
            deny: true,
        });
        profile.add_rule(AppArmorRule::Network {
            family: NetworkFamily::Inet,
            socket_type: Some(NetworkType::Raw),
            protocol: None,
            address: None,
            port: None,
            deny: true,
        });
        profile.add_rule(AppArmorRule::Network {
            family: NetworkFamily::Inet6,
            socket_type: Some(NetworkType::Raw),
            protocol: None,
            address: None,
            port: None,
            deny: true,
        });

        // File access - ClawFS workspace
        profile.add_rule(AppArmorRule::Comment {
            text: "File access - ClawFS workspace".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/var/lib/clawos/workspace/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/var/lib/clawos/workspace/**/".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });

        // File access - Configuration
        profile.add_rule(AppArmorRule::Comment {
            text: "File access - Configuration".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/clawos/**".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/clawos/config.json".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });

        // File access - Logs
        profile.add_rule(AppArmorRule::Comment {
            text: "File access - Logs".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/var/log/clawos/agent-loop.log".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/var/log/clawos/agent-loop.log*".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });

        // File access - Runtime
        profile.add_rule(AppArmorRule::Comment {
            text: "File access - Runtime".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/run/clawos/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/run/clawos/agent-loop.sock".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });

        // File access - Temporary files
        profile.add_rule(AppArmorRule::Comment {
            text: "File access - Temporary files".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/tmp/clawos-agent-loop/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "owner /tmp/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });

        // File access - System libraries
        profile.add_rule(AppArmorRule::Comment {
            text: "File access - System libraries".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/usr/lib/**".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/usr/lib64/**".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/lib/**".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/lib64/**".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });

        // File access - Executables
        profile.add_rule(AppArmorRule::Comment {
            text: "File access - Executables".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/usr/bin/**".to_string(),
            permissions: [FilePermission::InheritExecute].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/bin/**".to_string(),
            permissions: [FilePermission::InheritExecute].iter().cloned().collect(),
            deny: false,
        });

        // Deny sensitive file modifications
        profile.add_rule(AppArmorRule::Comment {
            text: "Deny sensitive file modifications".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/passwd".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/shadow".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/group".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/gshadow".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/sudoers".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/ssh/**".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });

        // Deny kernel module operations
        profile.add_rule(AppArmorRule::Comment {
            text: "Deny kernel module operations".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/sys/module/**".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/proc/sys/**".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });

        // Deny device access (except through eBPF)
        profile.add_rule(AppArmorRule::Comment {
            text: "Deny device access (except through eBPF)".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/dev/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });

        // Signal permissions
        profile.add_rule(AppArmorRule::Comment {
            text: "Signal permissions".to_string(),
        });
        profile.add_rule(AppArmorRule::Signal {
            signal_set: vec!["receive".to_string()],
            peer: Some("clawos-wasm-daemon".to_string()),
            deny: false,
        });
        profile.add_rule(AppArmorRule::Signal {
            signal_set: vec!["receive".to_string()],
            peer: Some("clawos-kernel-svc".to_string()),
            deny: false,
        });

        // Change profile for subprocesses
        profile.add_rule(AppArmorRule::Comment {
            text: "Change profile for subprocesses".to_string(),
        });
        profile.add_rule(AppArmorRule::ChangeProfile {
            target: "clawos-wasm-daemon".to_string(),
        });

        // Ptrace restrictions
        profile.add_rule(AppArmorRule::Comment {
            text: "Ptrace restrictions".to_string(),
        });
        profile.add_rule(AppArmorRule::Ptrace {
            access: vec!["read".to_string(), "trace".to_string()],
            peer: Some("unconfined".to_string()),
            deny: true,
        });

        profile
    }

    /// Generate profile for clawos-wasm-daemon
    pub fn generate_wasm_daemon_profile(&self) -> AppArmorProfile {
        let mut profile = AppArmorProfile::new("clawos-wasm-daemon".to_string(), SecurityLevel::Strict);
        
        // Add mediate_deleted flag for strict isolation
        profile.flags.push("mediate_deleted".to_string());

        // Add header comment
        profile.add_rule(AppArmorRule::Comment {
            text: "Capability grants (minimum required principle)".to_string(),
        });
        profile.add_rule(AppArmorRule::Comment {
            text: "NO CAPABILITIES GRANTED - STRICT ISOLATION".to_string(),
        });

        // Deny all network access (WASM must use host function)
        profile.add_rule(AppArmorRule::Comment {
            text: "Deny all network access (WASM must use host function)".to_string(),
        });
        let network_families = vec![
            NetworkFamily::Inet, NetworkFamily::Inet6, NetworkFamily::Unix,
            NetworkFamily::Packet, NetworkFamily::Ax25, NetworkFamily::Ipx,
            NetworkFamily::Netrom, NetworkFamily::Atmpvc, NetworkFamily::X25,
            NetworkFamily::Rose, NetworkFamily::Decnet, NetworkFamily::Netbeui,
            NetworkFamily::Security, NetworkFamily::Key, NetworkFamily::Netlink,
            NetworkFamily::Ash, NetworkFamily::Econet, NetworkFamily::Atmsvc,
            NetworkFamily::Rds, NetworkFamily::Sna, NetworkFamily::Irida,
            NetworkFamily::Pppox, NetworkFamily::Wanpipe, NetworkFamily::Llc,
            NetworkFamily::Ib, NetworkFamily::Mpls, NetworkFamily::Can,
            NetworkFamily::Tipc, NetworkFamily::Bluetooth, NetworkFamily::Iucv,
            NetworkFamily::Rxrpc, NetworkFamily::Kcm, NetworkFamily::Qipcrtr,
            NetworkFamily::Smc, NetworkFamily::Xdp,
        ];
        for family in network_families {
            profile.add_rule(AppArmorRule::Network {
                family,
                socket_type: None,
                protocol: None,
                address: None,
                port: None,
                deny: true,
            });
        }

        // File access - WASM sandbox directory
        profile.add_rule(AppArmorRule::Comment {
            text: "File access - WASM sandbox directory".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/var/lib/clawos/wasm-sandbox/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/var/lib/clawos/wasm-sandbox/**/".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });

        // File access - WASM tool cache (read-only)
        profile.add_rule(AppArmorRule::Comment {
            text: "File access - WASM tool cache (read-only)".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/var/lib/clawos/wasm-cache/**".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });

        // File access - Configuration (read-only)
        profile.add_rule(AppArmorRule::Comment {
            text: "File access - Configuration (read-only)".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/clawos/wasm/**".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });

        // File access - Logs
        profile.add_rule(AppArmorRule::Comment {
            text: "File access - Logs".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/var/log/clawos/wasm-daemon.log".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/var/log/clawos/wasm-daemon.log*".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });

        // File access - Runtime
        profile.add_rule(AppArmorRule::Comment {
            text: "File access - Runtime".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/run/clawos/wasm/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/run/clawos/wasm.sock".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });

        // File access - Temporary files (isolated)
        profile.add_rule(AppArmorRule::Comment {
            text: "File access - Temporary files (isolated)".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/tmp/clawos-wasm/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "owner /tmp/clawos-wasm/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });

        // File access - WASM runtime libraries
        profile.add_rule(AppArmorRule::Comment {
            text: "File access - WASM runtime libraries".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/usr/lib/wasmtime/**".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/usr/lib64/wasmtime/**".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });

        // File access - System libraries (read-only)
        profile.add_rule(AppArmorRule::Comment {
            text: "File access - System libraries (read-only)".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/usr/lib/**".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/usr/lib64/**".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/lib/**".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/lib64/**".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });

        // Deny sensitive file access
        profile.add_rule(AppArmorRule::Comment {
            text: "Deny sensitive file access".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/passwd".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/shadow".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/group".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/gshadow".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/sudoers".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/ssh/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/root/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/home/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });

        // Deny system configuration modification
        profile.add_rule(AppArmorRule::Comment {
            text: "Deny system configuration modification".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/**".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/usr/local/etc/**".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });

        // Deny kernel module operations
        profile.add_rule(AppArmorRule::Comment {
            text: "Deny kernel module operations".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/sys/module/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/proc/sys/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });

        // Deny device access
        profile.add_rule(AppArmorRule::Comment {
            text: "Deny device access".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/dev/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });

        // Deny mount operations
        profile.add_rule(AppArmorRule::Comment {
            text: "Deny mount operations".to_string(),
        });
        profile.add_rule(AppArmorRule::Mount {
            options: vec![],
            fstype: None,
            source: "*".to_string(),
            target: "*".to_string(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::Mount {
            options: vec![],
            fstype: None,
            source: "*".to_string(),
            target: "*".to_string(),
            deny: true,
        });

        // Deny ptrace (prevent debugging)
        profile.add_rule(AppArmorRule::Comment {
            text: "Deny ptrace (prevent debugging)".to_string(),
        });
        profile.add_rule(AppArmorRule::Ptrace {
            access: vec![],
            peer: None,
            deny: true,
        });

        // Deny signal to other processes
        profile.add_rule(AppArmorRule::Comment {
            text: "Deny signal to other processes".to_string(),
        });
        profile.add_rule(AppArmorRule::Signal {
            signal_set: vec!["send".to_string()],
            peer: Some("unconfined".to_string()),
            deny: true,
        });
        profile.add_rule(AppArmorRule::Signal {
            signal_set: vec!["send".to_string()],
            peer: Some("clawos-agent-loop".to_string()),
            deny: true,
        });
        profile.add_rule(AppArmorRule::Signal {
            signal_set: vec!["send".to_string()],
            peer: Some("clawos-kernel-svc".to_string()),
            deny: true,
        });

        // Allow signal from agent loop only
        profile.add_rule(AppArmorRule::Comment {
            text: "Allow signal from agent loop only".to_string(),
        });
        profile.add_rule(AppArmorRule::Signal {
            signal_set: vec!["receive".to_string()],
            peer: Some("clawos-agent-loop".to_string()),
            deny: false,
        });

        // Deny capability escalation
        profile.add_rule(AppArmorRule::Comment {
            text: "Deny capability escalation".to_string(),
        });
        profile.add_rule(AppArmorRule::Capability {
            capabilities: vec![],
            deny: true,
        });

        // Deny process creation outside sandbox
        profile.add_rule(AppArmorRule::Comment {
            text: "Deny process creation outside sandbox".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/bin/**".to_string(),
            permissions: [FilePermission::InheritExecute].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/usr/bin/**".to_string(),
            permissions: [FilePermission::InheritExecute].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/sbin/**".to_string(),
            permissions: [FilePermission::InheritExecute].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/usr/sbin/**".to_string(),
            permissions: [FilePermission::InheritExecute].iter().cloned().collect(),
            deny: true,
        });

        // Allow only WASM runtime execution
        profile.add_rule(AppArmorRule::Comment {
            text: "Allow only WASM runtime execution".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/usr/bin/wasmtime".to_string(),
            permissions: [FilePermission::InheritExecute].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/usr/local/bin/wasmtime".to_string(),
            permissions: [FilePermission::InheritExecute].iter().cloned().collect(),
            deny: false,
        });

        // Deny shared library modification
        profile.add_rule(AppArmorRule::Comment {
            text: "Deny shared library modification".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/usr/lib/**/*.so".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/usr/lib64/**/*.so".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/lib/**/*.so".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/lib64/**/*.so".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });

        profile
    }

    /// Generate profile for clawos-kernel-svc
    pub fn generate_kernel_svc_profile(&self) -> AppArmorProfile {
        let mut profile = AppArmorProfile::new("clawos-kernel-svc".to_string(), SecurityLevel::Moderate);
        
        // Add additional includes
        profile.add_include("abstractions/nameservice".to_string());

        // Add header comment
        profile.add_rule(AppArmorRule::Comment {
            text: "Capability grants (minimum required principle)".to_string(),
        });

        // Capability grants
        profile.add_rule(AppArmorRule::Comment {
            text: "Required for cgroup management".to_string(),
        });
        profile.add_rule(AppArmorRule::Capability {
            capabilities: vec![Capability::SysAdmin],
            deny: false,
        });
        profile.add_rule(AppArmorRule::Capability {
            capabilities: vec![Capability::SysResource],
            deny: false,
        });
        profile.add_rule(AppArmorRule::Comment {
            text: "Network configuration (for XDP)".to_string(),
        });
        profile.add_rule(AppArmorRule::Capability {
            capabilities: vec![Capability::NetAdmin],
            deny: false,
        });
        profile.add_rule(AppArmorRule::Comment {
            text: "Lock memory for eBPF maps".to_string(),
        });
        profile.add_rule(AppArmorRule::Capability {
            capabilities: vec![Capability::IpcLock],
            deny: false,
        });
        profile.add_rule(AppArmorRule::Comment {
            text: "Load kernel modules (RESTRICTED)".to_string(),
        });
        profile.add_rule(AppArmorRule::Capability {
            capabilities: vec![Capability::SysModule],
            deny: false,
        });
        profile.add_rule(AppArmorRule::Comment {
            text: "Create device nodes (RESTRICTED)".to_string(),
        });
        profile.add_rule(AppArmorRule::Capability {
            capabilities: vec![Capability::Mknod],
            deny: false,
        });

        // Network access - XDP monitoring (read-only)
        profile.add_rule(AppArmorRule::Comment {
            text: "Network access - XDP monitoring (read-only)".to_string(),
        });
        profile.add_rule(AppArmorRule::Network {
            family: NetworkFamily::Inet,
            socket_type: Some(NetworkType::Raw),
            protocol: None,
            address: None,
            port: None,
            deny: false,
        });
        profile.add_rule(AppArmorRule::Network {
            family: NetworkFamily::Packet,
            socket_type: Some(NetworkType::Raw),
            protocol: None,
            address: None,
            port: None,
            deny: false,
        });

        // Deny application network access
        profile.add_rule(AppArmorRule::Comment {
            text: "Deny application network access".to_string(),
        });
        profile.add_rule(AppArmorRule::Network {
            family: NetworkFamily::Inet,
            socket_type: Some(NetworkType::Stream),
            protocol: None,
            address: None,
            port: None,
            deny: true,
        });
        profile.add_rule(AppArmorRule::Network {
            family: NetworkFamily::Inet6,
            socket_type: Some(NetworkType::Stream),
            protocol: None,
            address: None,
            port: None,
            deny: true,
        });
        profile.add_rule(AppArmorRule::Network {
            family: NetworkFamily::Inet,
            socket_type: Some(NetworkType::Dgram),
            protocol: None,
            address: None,
            port: None,
            deny: true,
        });
        profile.add_rule(AppArmorRule::Network {
            family: NetworkFamily::Inet6,
            socket_type: Some(NetworkType::Dgram),
            protocol: None,
            address: None,
            port: None,
            deny: true,
        });

        // File access - eBPF programs and maps
        profile.add_rule(AppArmorRule::Comment {
            text: "File access - eBPF programs and maps".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/sys/fs/bpf/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/sys/kernel/debug/tracing/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });

        // File access - cgroup management
        profile.add_rule(AppArmorRule::Comment {
            text: "File access - cgroup management".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/sys/fs/cgroup/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/sys/fs/cgroup/clawos/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });

        // File access - Device nodes (restricted)
        profile.add_rule(AppArmorRule::Comment {
            text: "File access - Device nodes (restricted)".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/dev/null".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/dev/zero".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/dev/full".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/dev/random".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/dev/urandom".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/dev/ptmx".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/dev/pts/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });

        // Deny other device access
        profile.add_rule(AppArmorRule::Comment {
            text: "Deny other device access".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/dev/sda*".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/dev/nvme*".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/dev/mapper/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/dev/disk/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/dev/snd/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/dev/video*".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/dev/input/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });

        // File access - Configuration
        profile.add_rule(AppArmorRule::Comment {
            text: "File access - Configuration".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/clawos/kernel/**".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/clawos/kernel/config.json".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });

        // File access - Logs
        profile.add_rule(AppArmorRule::Comment {
            text: "File access - Logs".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/var/log/clawos/kernel-svc.log".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/var/log/clawos/kernel-svc.log*".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/var/log/kern.log".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });

        // File access - Runtime
        profile.add_rule(AppArmorRule::Comment {
            text: "File access - Runtime".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/run/clawos/kernel/**".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/run/clawos/kernel.sock".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        });

        // File access - System libraries
        profile.add_rule(AppArmorRule::Comment {
            text: "File access - System libraries".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/usr/lib/**".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/usr/lib64/**".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/lib/**".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/lib64/**".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });

        // File access - Executables
        profile.add_rule(AppArmorRule::Comment {
            text: "File access - Executables".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/usr/bin/**".to_string(),
            permissions: [FilePermission::InheritExecute].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/bin/**".to_string(),
            permissions: [FilePermission::InheritExecute].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/sbin/**".to_string(),
            permissions: [FilePermission::InheritExecute].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/usr/sbin/**".to_string(),
            permissions: [FilePermission::InheritExecute].iter().cloned().collect(),
            deny: false,
        });

        // File access - Kernel modules (read-only)
        profile.add_rule(AppArmorRule::Comment {
            text: "File access - Kernel modules (read-only)".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/lib/modules/**".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/usr/lib/modules/**".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        });

        // Deny sensitive file modifications
        profile.add_rule(AppArmorRule::Comment {
            text: "Deny sensitive file modifications".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/passwd".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/shadow".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/group".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/gshadow".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/sudoers".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/ssh/**".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });

        // Deny system configuration modification
        profile.add_rule(AppArmorRule::Comment {
            text: "Deny system configuration modification".to_string(),
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/sysctl.conf".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });
        profile.add_rule(AppArmorRule::File {
            path: "/etc/sysctl.d/**".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: true,
        });

        // Mount operations (restricted)
        profile.add_rule(AppArmorRule::Comment {
            text: "Mount operations (restricted)".to_string(),
        });
        profile.add_rule(AppArmorRule::Mount {
            options: vec!["ro".to_string(), "bind".to_string()],
            fstype: None,
            source: "/sys/fs/bpf/".to_string(),
            target: "/sys/fs/bpf/".to_string(),
            deny: false,
        });
        profile.add_rule(AppArmorRule::Mount {
            options: vec![],
            fstype: None,
            source: "*".to_string(),
            target: "*".to_string(),
            deny: true,
        });

        // Signal permissions
        profile.add_rule(AppArmorRule::Comment {
            text: "Signal permissions".to_string(),
        });
        profile.add_rule(AppArmorRule::Signal {
            signal_set: vec!["receive".to_string()],
            peer: Some("clawos-agent-loop".to_string()),
            deny: false,
        });
        profile.add_rule(AppArmorRule::Signal {
            signal_set: vec!["send".to_string()],
            peer: Some("clawos-agent-loop".to_string()),
            deny: false,
        });

        // Ptrace restrictions
        profile.add_rule(AppArmorRule::Comment {
            text: "Ptrace restrictions".to_string(),
        });
        profile.add_rule(AppArmorRule::Ptrace {
            access: vec!["read".to_string(), "trace".to_string()],
            peer: Some("unconfined".to_string()),
            deny: true,
        });
        profile.add_rule(AppArmorRule::Ptrace {
            access: vec!["read".to_string(), "trace".to_string()],
            peer: Some("clawos-wasm-daemon".to_string()),
            deny: true,
        });

        // Change profile for subprocesses
        profile.add_rule(AppArmorRule::Comment {
            text: "Change profile for subprocesses".to_string(),
        });
        profile.add_rule(AppArmorRule::ChangeProfile {
            target: "clawos-agent-loop".to_string(),
        });

        profile
    }

    /// Generate all ClawOS component profiles
    pub fn generate_all_profiles(&self) -> Vec<AppArmorProfile> {
        vec![
            self.generate_agent_loop_profile(),
            self.generate_wasm_daemon_profile(),
            self.generate_kernel_svc_profile(),
        ]
    }

    /// Validate a network rule against the PostgreSQL allowlist
    pub fn validate_network_allowlist(
        &self,
        family: NetworkFamily,
        socket_type: Option<NetworkType>,
        protocol: Option<NetworkProtocol>,
        address: Option<&str>,
        port: Option<u16>,
    ) -> bool {
        // Only allow PostgreSQL connections
        if socket_type != Some(NetworkType::Stream) {
            return false;
        }
        if protocol != Some(NetworkProtocol::Tcp) {
            return false;
        }
        if family != NetworkFamily::Inet && family != NetworkFamily::Inet6 {
            return false;
        }

        // Check against allowlist
        if let (Some(addr), Some(p)) = (address, port) {
            self.postgresql_allowlist.contains(&(addr.to_string(), p))
        } else {
            false
        }
    }
}

impl Default for AppArmorGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate complain mode wrapper script for testing
pub fn generate_complain_mode_wrapper(profile_name: &str) -> String {
    format!(
        r#"#!/bin/bash
# Complain mode wrapper for {profile_name}
# This script loads the profile in complain mode for testing
# Usage: sudo ./{profile_name}-complain.sh

set -e

PROFILE_PATH="/etc/apparmor.d/{profile_name}"
LOG_PATH="/var/log/clawos/{profile_name}-complain.log"

echo "Loading {profile_name} in complain mode..."
sudo apparmor_parser -C "$PROFILE_PATH"

echo "Profile loaded in complain mode"
echo "Monitoring violations at: $LOG_PATH"
echo ""
echo "To view violations:"
echo "  sudo journalctl -u apparmor | grep {profile_name}"
echo "  sudo aa-logprof"
echo ""
echo "To transition to enforce mode after testing:"
echo "  sudo aa-enforce /usr/bin/{profile_name}"
"#,
        profile_name = profile_name
    )
}

/// Generate enforce mode wrapper script for production
pub fn generate_enforce_mode_wrapper(profile_name: &str) -> String {
    format!(
        r#"#!/bin/bash
# Enforce mode wrapper for {profile_name}
# This script transitions the profile from complain to enforce mode
# WARNING: Ensure complain mode testing is complete before using this
# Usage: sudo ./{profile_name}-enforce.sh

set -e

PROFILE_PATH="/etc/apparmor.d/{profile_name}"
BINARY_PATH="/usr/bin/{profile_name}"

echo "Transitioning {profile_name} to enforce mode..."
sudo aa-enforce "$BINARY_PATH"

echo "Profile now in enforce mode"
echo "Blocked operations will be logged to:"
echo "  /var/log/clawos/{profile_name}-violations.log"
echo ""
echo "To view status:"
echo "  sudo aa-status | grep {profile_name}"
echo ""
echo "To return to complain mode (emergency only):"
echo "  sudo aa-complain $BINARY_PATH"
"#,
        profile_name = profile_name
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_permission_syntax() {
        assert_eq!(FilePermission::Read.to_syntax(), "r");
        assert_eq!(FilePermission::Write.to_syntax(), "w");
        assert_eq!(FilePermission::Execute.to_syntax(), "x");
        assert_eq!(FilePermission::InheritExecute.to_syntax(), "ix");
    }

    #[test]
    fn test_file_permission_from_syntax() {
        assert_eq!(FilePermission::from_syntax("r").unwrap(), FilePermission::Read);
        assert_eq!(FilePermission::from_syntax("w").unwrap(), FilePermission::Write);
        assert_eq!(FilePermission::from_syntax("ix").unwrap(), FilePermission::InheritExecute);
    }

    #[test]
    fn test_capability_syntax() {
        assert_eq!(Capability::Bpf.to_syntax(), "bpf");
        assert_eq!(Capability::SysAdmin.to_syntax(), "sys_admin");
        assert_eq!(Capability::NetBindService.to_syntax(), "net_bind_service");
    }

    #[test]
    fn test_network_family_syntax() {
        assert_eq!(NetworkFamily::Inet.to_syntax(), "inet");
        assert_eq!(NetworkFamily::Inet6.to_syntax(), "inet6");
        assert_eq!(NetworkFamily::Unix.to_syntax(), "unix");
    }

    #[test]
    fn test_network_type_syntax() {
        assert_eq!(NetworkType::Stream.to_syntax(), "stream");
        assert_eq!(NetworkType::Dgram.to_syntax(), "dgram");
        assert_eq!(NetworkType::Raw.to_syntax(), "raw");
    }

    #[test]
    fn test_network_protocol_syntax() {
        assert_eq!(NetworkProtocol::Tcp.to_syntax(), "tcp");
        assert_eq!(NetworkProtocol::Udp.to_syntax(), "udp");
    }

    #[test]
    fn test_rule_to_syntax() {
        // Capability rule
        let rule = AppArmorRule::Capability {
            capabilities: vec![Capability::Bpf],
            deny: false,
        };
        assert_eq!(rule.to_syntax(), "capability bpf,");

        // File rule
        let rule = AppArmorRule::File {
            path: "/etc/clawos/config.json".to_string(),
            permissions: [FilePermission::Read, FilePermission::Write].iter().cloned().collect(),
            deny: false,
        };
        assert_eq!(rule.to_syntax(), "/etc/clawos/config.json rw,");

        // Network rule
        let rule = AppArmorRule::Network {
            family: NetworkFamily::Inet,
            socket_type: Some(NetworkType::Stream),
            protocol: Some(NetworkProtocol::Tcp),
            address: Some("127.0.0.1".to_string()),
            port: Some(5432),
            deny: false,
        };
        assert_eq!(rule.to_syntax(), "network inet stream tcp to 127.0.0.1 port 5432,");

        // Deny rule
        let rule = AppArmorRule::File {
            path: "/etc/passwd".to_string(),
            permissions: [FilePermission::Write].iter().cloned().collect(),
            deny: true,
        };
        assert_eq!(rule.to_syntax(), "deny /etc/passwd w,");
    }

    #[test]
    fn test_profile_creation() {
        let profile = AppArmorProfile::new("test-profile".to_string(), SecurityLevel::Moderate);
        assert_eq!(profile.name, "test-profile");
        assert_eq!(profile.security_level, SecurityLevel::Moderate);
        assert!(profile.flags.contains(&"attach_disconnected".to_string()));
        assert_eq!(profile.owner, "Security Agent");
        assert_eq!(profile.status, "FROZEN");
    }

    #[test]
    fn test_profile_validation() {
        let profile = AppArmorProfile::new("valid-profile".to_string(), SecurityLevel::Moderate);
        assert!(profile.validate().is_ok());

        let invalid_profile = AppArmorProfile::new("invalid profile!".to_string(), SecurityLevel::Moderate);
        assert!(invalid_profile.validate().is_err());
    }

    #[test]
    fn test_file_rule_validation() {
        let profile = AppArmorProfile::new("test".to_string(), SecurityLevel::Moderate);
        
        // Valid absolute path
        let rule = AppArmorRule::File {
            path: "/etc/clawos/config.json".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        };
        assert!(profile.validate_rule(&rule).is_ok());

        // Invalid relative path
        let rule = AppArmorRule::File {
            path: "etc/clawos/config.json".to_string(),
            permissions: [FilePermission::Read].iter().cloned().collect(),
            deny: false,
        };
        assert!(profile.validate_rule(&rule).is_err());
    }

    #[test]
    fn test_network_rule_validation() {
        let profile = AppArmorProfile::new("test".to_string(), SecurityLevel::Moderate);
        
        // Valid IPv4 address
        let rule = AppArmorRule::Network {
            family: NetworkFamily::Inet,
            socket_type: Some(NetworkType::Stream),
            protocol: Some(NetworkProtocol::Tcp),
            address: Some("127.0.0.1".to_string()),
            port: Some(5432),
            deny: false,
        };
        assert!(profile.validate_rule(&rule).is_ok());

        // Invalid port
        let rule = AppArmorRule::Network {
            family: NetworkFamily::Inet,
            socket_type: Some(NetworkType::Stream),
            protocol: Some(NetworkProtocol::Tcp),
            address: Some("127.0.0.1".to_string()),
            port: Some(0),
            deny: false,
        };
        assert!(profile.validate_rule(&rule).is_err());
    }

    #[test]
    fn test_generator_creation() {
        let generator = AppArmorGenerator::new();
        assert!(generator.postgresql_allowlist.contains(&(String::from("127.0.0.1"), 5432)));
        assert!(generator.postgresql_allowlist.contains(&(String::from("::1"), 5432)));
    }

    #[test]
    fn test_network_allowlist_validation() {
        let generator = AppArmorGenerator::new();
        
        // Valid PostgreSQL connection
        assert!(generator.validate_network_allowlist(
            NetworkFamily::Inet,
            Some(NetworkType::Stream),
            Some(NetworkProtocol::Tcp),
            Some("127.0.0.1"),
            Some(5432)
        ));

        // Invalid port
        assert!(!generator.validate_network_allowlist(
            NetworkFamily::Inet,
            Some(NetworkType::Stream),
            Some(NetworkProtocol::Tcp),
            Some("127.0.0.1"),
            Some(8080)
        ));

        // Invalid protocol
        assert!(!generator.validate_network_allowlist(
            NetworkFamily::Inet,
            Some(NetworkType::Stream),
            Some(NetworkProtocol::Udp),
            Some("127.0.0.1"),
            Some(5432)
        ));
    }

    #[test]
    fn test_generate_agent_loop_profile() {
        let generator = AppArmorGenerator::new();
        let profile = generator.generate_agent_loop_profile();
        
        assert_eq!(profile.name, "clawos-agent-loop");
        assert_eq!(profile.security_level, SecurityLevel::Moderate);
        assert!(!profile.rules.is_empty());
        
        // Check for PostgreSQL network rule
        let has_postgres_rule = profile.rules.iter().any(|rule| {
            if let AppArmorRule::Network { address, port, .. } = rule {
                address.as_deref() == Some("127.0.0.1") && *port == Some(5432)
            } else {
                false
            }
        });
        assert!(has_postgres_rule);
    }

    #[test]
    fn test_generate_wasm_daemon_profile() {
        let generator = AppArmorGenerator::new();
        let profile = generator.generate_wasm_daemon_profile();
        
        assert_eq!(profile.name, "clawos-wasm-daemon");
        assert_eq!(profile.security_level, SecurityLevel::Strict);
        assert!(profile.flags.contains(&"mediate_deleted".to_string()));
        
        // Check for network deny rules
        let has_network_deny = profile.rules.iter().any(|rule| {
            matches!(rule, AppArmorRule::Network { deny: true, .. })
        });
        assert!(has_network_deny);
    }

    #[test]
    fn test_generate_kernel_svc_profile() {
        let generator = AppArmorGenerator::new();
        let profile = generator.generate_kernel_svc_profile();
        
        assert_eq!(profile.name, "clawos-kernel-svc");
        assert_eq!(profile.security_level, SecurityLevel::Moderate);
        
        // Check for sys_admin capability
        let has_sys_admin = profile.rules.iter().any(|rule| {
            if let AppArmorRule::Capability { capabilities, deny: false } = rule {
                capabilities.contains(&Capability::SysAdmin)
            } else {
                false
            }
        });
        assert!(has_sys_admin);
    }

    #[test]
    fn test_generate_all_profiles() {
        let generator = AppArmorGenerator::new();
        let profiles = generator.generate_all_profiles();
        
        assert_eq!(profiles.len(), 3);
        
        let profile_names: Vec<&str> = profiles.iter().map(|p| p.name.as_str()).collect();
        assert!(profile_names.contains(&"clawos-agent-loop"));
        assert!(profile_names.contains(&"clawos-wasm-daemon"));
        assert!(profile_names.contains(&"clawos-kernel-svc"));
    }

    #[test]
    fn test_profile_generation_syntax() {
        let generator = AppArmorGenerator::new();
        let profile = generator.generate_agent_loop_profile();
        let syntax = profile.generate();
        
        // Check for required elements
        assert!(syntax.contains("profile clawos-agent-loop"));
        assert!(syntax.contains("flags=(attach_disconnected)"));
        assert!(syntax.contains("#include <tunables/global>"));
        assert!(syntax.contains("capability bpf,"));
        assert!(syntax.contains("network inet stream tcp to 127.0.0.1 port 5432,"));
        assert!(syntax.contains("deny /etc/passwd w,"));
    }

    #[test]
    fn test_complain_mode_wrapper() {
        let wrapper = generate_complain_mode_wrapper("test-profile");
        assert!(wrapper.contains("test-profile"));
        assert!(wrapper.contains("apparmor_parser -C"));
        assert!(wrapper.contains("aa-enforce"));
    }

    #[test]
    fn test_enforce_mode_wrapper() {
        let wrapper = generate_enforce_mode_wrapper("test-profile");
        assert!(wrapper.contains("test-profile"));
        assert!(wrapper.contains("aa-enforce"));
        assert!(wrapper.contains("aa-complain"));
    }

    #[test]
    fn test_security_level_display() {
        assert_eq!(SecurityLevel::Strict.to_string(), "STRICT");
        assert_eq!(SecurityLevel::Moderate.to_string(), "MODERATE");
        assert_eq!(SecurityLevel::Permissive.to_string(), "PERMISSIVE");
    }
}
