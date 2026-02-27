use libseccomp::{ScmpFilterContext, ScmpAction, ScmpSyscall, ScmpCompareOp, ScmpArgCompare};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::error::{SecurityError, SecurityResult, ErrorCode};

/// Permission level for a syscall
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Permission {
    /// Allow this syscall unconditionally
    Allow,
    /// Deny this syscall unconditionally
    Deny,
    /// Allow this syscall only under specific conditions
    Conditional,
}

/// Comparison operator for argument filtering
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompareOperator {
    /// Equal
    Eq,
    /// Not equal
    Ne,
    /// Greater than
    Gt,
    /// Less than
    Lt,
    /// Greater than or equal
    Ge,
    /// Less than or equal
    Le,
    /// Masked equality (value & mask == expected)
    MaskedEq,
}

impl CompareOperator {
    fn to_seccomp_op(self) -> ScmpCompareOp {
        match self {
            CompareOperator::Eq => ScmpCompareOp::Equal,
            CompareOperator::Ne => ScmpCompareOp::NotEqual,
            CompareOperator::Gt => ScmpCompareOp::Greater,
            CompareOperator::Lt => ScmpCompareOp::Less,
            CompareOperator::Ge => ScmpCompareOp::GreaterEqual,
            CompareOperator::Le => ScmpCompareOp::LessOrEqual,
            CompareOperator::MaskedEq => ScmpCompareOp::MaskedEqual(0), // mask will be applied separately
        }
    }
}

/// Port restriction for network syscalls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRestriction {
    pub allowed_ports: Vec<u16>,
    #[serde(default)]
    pub description: Option<String>,
}

/// Argument filter for conditional syscalls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgumentFilter {
    pub arg_index: u32,
    pub operator: CompareOperator,
    pub value: u64,
    #[serde(default)]
    pub mask: Option<u64>,
}

/// Conditions for conditional permission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    #[serde(default)]
    pub port_restriction: Option<PortRestriction>,
    #[serde(default)]
    pub argument_filter: Option<ArgumentFilter>,
    pub description: String,
}

/// Syscall category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyscallCategory {
    Memory,
    FileIo,
    Process,
    Network,
    Time,
    Signals,
    Misc,
    TokioRuntime,
}

/// Single syscall rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallRule {
    pub name: String,
    pub permission: Permission,
    #[serde(default)]
    pub category: Option<SyscallCategory>,
    #[serde(default)]
    pub conditions: Option<Condition>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub verified_by_strace: Option<bool>,
    #[serde(default)]
    pub tokio_required: Option<bool>,
}

/// Metadata about the whitelist
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistMetadata {
    #[serde(default)]
    pub target_process: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub security_level: Option<String>,
    #[serde(default)]
    pub tokio_version: Option<String>,
    #[serde(default)]
    pub rust_version: Option<String>,
}

/// Complete seccomp whitelist
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Whitelist {
    pub schema_version: String,
    pub whitelist_id: String,
    pub created_at: String,
    pub created_by: String,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub updated_by: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    pub syscalls: Vec<SyscallRule>,
    #[serde(default)]
    pub metadata: Option<WhitelistMetadata>,
}

impl Whitelist {
    pub fn from_json<P: AsRef<Path>>(path: P) -> SecurityResult<Self> {
        let content = fs::read_to_string(path)?;
        let whitelist: Whitelist = serde_json::from_str(&content)?;
        whitelist.validate()?;
        Ok(whitelist)
    }

    pub fn from_json_str(json: &str) -> SecurityResult<Self> {
        let whitelist: Whitelist = serde_json::from_str(json)?;
        whitelist.validate()?;
        Ok(whitelist)
    }

    pub fn validate(&self) -> SecurityResult<()> {
        if self.created_by != "Security Agent" {
            return Err(SecurityError::WhitelistValidation(
                "Whitelist must be created by Security Agent".to_string(),
            ));
        }

        let mut syscall_names = HashSet::new();
        for rule in &self.syscalls {
            if !syscall_names.insert(&rule.name) {
                return Err(SecurityError::WhitelistValidation(format!(
                    "Duplicate syscall: {}",
                    rule.name
                )));
            }

            if rule.permission == Permission::Conditional && rule.conditions.is_none() {
                return Err(SecurityError::WhitelistValidation(format!(
                    "Conditional syscall {} must have conditions",
                    rule.name
                )));
            }
        }

        Ok(())
    }

    pub fn get_tokio_syscalls(&self) -> Vec<&SyscallRule> {
        self.syscalls
            .iter()
            .filter(|s| s.tokio_required.unwrap_or(false))
            .collect()
    }
}

/// seccomp-BPF filter builder
pub struct SeccompFilter {
    ctx: ScmpFilterContext,
    whitelist: Whitelist,
}

impl SeccompFilter {
    pub fn new(whitelist: Whitelist) -> SecurityResult<Self> {
        let ctx = ScmpFilterContext::new(ScmpAction::KillProcess)
            .map_err(|e| SecurityError::SeccompFilter(format!("Failed to create filter: {}", e)))?;

        let mut filter = SeccompFilter { ctx, whitelist };
        filter.build()?;
        Ok(filter)
    }

    pub fn from_json<P: AsRef<Path>>(path: P) -> SecurityResult<Self> {
        let whitelist = Whitelist::from_json(path)?;
        Self::new(whitelist)
    }

    pub fn from_json_str(json: &str) -> SecurityResult<Self> {
        let whitelist = Whitelist::from_json_str(json)?;
        Self::new(whitelist)
    }

    fn build(&mut self) -> SecurityResult<()> {
        for rule in &self.whitelist.syscalls {
            match rule.permission {
                Permission::Allow => self.add_allow_rule(rule)?,
                Permission::Deny => self.add_deny_rule(rule)?,
                Permission::Conditional => self.add_conditional_rule(rule)?,
            }
        }
        Ok(())
    }

    fn add_allow_rule(&mut self, rule: &SyscallRule) -> SecurityResult<()> {
        let syscall = self.resolve_syscall(&rule.name)?;
        self.ctx
            .add_rule(ScmpAction::Allow, syscall)
            .map_err(|e| {
                SecurityError::SeccompFilter(format!("Failed to add allow rule for {}: {}", rule.name, e))
            })?;
        Ok(())
    }

    fn add_deny_rule(&mut self, rule: &SyscallRule) -> SecurityResult<()> {
        let syscall = self.resolve_syscall(&rule.name)?;
        let errno = ErrorCode::EPerm.to_seccomp_errno().unwrap_or(libc::EPERM as u32) as i32;
        self.ctx
            .add_rule(ScmpAction::Errno(errno), syscall)
            .map_err(|e| {
                SecurityError::SeccompFilter(format!("Failed to add deny rule for {}: {}", rule.name, e))
            })?;
        Ok(())
    }

    fn add_conditional_rule(&mut self, rule: &SyscallRule) -> SecurityResult<()> {
        let syscall = self.resolve_syscall(&rule.name)?;
        let conditions = rule.conditions.as_ref().ok_or_else(|| {
            SecurityError::InvalidCondition(format!("No conditions for conditional syscall {}", rule.name))
        })?;

        if let Some(ref port_restriction) = conditions.port_restriction {
            self.add_port_restriction(syscall, port_restriction)?;
        }

        if let Some(ref arg_filter) = conditions.argument_filter {
            self.add_argument_filter(syscall, arg_filter)?;
        }

        Ok(())
    }

    fn add_port_restriction(&mut self, syscall: ScmpSyscall, restriction: &PortRestriction) -> SecurityResult<()> {
        let errno = ErrorCode::EPerm.to_seccomp_errno().unwrap_or(libc::EPERM as u32) as i32;

        for port in &restriction.allowed_ports {
            let arg_cmp = ScmpArgCompare::new(1, ScmpCompareOp::Equal, *port as u64);
            self.ctx
                .add_rule_conditional(ScmpAction::Allow, syscall, &[arg_cmp])
                .map_err(|e| {
                    SecurityError::SeccompFilter(format!(
                        "Failed to add port restriction for port {}: {}",
                        port, e
                    ))
                })?;
        }

        self.ctx
            .add_rule(ScmpAction::Errno(errno), syscall)
            .map_err(|e| {
                SecurityError::SeccompFilter(format!(
                    "Failed to add default deny for port-restricted syscall: {}",
                    e
                ))
            })?;

        Ok(())
    }

    fn add_argument_filter(&mut self, syscall: ScmpSyscall, filter: &ArgumentFilter) -> SecurityResult<()> {
        let errno = ErrorCode::EPerm.to_seccomp_errno().unwrap_or(libc::EPERM as u32) as i32;

        // For masked operations, use MaskedEqual variant
        let op = if filter.mask.is_some() {
            ScmpCompareOp::MaskedEqual(filter.mask.unwrap())
        } else {
            filter.operator.to_seccomp_op()
        };
        let arg_cmp = ScmpArgCompare::new(filter.arg_index, op, filter.value);

        self.ctx
            .add_rule_conditional(ScmpAction::Allow, syscall, &[arg_cmp])
            .map_err(|e| {
                SecurityError::SeccompFilter(format!(
                    "Failed to add argument filter for arg {}: {}",
                    filter.arg_index, e
                ))
            })?;

        self.ctx
            .add_rule(ScmpAction::Errno(errno), syscall)
            .map_err(|e| {
                SecurityError::SeccompFilter(format!(
                    "Failed to add default deny for argument-filtered syscall: {}",
                    e
                ))
            })?;

        Ok(())
    }

    fn resolve_syscall(&self, name: &str) -> SecurityResult<ScmpSyscall> {
        ScmpSyscall::from_name(name)
            .map_err(|_| SecurityError::InvalidSyscall(name.to_string()))
    }

    pub fn apply(&mut self) -> SecurityResult<()> {
        self.ctx
            .load()
            .map_err(|e| SecurityError::SeccompFilter(format!("Failed to load seccomp filter: {}", e)))?;
        Ok(())
    }

    /// Export the BPF filter (Note: libseccomp 0.4 removed get_filter method)
    /// This method is no longer supported - use load() instead to apply the filter
    pub fn export_bpf(&self) -> SecurityResult<Vec<u8>> {
        Err(SecurityError::SeccompFilter(
            "export_bpf() is not supported in libseccomp 0.4. Use apply() to load the filter instead.".to_string()
        ))
    }

    pub fn get_whitelist(&self) -> &Whitelist {
        &self.whitelist
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_whitelist() -> Whitelist {
        Whitelist {
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
                SyscallRule {
                    name: "write".to_string(),
                    permission: Permission::Allow,
                    category: Some(SyscallCategory::FileIo),
                    conditions: None,
                    notes: None,
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
                        description: "Socket creation allowed only for PostgreSQL connections".to_string(),
                    }),
                    notes: None,
                    verified_by_strace: Some(true),
                    tokio_required: Some(false),
                },
            ],
            metadata: None,
            signature: None,
            updated_at: None,
            updated_by: None,
        }
    }

    #[test]
    fn test_whitelist_validation() {
        let whitelist = create_test_whitelist();
        assert!(whitelist.validate().is_ok());
    }

    #[test]
    fn test_whitelist_invalid_creator() {
        let mut whitelist = create_test_whitelist();
        whitelist.created_by = "Invalid Agent".to_string();
        assert!(whitelist.validate().is_err());
    }

    #[test]
    fn test_whitelist_duplicate_syscall() {
        let mut whitelist = create_test_whitelist();
        whitelist.syscalls.push(whitelist.syscalls[0].clone());
        assert!(whitelist.validate().is_err());
    }

    #[test]
    fn test_whitelist_conditional_without_conditions() {
        let mut whitelist = create_test_whitelist();
        whitelist.syscalls.push(SyscallRule {
            name: "connect".to_string(),
            permission: Permission::Conditional,
            category: Some(SyscallCategory::Network),
            conditions: None,
            notes: None,
            verified_by_strace: Some(true),
            tokio_required: Some(false),
        });
        assert!(whitelist.validate().is_err());
    }

    #[test]
    fn test_whitelist_from_json_str() {
        let json = r#"{
            "schema_version": "1.0.0",
            "whitelist_id": "550e8400-e29b-41d4-a716-446655440000",
            "created_at": "2026-02-24T00:00:00Z",
            "created_by": "Security Agent",
            "syscalls": [
                {
                    "name": "read",
                    "permission": "ALLOW",
                    "category": "file_io",
                    "verified_by_strace": true,
                    "tokio_required": false
                }
            ]
        }"#;
        let whitelist = Whitelist::from_json_str(json);
        assert!(whitelist.is_ok());
        assert_eq!(whitelist.unwrap().syscalls.len(), 1);
    }

    #[test]
    fn test_compare_operator_conversion() {
        assert_eq!(CompareOperator::Eq.to_seccomp_op(), ScmpCompareOp::ScmpCmpEq);
        assert_eq!(CompareOperator::Ne.to_seccomp_op(), ScmpCompareOp::ScmpCmpNe);
        assert_eq!(CompareOperator::Gt.to_seccomp_op(), ScmpCompareOp::ScmpCmpGt);
        assert_eq!(CompareOperator::Lt.to_seccomp_op(), ScmpCompareOp::ScmpCmpLt);
        assert_eq!(CompareOperator::Ge.to_seccomp_op(), ScmpCompareOp::ScmpCmpGe);
        assert_eq!(CompareOperator::Le.to_seccomp_op(), ScmpCompareOp::ScmpCmpLe);
        assert_eq!(CompareOperator::MaskedEq.to_seccomp_op(), ScmpCompareOp::ScmpCmpMaskedEq);
    }

    #[test]
    fn test_get_tokio_syscalls() {
        let mut whitelist = create_test_whitelist();
        whitelist.syscalls.push(SyscallRule {
            name: "epoll_wait".to_string(),
            permission: Permission::Allow,
            category: Some(SyscallCategory::TokioRuntime),
            conditions: None,
            notes: None,
            verified_by_strace: Some(true),
            tokio_required: Some(true),
        });

        let tokio_syscalls = whitelist.get_tokio_syscalls();
        assert_eq!(tokio_syscalls.len(), 1);
        assert_eq!(tokio_syscalls[0].name, "epoll_wait");
    }

    #[test]
    fn test_seccomp_filter_creation() {
        let whitelist = create_test_whitelist();
        let filter = SeccompFilter::new(whitelist);
        assert!(filter.is_ok());
    }

    #[test]
    fn test_seccomp_filter_invalid_syscall() {
        let mut whitelist = create_test_whitelist();
        whitelist.syscalls.push(SyscallRule {
            name: "invalid_syscall_name".to_string(),
            permission: Permission::Allow,
            category: Some(SyscallCategory::Misc),
            conditions: None,
            notes: None,
            verified_by_strace: Some(true),
            tokio_required: Some(false),
        });

        let filter = SeccompFilter::new(whitelist);
        assert!(filter.is_err());
    }

    #[test]
    fn test_argument_filter() {
        let whitelist = Whitelist {
            schema_version: "1.0.0".to_string(),
            whitelist_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            created_at: "2026-02-24T00:00:00Z".to_string(),
            created_by: "Security Agent".to_string(),
            syscalls: vec![SyscallRule {
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
            }],
            metadata: None,
            signature: None,
            updated_at: None,
            updated_by: None,
        };

        let filter = SeccompFilter::new(whitelist);
        assert!(filter.is_ok());
    }

    #[test]
    fn test_masked_argument_filter() {
        let whitelist = Whitelist {
            schema_version: "1.0.0".to_string(),
            whitelist_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            created_at: "2026-02-24T00:00:00Z".to_string(),
            created_by: "Security Agent".to_string(),
            syscalls: vec![SyscallRule {
                name: "openat".to_string(),
                permission: Permission::Conditional,
                category: Some(SyscallCategory::FileIo),
                conditions: Some(Condition {
                    port_restriction: None,
                    argument_filter: Some(ArgumentFilter {
                        arg_index: 1,
                        operator: CompareOperator::MaskedEq,
                        value: 0,
                        mask: 3,
                    }),
                    description: "Only allow O_RDONLY or O_WRONLY".to_string(),
                }),
                notes: None,
                verified_by_strace: Some(true),
                tokio_required: Some(false),
            }],
            metadata: None,
            signature: None,
            updated_at: None,
            updated_by: None,
        };

        let filter = SeccompFilter::new(whitelist);
        assert!(filter.is_ok());
    }
}
