use crate::error::{BridgeError, BridgeResult, ErrorCode};
use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall, ScmpCompareOp, ScmpArgCompare};
use tracing::{info, debug, warn};

const ALLOWED_SYSCALLS: &[&str] = &[
    "mmap", "munmap", "mprotect", "brk", "madvise",
    "read", "write", "open", "openat", "close", "stat", "fstat", "lstat",
    "exit", "exit_group", "getpid", "gettid", "futex", "clone", "clone3",
    "socket", "connect", "recv", "send", "poll", "epoll_create1",
    "epoll_ctl", "epoll_wait", "epoll_pwait",
    "clock_gettime", "clock_nanosleep",
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
    "prctl", "getrandom", "eventfd2", "pipe2",
    "bpf", "perf_event_open",
    "getuid", "geteuid", "getgid", "getegid",
    "getrlimit", "setrlimit",
    "sigaltstack",
    "arch_prctl",
    "set_tid_address",
    "set_robust_list",
    "rt_sigprocmask",
    "gettimeofday",
];

pub struct SeccompFilter {
    ctx: ScmpFilterContext,
}

impl SeccompFilter {
    pub fn new(strict: bool) -> BridgeResult<Self> {
        info!("Initializing seccomp filter (strict={})", strict);

        let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Errno(libc::EPERM))
            .map_err(|e| BridgeError::Security(format!("Failed to create seccomp filter: {}", e)))?;

        for syscall_name in ALLOWED_SYSCALLS {
            let syscall = ScmpSyscall::from_name(syscall_name)
                .map_err(|e| BridgeError::Security(format!("Unknown syscall {}: {}", syscall_name, e)))?;

            ctx.add_rule(ScmpAction::Allow, syscall)
                .map_err(|e| BridgeError::Security(format!("Failed to add rule for {}: {}", syscall_name, e)))?;

            debug!("Allowed syscall: {}", syscall_name);
        }

        if strict {
            Self::apply_strict_rules(&mut ctx)?;
        }

        info!("Seccomp filter initialized successfully");
        Ok(SeccompFilter { ctx })
    }

    fn apply_strict_rules(ctx: &mut ScmpFilterContext) -> BridgeResult<()> {
        info!("Applying strict seccomp rules");

        let execve = ScmpSyscall::from_name("execve")
            .map_err(|e| BridgeError::Security(format!("Unknown syscall execve: {}", e)))?;

        ctx.add_rule(ScmpAction::Errno(libc::EPERM), execve)
            .map_err(|e| BridgeError::Security(format!("Failed to deny execve: {}", e)))?;

        let execveat = ScmpSyscall::from_name("execveat")
            .map_err(|e| BridgeError::Security(format!("Unknown syscall execveat: {}", e)))?;

        ctx.add_rule(ScmpAction::Errno(libc::EPERM), execveat)
            .map_err(|e| BridgeError::Security(format!("Failed to deny execveat: {}", e)))?;

        let fork = ScmpSyscall::from_name("fork")
            .map_err(|e| BridgeError::Security(format!("Unknown syscall fork: {}", e)))?;

        ctx.add_rule(ScmpAction::Errno(libc::EPERM), fork)
            .map_err(|e| BridgeError::Security(format!("Failed to deny fork: {}", e)))?;

        let vfork = ScmpSyscall::from_name("vfork")
            .map_err(|e| BridgeError::Security(format!("Unknown syscall vfork: {}", e)))?;

        ctx.add_rule(ScmpAction::Errno(libc::EPERM), vfork)
            .map_err(|e| BridgeError::Security(format!("Failed to deny vfork: {}", e)))?;

        let ptrace = ScmpSyscall::from_name("ptrace")
            .map_err(|e| BridgeError::Security(format!("Unknown syscall ptrace: {}", e)))?;

        ctx.add_rule(ScmpAction::Errno(libc::EPERM), ptrace)
            .map_err(|e| BridgeError::Security(format!("Failed to deny ptrace: {}", e)))?;

        let mount = ScmpSyscall::from_name("mount")
            .map_err(|e| BridgeError::Security(format!("Unknown syscall mount: {}", e)))?;

        ctx.add_rule(ScmpAction::Errno(libc::EPERM), mount)
            .map_err(|e| BridgeError::Security(format!("Failed to deny mount: {}", e)))?;

        let umount2 = ScmpSyscall::from_name("umount2")
            .map_err(|e| BridgeError::Security(format!("Unknown syscall umount2: {}", e)))?;

        ctx.add_rule(ScmpAction::Errno(libc::EPERM), umount2)
            .map_err(|e| BridgeError::Security(format!("Failed to deny umount2: {}", e)))?;

        let kexec_load = ScmpSyscall::from_name("kexec_load")
            .map_err(|e| BridgeError::Security(format!("Unknown syscall kexec_load: {}", e)))?;

        ctx.add_rule(ScmpAction::Errno(libc::EPERM), kexec_load)
            .map_err(|e| BridgeError::Security(format!("Failed to deny kexec_load: {}", e)))?;

        let init_module = ScmpSyscall::from_name("init_module")
            .map_err(|e| BridgeError::Security(format!("Unknown syscall init_module: {}", e)))?;

        ctx.add_rule(ScmpAction::Errno(libc::EPERM), init_module)
            .map_err(|e| BridgeError::Security(format!("Failed to deny init_module: {}", e)))?;

        let finit_module = ScmpSyscall::from_name("finit_module")
            .map_err(|e| BridgeError::Security(format!("Unknown syscall finit_module: {}", e)))?;

        ctx.add_rule(ScmpAction::Errno(libc::EPERM), finit_module)
            .map_err(|e| BridgeError::Security(format!("Failed to deny finit_module: {}", e)))?;

        let delete_module = ScmpSyscall::from_name("delete_module")
            .map_err(|e| BridgeError::Security(format!("Unknown syscall delete_module: {}", e)))?;

        ctx.add_rule(ScmpAction::Errno(libc::EPERM), delete_module)
            .map_err(|e| BridgeError::Security(format!("Failed to deny delete_module: {}", e)))?;

        let name_to_handle_at = ScmpSyscall::from_name("name_to_handle_at")
            .map_err(|e| BridgeError::Security(format!("Unknown syscall name_to_handle_at: {}", e)))?;

        ctx.add_rule(ScmpAction::Errno(libc::EPERM), name_to_handle_at)
            .map_err(|e| BridgeError::Security(format!("Failed to deny name_to_handle_at: {}", e)))?;

        let open_by_handle_at = ScmpSyscall::from_name("open_by_handle_at")
            .map_err(|e| BridgeError::Security(format!("Unknown syscall open_by_handle_at: {}", e)))?;

        ctx.add_rule(ScmpAction::Errno(libc::EPERM), open_by_handle_at)
            .map_err(|e| BridgeError::Security(format!("Failed to deny open_by_handle_at: {}", e)))?;

        info!("Strict seccomp rules applied successfully");
        Ok(())
    }

    pub fn apply(&mut self) -> BridgeResult<()> {
        info!("Applying seccomp filter to current process");

        self.ctx.load()
            .map_err(|e| BridgeError::Security(format!("Failed to load seccomp filter: {}", e)))?;

        info!("Seccomp filter applied successfully");
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    pub strict_seccomp: bool,
    pub namespace_isolation: bool,
    pub no_network_egress: bool,
    pub readonly_rootfs: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        SecurityPolicy {
            strict_seccomp: true,
            namespace_isolation: true,
            no_network_egress: true,
            readonly_rootfs: true,
        }
    }
}

impl SecurityPolicy {
    pub fn wasm_sandbox() -> Self {
        SecurityPolicy {
            strict_seccomp: true,
            namespace_isolation: true,
            no_network_egress: true,
            readonly_rootfs: true,
        }
    }

    pub fn daemon() -> Self {
        SecurityPolicy {
            strict_seccomp: false,
            namespace_isolation: false,
            no_network_egress: false,
            readonly_rootfs: false,
        }
    }

    pub fn validate(&self) -> BridgeResult<()> {
        if self.strict_seccomp && !self.namespace_isolation {
            warn!("Strict seccomp without namespace isolation may be insufficient");
        }

        if self.no_network_egress && !self.strict_seccomp {
            warn!("Network egress blocked without strict seccomp may be bypassed");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_policy_default() {
        let policy = SecurityPolicy::default();
        assert!(policy.strict_seccomp);
        assert!(policy.namespace_isolation);
        assert!(policy.no_network_egress);
        assert!(policy.readonly_rootfs);
    }

    #[test]
    fn test_security_policy_wasm_sandbox() {
        let policy = SecurityPolicy::wasm_sandbox();
        assert!(policy.strict_seccomp);
        assert!(policy.namespace_isolation);
        assert!(policy.no_network_egress);
        assert!(policy.readonly_rootfs);
    }

    #[test]
    fn test_security_policy_daemon() {
        let policy = SecurityPolicy::daemon();
        assert!(!policy.strict_seccomp);
        assert!(!policy.namespace_isolation);
        assert!(!policy.no_network_egress);
        assert!(!policy.readonly_rootfs);
    }

    #[test]
    fn test_security_policy_validate() {
        let policy = SecurityPolicy::default();
        assert!(policy.validate().is_ok());
    }
}
