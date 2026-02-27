// clawos-seccomp — seccomp-BPF filter for ClawOS Agent
// Implements the P1.2 frozen syscall whitelist.
//
// IMPORTANT: apply_filter() must be called AFTER cgroup join
// and BEFORE any WASM or network operations.

use anyhow::{Context, Result};
use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};
use tracing::info;

/// Apply the P1.2 frozen seccomp whitelist.
/// After this returns Ok(()), the process is locked to the whitelist.
/// Any unlisted syscall will KILL the entire process.
pub fn apply_filter() -> Result<()> {
    // Default action: kill the process on any unlisted syscall.
    let mut filter = ScmpFilterContext::new_filter(ScmpAction::KillProcess)
        .context("Failed to create seccomp filter context")?;

    for name in WHITELIST {
        let sc = ScmpSyscall::from_name(name)
            .with_context(|| format!("Unknown syscall: {name}"))?;
        filter.add_rule(ScmpAction::Allow, sc)
            .with_context(|| format!("Failed to add rule for: {name}"))?;
    }

    filter.load().context("Failed to load seccomp filter into kernel")?;

    info!(
        syscalls_allowed = WHITELIST.len(),
        "seccomp-BPF filter loaded (P1.2 whitelist v1.0)"
    );
    Ok(())
}

/// P1.2 frozen syscall whitelist.
/// Generated from spec + C-02 strace analysis.
/// DO NOT MODIFY without dual-agent review (Security + Core Dev).
const WHITELIST: &[&str] = &[
    // Memory management
    "mmap", "munmap", "mprotect", "brk", "madvise", "mlock", "munlock",
    // File IO
    "read", "write", "pread64", "pwrite64", "readv", "writev",
    "open", "openat", "openat2",
    "close", "close_range",
    "stat", "fstat", "lstat", "newfstatat", "statx",
    "lseek", "fcntl", "ioctl",
    "fsync", "fdatasync",
    "getcwd",
    // Process control
    "exit", "exit_group",
    "getpid", "getppid", "gettid",
    "getuid", "getgid", "geteuid", "getegid",
    "futex", "set_robust_list", "get_robust_list",
    "clone", "clone3",
    "wait4", "waitid",
    "prctl", "arch_prctl",
    "set_tid_address",
    // Network
    "socket", "connect", "bind",
    "recv", "send", "recvfrom", "sendto", "recvmsg", "sendmsg",
    "setsockopt", "getsockopt",
    "getsockname", "getpeername",
    "shutdown",
    "poll", "ppoll", "select", "pselect6",
    "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait",
    // Signals
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
    "rt_sigpending", "rt_sigsuspend",
    "sigaltstack", "kill", "tgkill",
    // Time
    "clock_gettime", "clock_nanosleep", "clock_getres",
    "gettimeofday", "nanosleep",
    "timer_create", "timer_settime", "timer_gettime", "timer_delete",
    // IPC
    "pipe2", "eventfd2",
    // Misc
    "getrandom", "uname",
    "getrlimit", "setrlimit", "prlimit64",
    "sysinfo", "rseq",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitelist_has_no_dangerous_syscalls() {
        let forbidden = ["ptrace", "process_vm_readv", "kexec_load",
                         "reboot", "mount", "init_module", "perf_event_open"];
        for bad in &forbidden {
            assert!(
                !WHITELIST.contains(bad),
                "DANGEROUS syscall '{bad}' found in whitelist!"
            );
        }
    }

    #[test]
    fn whitelist_has_minimum_required_syscalls() {
        let required = ["read", "write", "mmap", "exit_group",
                        "futex", "epoll_wait", "clone"];
        for req in &required {
            assert!(
                WHITELIST.contains(req),
                "Required syscall '{req}' missing from whitelist!"
            );
        }
    }
}
