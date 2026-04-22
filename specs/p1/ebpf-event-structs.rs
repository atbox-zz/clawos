// ============================================================
// ClawOS eBPF Event Struct Definitions — FROZEN v1.0 (P1.3)
// ============================================================
// DO NOT MODIFY without dual-agent review (eBPF + Observability).
// Shared between: clawos-ebpf (kernel side) and clawos-monitor (userspace).
// Any field change is a BREAKING CHANGE → bump CLAWOS_EBPF_ABI_VERSION.
// ============================================================

pub const CLAWOS_EBPF_ABI_VERSION: u32 = 1;

/// Discriminant for all events flowing through the Ring Buffer.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// A syscall not on the whitelist was attempted (seccomp pre-trigger)
    SyscallViolation      = 1,
    /// open()/openat() on a path matching the sensitive-path list
    SuspiciousFileOpen    = 2,
    /// execve() called — always flagged, always reviewed
    UnexpectedExecve      = 3,
    /// Network connection to a destination not in the allowlist
    NetworkToUnknownDest  = 4,
    /// Per-process syscall rate exceeded threshold (fork bomb / loop)
    ExcessiveSyscallRate  = 5,
    /// WASM worker memory usage spiked above its cgroup soft limit
    WasmMemorySpike       = 6,
    /// Process tried to ptrace another process
    PtraceAttempt         = 7,
    /// File in /var/lib/clawos/secrets was opened
    SecretsAccess         = 8,
    /// A file was written outside the allowed write paths
    UnauthorizedWrite     = 9,
    /// Process attempted a forbidden capability (e.g. CAP_SYS_ADMIN)
    CapabilityViolation   = 10,
}

/// Severity used by the userspace Anomaly Engine for triage.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info     = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
}

/// Primary event — all fields are fixed-size for lock-free Ring Buffer reads.
/// Total size: 256 bytes (cache-line aligned × 4).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ClawOsEvent {
    // ── Identity ──────────────────────────────── (16 bytes)
    pub kind:           EventKind,      // u32 — what happened
    pub severity:       Severity,       // u8
    pub _pad:           [u8; 3],        // alignment padding

    // ── Process context ───────────────────────── (24 bytes)
    pub pid:            u32,
    pub tgid:           u32,
    pub uid:            u32,
    pub gid:            u32,
    pub ppid:           u32,
    pub _pad2:          u32,

    // ── Timing ────────────────────────────────── (8 bytes)
    pub timestamp_ns:   u64,            // bpf_ktime_get_ns()

    // ── Syscall context (if applicable) ──────── (16 bytes)
    pub syscall_nr:     u64,
    pub syscall_arg0:   u64,

    // ── Process name ──────────────────────────── (16 bytes)
    pub comm:           [u8; 16],       // task->comm, null-terminated

    // ── Detail payload ────────────────────────── (176 bytes)
    /// Interpretation depends on `kind`:
    /// - SuspiciousFileOpen / UnauthorizedWrite: file path (null-terminated)
    /// - NetworkToUnknownDest: "ip:port\0"
    /// - ExcessiveSyscallRate: syscall name + rate as ASCII
    /// - All others: human-readable description
    pub details:        [u8; 176],
}

impl ClawOsEvent {
    /// Size must remain exactly 256 bytes — verified by test below.
    pub const SIZE: usize = 256;

    pub fn details_str(&self) -> &str {
        let end = self.details.iter().position(|&b| b == 0).unwrap_or(176);
        core::str::from_utf8(&self.details[..end]).unwrap_or("<invalid utf8>")
    }

    pub fn comm_str(&self) -> &str {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
        core::str::from_utf8(&self.comm[..end]).unwrap_or("<?>")
    }
}

/// Sliding-window counter event — sent periodically by the rate-monitor hook.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RateEvent {
    pub pid:            u32,
    pub syscall_nr:     u32,
    pub count_per_sec:  u64,
    pub timestamp_ns:   u64,
    pub threshold:      u64,            // from config, for context
}

/// eBPF map keys for per-process state tracking.
#[repr(C)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct ProcessKey {
    pub pid:  u32,
    pub tgid: u32,
}

// ── Compile-time size assertion ─────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_size_is_256_bytes() {
        assert_eq!(
            core::mem::size_of::<ClawOsEvent>(),
            ClawOsEvent::SIZE,
            "ClawOsEvent must be exactly 256 bytes — ABI is frozen at v1.0"
        );
    }

    #[test]
    fn event_kind_variants_stable() {
        // Discriminant values are part of the frozen ABI.
        assert_eq!(EventKind::SyscallViolation   as u32, 1);
        assert_eq!(EventKind::SuspiciousFileOpen as u32, 2);
        assert_eq!(EventKind::UnexpectedExecve   as u32, 3);
        assert_eq!(EventKind::NetworkToUnknownDest as u32, 4);
        assert_eq!(EventKind::ExcessiveSyscallRate as u32, 5);
    }
}
