// clawos-ebpf — eBPF kernel-side monitoring programs
// Implements B-01 through B-05 from the task spec.
//
// Kernel-side programs (no_std, no_main):
//   - sys_enter_execve  : tracepoint — flag any execve()
//   - sys_enter_openat  : tracepoint — detect sensitive path access
//   - file_open         : LSM hook   — enforce file access policy
//   - socket_connect    : LSM hook   — enforce network allowlist
//
// Event structs defined in specs/p1/ebpf-event-structs.rs (P1.3 frozen).

#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{tracepoint, lsm, map},
    maps::{RingBuf, HashMap},
    programs::{TracePointContext, LsmContext},
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user_str_bytes},
    EbpfContext,
};
use aya_log_ebpf::info;

// ── Shared Types (mirrors specs/p1/ebpf-event-structs.rs) ───

#[repr(u32)]
#[derive(Clone, Copy)]
enum EventKind {
    SyscallViolation     = 1,
    SuspiciousFileOpen   = 2,
    UnexpectedExecve     = 3,
    NetworkToUnknownDest = 4,
    ExcessiveSyscallRate = 5,
    PtraceAttempt        = 7,
    SecretsAccess        = 8,
    UnauthorizedWrite    = 9,
}

#[repr(u8)]
#[derive(Clone, Copy)]
enum Severity {
    Info     = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
}

#[repr(C)]
struct ClawOsEvent {
    kind:         u32,
    severity:     u8,
    _pad:         [u8; 3],
    pid:          u32,
    tgid:         u32,
    uid:          u32,
    gid:          u32,
    ppid:         u32,
    _pad2:        u32,
    timestamp_ns: u64,
    syscall_nr:   u64,
    syscall_arg0: u64,
    comm:         [u8; 16],
    details:      [u8; 176],
}

// ── eBPF Maps ─────────────────────────────────────────────────

/// Ring buffer for events → userspace anomaly engine
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0); // 4MB

/// Per-PID syscall counters for rate detection
#[map]
static SYSCALL_COUNTS: HashMap<u32, u64> = HashMap::with_max_entries(4096, 0);

// ── Tracepoints ───────────────────────────────────────────────

/// Flag every execve() — ClawOS tools should never need to exec.
#[tracepoint]
pub fn clawos_execve(ctx: TracePointContext) -> u32 {
    let pid = (unsafe { bpf_get_current_pid_tgid() } >> 32) as u32;

    if let Some(mut entry) = EVENTS.reserve::<ClawOsEvent>(0) {
        let e = unsafe { entry.as_mut_ptr().as_mut().unwrap() };
        e.kind         = EventKind::UnexpectedExecve as u32;
        e.severity     = Severity::High as u8;
        e.pid          = pid;
        e.timestamp_ns = unsafe { bpf_ktime_get_ns() };
        entry.submit(0);
    }
    0
}

/// Monitor openat() for sensitive path access.
#[tracepoint]
pub fn clawos_openat(ctx: TracePointContext) -> u32 {
    let pid = (unsafe { bpf_get_current_pid_tgid() } >> 32) as u32;

    // Read filename argument (arg1 in sys_enter_openat)
    let filename_ptr: u64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };

    let mut filename = [0u8; 128];
    if unsafe { bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut filename) }.is_err() {
        return 0;
    }

    // Check against sensitive prefix list
    let sensitive: &[&[u8]] = &[
        b"/etc/shadow",
        b"/etc/sudoers",
        b"/root/",
        b"/proc/1/",
        b"/sys/kernel/",
        b"/var/lib/clawos/secrets",
    ];

    let is_sensitive = sensitive.iter().any(|prefix| {
        filename.len() >= prefix.len() && &filename[..prefix.len()] == *prefix
    });

    if is_sensitive {
        let kind = if filename.starts_with(b"/var/lib/clawos/secrets") {
            EventKind::SecretsAccess
        } else {
            EventKind::SuspiciousFileOpen
        };

        let severity = if kind as u32 == EventKind::SecretsAccess as u32 {
            Severity::Critical
        } else {
            Severity::High
        };

        if let Some(mut entry) = EVENTS.reserve::<ClawOsEvent>(0) {
            let e = unsafe { entry.as_mut_ptr().as_mut().unwrap() };
            e.kind         = kind as u32;
            e.severity     = severity as u8;
            e.pid          = pid;
            e.timestamp_ns = unsafe { bpf_ktime_get_ns() };
            // Copy filename into details
            let copy_len = filename.len().min(175);
            e.details[..copy_len].copy_from_slice(&filename[..copy_len]);
            entry.submit(0);
        }
    }
    0
}

// ── LSM Hooks ─────────────────────────────────────────────────

/// LSM hook: enforce file open policy at kernel level.
/// Returns -1 (EPERM) to block, 0 to allow.
/// This runs BEFORE userspace AppArmor — eBPF LSM takes priority.
#[lsm(hook = "file_open")]
pub fn clawos_lsm_file_open(ctx: LsmContext) -> i32 {
    // Extract file struct from LSM context
    let file_ptr: u64 = match unsafe { ctx.read_at(0) } {
        Ok(v) => v,
        Err(_) => return 0, // On error, allow (fail-open for stability)
    };

    // Read file path (this is a simplified approach; actual path extraction
    // requires more complex eBPF operations with d_path helper)
    let mut filepath = [0u8; 256];
    let ptr = file_ptr as *const u8;
    if unsafe { bpf_probe_read_user_str_bytes(ptr, &mut filepath) }.is_ok() {
        // Check against ClawOS allowlist
        let allowed_prefixes: &[&[u8]] = &[
            b"/var/lib/clawos/",      // ClawFS data directory
            b"/proc/self/",            // Process self-access
            b"/dev/null",              // Required for WASM sandbox
            b"/dev/urandom",           // Required for crypto
            b"/etc/hosts",             // DNS resolution
            b"/tmp/",                 // WASM temporary files
        ];

        // Check if path starts with any allowed prefix
        let is_allowed = allowed_prefixes.iter().any(|prefix| {
            filepath.len() >= prefix.len() && &filepath[..prefix.len()] == *prefix
        });

        // If not in allowlist, block access (EPERM)
        if !is_allowed {
            // Emit security event for monitoring
            let pid = (unsafe { bpf_get_current_pid_tgid() } >> 32) as u32;
            if let Some(mut entry) = EVENTS.reserve::<ClawOsEvent>(0) {
                let e = unsafe { entry.as_mut_ptr().as_mut().unwrap() };
                e.kind = EventKind::UnauthorizedWrite as u32;
                e.severity = Severity::High as u8;
                e.pid = pid;
                e.timestamp_ns = unsafe { bpf_ktime_get_ns() };
                entry.submit(0);
            }
            return -1; // EPERM - Operation not permitted
        }
    }

    0 // Allow
}

/// LSM hook: enforce network connection policy.
/// Returns -1 (EPERM) to block, 0 to allow.
/// XDP filter enforces this at packet level, but LSM provides defense-in-depth.
#[lsm(hook = "socket_connect")]
pub fn clawos_lsm_socket_connect(ctx: LsmContext) -> i32 {
    // Extract socket address structure from LSM context
    let sockaddr_ptr: u64 = match unsafe { ctx.read_at(0) } {
        Ok(v) => v,
        Err(_) => return 0, // On error, allow (fail-open for stability)
    };

    // Read address family to determine IPv4 or IPv6
    let mut addr_buf = [0u8; 128]; // Max size for sockaddr_storage
    let ptr = sockaddr_ptr as *const u8;
    if unsafe { bpf_probe_read_user_str_bytes(ptr, &mut addr_buf) }.is_ok() {
        // Address family is first 2 bytes (sa_family_t)
        let sa_family = u16::from_le_bytes([addr_buf[0], addr_buf[1]]);

        // For IPv4 (AF_INET = 2), extract IP and port
        if sa_family == 2 {
            // sockaddr_in: sa_family(2) + port(2) + addr(4)
            let port_be = u16::from_be_bytes([addr_buf[2], addr_buf[3]]);
            let port = port_be.to_be(); // Convert to host byte order

            // Check against ClawOS network allowlist
            let allowed_ports: &[u16] = &[
                5432,  // PostgreSQL
                4433,  // NEAR AI bridge
                80,    // HTTP (read-only APIs)
                443,   // HTTPS (read-only APIs)
            ];

            // Allow only if port is in allowlist
            if !allowed_ports.contains(&port) {
                let pid = (unsafe { bpf_get_current_pid_tgid() } >> 32) as u32;
                if let Some(mut entry) = EVENTS.reserve::<ClawOsEvent>(0) {
                    let e = unsafe { entry.as_mut_ptr().as_mut().unwrap() };
                    e.kind = EventKind::NetworkToUnknownDest as u32;
                    e.severity = Severity::High as u8;
                    e.pid = pid;
                    e.timestamp_ns = unsafe { bpf_ktime_get_ns() };
                    // Store port in details
                    let port_str = port.to_string().as_bytes();
                    let copy_len = port_str.len().min(175);
                    e.details[..copy_len].copy_from_slice(&port_str[..copy_len]);
                    entry.submit(0);
                }
                return -1; // EPERM - Block connection
            }
        }
    }

    0 // Allow
}
/// LSM hook: enforce network connection policy.
#[lsm(hook = "socket_connect")]
pub fn clawos_lsm_socket_connect(ctx: LsmContext) -> i32 {
    // TODO P2: extract destination IP/port and verify against allowlist
    // XDP filter enforces this at packet level, but LSM provides defense-in-depth
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
