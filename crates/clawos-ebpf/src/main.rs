// clawos-ebpf — eBPF kernel-side monitoring programs
#![allow(dead_code)]
#![no_std]
#![no_main]

mod lsm;
mod xdp;

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user_str_bytes},
    macros::{lsm, map, tracepoint},
    maps::HashMap,
    maps::RingBuf,
    programs::{LsmContext,TracePointContext},
//    EbpfContext,
};
//use aya_log_ebpf::info;
// ── Shared Types ─────────────────────────────────────────────
#[repr(u32)]
#[derive(Clone, Copy)]
pub enum EventKind {
    SyscallViolation     = 1,
    SuspiciousFileOpen   = 2,
    UnexpectedExecve     = 3,
    NetworkToUnknownDest = 4,
    ExcessiveSyscallRate = 5,
    WasmMemorySpike      = 6,
    PtraceAttempt        = 7,
    SecretsAccess        = 8,
    UnauthorizedWrite    = 9,
    CapabilityViolation  = 10,
}

#[repr(u8)]
pub enum Severity {
    Info     = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
}

#[repr(C)]
pub struct ClawOsEvent {
    pub kind: u32,
    pub severity: u8,
    pub _pad: [u8; 3],
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub ppid: u32,
    pub _pad2: u32,
    pub timestamp_ns: u64,
    pub syscall_nr: u64,
    pub syscall_arg0: u64,
    pub comm: [u8; 16],
    pub details: [u8; 176],
    pub _final_pad: u64, //加上這 8 bytes，248+8=256
}

// ── eBPF Maps ─────────────────────────────────────────────────

#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

static SYSCALL_COUNTS: HashMap<u32, u64> = HashMap::with_max_entries(4096, 0);

// ── Tracepoints ───────────────────────────────────────────────

//#[tracepoint]
#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn clawos_execve(_ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    if let Some(mut entry) = EVENTS.reserve::<ClawOsEvent>(0) {
        let e              = unsafe { entry.as_mut_ptr().as_mut().unwrap() };
        e.kind             = EventKind::UnexpectedExecve as u32;
        e.severity         = Severity::High as u8;
        e.pid              = pid;
        e.timestamp_ns     = unsafe { bpf_ktime_get_ns() };
        entry.submit(0);
    }
    0
}
//#[tracepoint]
#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
pub fn clawos_openat(ctx: TracePointContext) -> u32 {
    let filename_ptr: u64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let mut filename = [0u8; 64];
    if unsafe { bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut filename) }.is_err() {
        return 0;
    }
    let sensitive: &[&[u8]] = &[
        b"/etc/shadow",
        b"/etc/sudoers",
        b"/root/",
        b"/proc/1/",
        b"/sys/kernel/",
        b"/var/lib/clawos/secrets",
    ];
    let is_sensitive = sensitive
        .iter()
        .any(|prefix| filename.len() >= prefix.len() && &filename[..prefix.len()] == *prefix);
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
            e.kind = kind as u32;
            e.severity = severity as u8;
            // 獲取當前 PID 和 TGID (上位 32 位是 PID)
            let pid_tgid = bpf_get_current_pid_tgid();
            let pid = (pid_tgid >> 32) as u32; // 提取 PID

            e.pid = pid;
            e.timestamp_ns = unsafe { bpf_ktime_get_ns() };
            let copy_len = filename.len().min(63);
            e.details[..copy_len].copy_from_slice(&filename[..copy_len]);
            entry.submit(0);
        }
    }
    0
}
pub use lsm::clawos_lsm_file_open;
pub use lsm::clawos_lsm_socket_connect;
pub use xdp::clawos_xdp_filter;
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
