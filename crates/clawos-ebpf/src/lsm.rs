// crates/clawos-ebpf/src/lsm.rs
// eBPF LSM hooks — file_open + socket_connect
//
// file_open strategy (FIX BUG-1):
//   bpf_d_path requires *mut path, but the LSM context gives us *mut file.
//   Even though f_path sits at offset 0, the verifier does TYPE checking,
//   not address checking — the cast is rejected at load time.
//   Solution: do NOT use bpf_d_path here.
//
//   Path-prefix rules (/etc/shadow, /proc/*/mem, /sys/kernel/, …) are
//   handled by the clawos_openat tracepoint in main.rs which reads the
//   raw userspace filename string via bpf_probe_read_user_str — no type
//   conflict, verifier is happy.
//
//   This hook's sole responsibility: deny by LEAF NAME as a last-resort
//   backstop (catches renames/bind-mounts that bypass the openat path).
//
// socket_connect strategy (FIX SEC-2):
//   AF_INET6 (10): loopback ::1 and port 443 allowed, all else denied.
//   AF_INET  (2):  loopback, ClawFS host, and port 443 allowed.
//   AF_UNIX  (1):  allowed — IPC inside the sandbox is fine.
//   AF_NETLINK (16): denied — no kernel netlink access from WASM tools.
//   All other families: denied (fail-closed).

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::lsm,
    programs::LsmContext,
};
use aya_log_ebpf::warn;
use core::ffi::c_int;

const EPERM: c_int = -1;
const ALLOW: c_int = 0;

// ── file_open ─────────────────────────────────────────────────

#[lsm(hook = "file_open")]
pub fn clawos_lsm_file_open(ctx: LsmContext) -> i32 {
    try_lsm_file_open(&ctx)
}

fn try_lsm_file_open(ctx: &LsmContext) -> i32 {
    let file_ptr: usize = unsafe { ctx.arg(0) };
    if file_ptr == 0 {
        return ALLOW;
    }

    // Read dentry pointer from file->f_path.dentry (offset 8 — stable since Linux 3.x)
    let dentry_ptr: u64 =
        unsafe { bpf_probe_read_kernel((file_ptr + 8) as *const u64).unwrap_or(0) };
    if dentry_ptr == 0 {
        return ALLOW;
    }

    // Read d_name.name pointer from dentry->d_name (qstr.name at offset +48)
    let name_ptr: u64 =
        unsafe { bpf_probe_read_kernel((dentry_ptr as usize + 48) as *const u64).unwrap_or(0) };
    if name_ptr == 0 {
        return ALLOW;
    }

    // Read up to 32 bytes of the leaf filename
    let name: [u8; 32] =
        unsafe { bpf_probe_read_kernel(name_ptr as *const [u8; 32]).unwrap_or([0u8; 32]) };

    // Blocked leaf names — complements the prefix rules in clawos_openat.
    // Keep this list in sync with the openat prefix list.
    let blocked: &[&[u8]] = &[
        b"shadow",
        b"sudoers",
        b"authorized_keys",
        b"id_rsa",
        b"id_ed25519",
        b"id_ecdsa",
        b"id_dsa",
        b"mem",   // /proc/<pid>/mem
        b"maps",  // /proc/<pid>/maps
    ];

    let leaf_len = name.iter().position(|&b| b == 0).unwrap_or(32);
    let is_blocked = blocked
        .iter()
        .any(|bl| leaf_len == bl.len() && &name[..leaf_len] == *bl);

    if is_blocked {
        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        warn!(ctx, "LSM DENY file_open pid={} leaf blocked", pid);

        if let Some(mut entry) = super::EVENTS.reserve::<super::ClawOsEvent>(0) {
            let e = unsafe { entry.as_mut_ptr().as_mut().unwrap() };
            e.kind = super::EventKind::SuspiciousFileOpen as u32;
            e.severity = super::Severity::High as u8;
            e.pid = pid;
            e.timestamp_ns = unsafe { bpf_ktime_get_ns() };
            let copy_len = leaf_len.min(e.details.len());
            e.details[..copy_len].copy_from_slice(&name[..copy_len]);
            entry.submit(0);
        }

        return EPERM;
    }

    ALLOW
}

// ── socket_connect ────────────────────────────────────────────

#[lsm(hook = "socket_connect")]
pub fn clawos_lsm_socket_connect(ctx: LsmContext) -> i32 {
    match try_lsm_socket_connect(&ctx) {
        Ok(ret) => ret,
        Err(_) => EPERM, // fail-closed (H-01)
    }
}

fn try_lsm_socket_connect(ctx: &LsmContext) -> Result<i32, i64> {
    let sockaddr_ptr: usize = unsafe { ctx.arg(1) };
    let addrlen: u32 = unsafe { ctx.arg(2) };

    if sockaddr_ptr == 0 || addrlen < 2 {
        return Ok(ALLOW);
    }

    let sa_family: u16 =
        unsafe { bpf_probe_read_kernel(sockaddr_ptr as *const u16).unwrap_or(0) };

    match sa_family {
        // AF_UNIX (1) — intra-sandbox IPC, always allow
        1 => Ok(ALLOW),

        // AF_INET (2) — IPv4
        2 => {
            if addrlen < 8 {
                return Ok(EPERM);
            }
            let sin_port: u16 = unsafe {
                bpf_probe_read_kernel((sockaddr_ptr + 2) as *const u16).unwrap_or(0)
            };
            let sin_addr: u32 = unsafe {
                bpf_probe_read_kernel((sockaddr_ptr + 4) as *const u32).unwrap_or(0)
            };
            let port = u16::from_be(sin_port);
            let addr = u32::from_be(sin_addr);

            // Loopback 127.x.x.x
            if addr >> 24 == 127 {
                return Ok(ALLOW);
            }
            // ClawFS host: 10.100.0.1 port 5432
            if addr == 0x0A640001 && port == 5432 {
                return Ok(ALLOW);
            }
            // HTTPS — actual host enforced by iptables allowlist
            if port == 443 {
                return Ok(ALLOW);
            }

            let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            warn!(ctx, "LSM DENY socket_connect(AF_INET) pid={} addr={} port={}", pid, addr, port);
            emit_network_event(pid, addr.to_le_bytes(), port);
            Ok(EPERM)
        }

        // AF_INET6 (10) — IPv6 (FIX SEC-2: was missing, fell through to AF_INET path)
        10 => {
            if addrlen < 28 {
                return Ok(EPERM);
            }
            let addr_hi: u64 = unsafe {
                bpf_probe_read_kernel((sockaddr_ptr + 8) as *const u64).unwrap_or(0)
            };
            let addr_lo: u64 = unsafe {
                bpf_probe_read_kernel((sockaddr_ptr + 16) as *const u64).unwrap_or(0)
            };
            // ::1 loopback
            if addr_hi == 0 && addr_lo == 1u64.to_be() {
                return Ok(ALLOW);
            }
            let sin6_port: u16 = unsafe {
                bpf_probe_read_kernel((sockaddr_ptr + 2) as *const u16).unwrap_or(0)
            };
            let port6 = u16::from_be(sin6_port);
            if port6 == 443 {
                return Ok(ALLOW);
            }

            let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            warn!(ctx, "LSM DENY socket_connect(AF_INET6) pid={} port={}", pid, port6);
            Ok(EPERM)
        }

        // AF_NETLINK (16) — deny; no kernel netlink from WASM tools (FIX SEC-2)
        16 => {
            let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            warn!(ctx, "LSM DENY socket_connect(AF_NETLINK) pid={}", pid);
            Ok(EPERM)
        }

        // All other families — fail-closed (FIX SEC-2)
        family => {
            let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            warn!(ctx, "LSM DENY socket_connect unknown family={} pid={}", family, pid);
            Ok(EPERM)
        }
    }
}

fn emit_network_event(pid: u32, addr_bytes: [u8; 4], port: u16) {
    if let Some(mut entry) = super::EVENTS.reserve::<super::ClawOsEvent>(0) {
        let e = unsafe { entry.as_mut_ptr().as_mut().unwrap() };
        e.kind = super::EventKind::NetworkToUnknownDest as u32;
        e.severity = super::Severity::High as u8;
        e.pid = pid;
        e.timestamp_ns = unsafe { bpf_ktime_get_ns() };
        e.details[0..4].copy_from_slice(&addr_bytes);
        e.details[4..6].copy_from_slice(&port.to_le_bytes());
        entry.submit(0);
    }
}
