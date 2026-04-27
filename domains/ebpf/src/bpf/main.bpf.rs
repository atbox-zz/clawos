#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, program, tracepoint, lsm, cgroup_skb},
    maps::{RingBuffer, PerCpuArray, HashMap},
    programs::LsmContext,
    cty::{c_char, c_int, c_void, size_t},
};
use aya_log_ebpf::{error, info, warn};

mod events;

use events::{
    AnomalyEvent, SyscallTraceEvent, FileAccessEvent, NetworkEvent, CgroupEvent,
    EventType, SeverityCode, FileOperation, NetworkProtocol, NetworkDirection,
    CgroupMetricType, EventId,
};

// ============================================================================
// Maps
// ============================================================================

#[map]
pub static EVENTS: RingBuffer = RingBuffer::with_max_entries(1024 * 1024, 0);

#[map]
pub static CONFIG: PerCpuArray<Config> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static SYSCALL_COUNTS: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

#[map]
pub static FILE_ACCESS_TRACKER: HashMap<u64, FileAccessState> = HashMap::with_max_entries(4096, 0);

#[map]
pub static NETWORK_TRACKER: HashMap<u64, NetworkState> = HashMap::with_max_entries(4096, 0);

#[map]
pub static CGROUP_THRESHOLDS: HashMap<u64, CgroupThreshold> = HashMap::with_max_entries(256, 0);

// ============================================================================
// Configuration Structures
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Config {
    pub enable_syscall_tracing: u8,
    pub enable_file_monitoring: u8,
    pub enable_network_monitoring: u8,
    pub enable_cgroup_monitoring: u8,
    pub syscall_anomaly_threshold: u32,
    pub file_access_violation_mode: u8,
    pub network_suspicious_threshold: u32,
    pub reserved: [u8; 7],
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enable_syscall_tracing: 1,
            enable_file_monitoring: 1,
            enable_network_monitoring: 1,
            enable_cgroup_monitoring: 1,
            syscall_anomaly_threshold: 1000,
            file_access_violation_mode: 1,
            network_suspicious_threshold: 100,
            reserved: [0; 7],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileAccessState {
    pub pid: u32,
    pub last_access_ns: u64,
    pub access_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkState {
    pub pid: u32,
    pub connection_count: u32,
    pub last_connection_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CgroupThreshold {
    pub memory_threshold: u64,
    pub cpu_threshold: u64,
    pub io_threshold: u64,
    pub network_threshold: u64,
}

// ============================================================================
// Helper Functions
// ============================================================================

#[inline(always)]
fn get_config() -> Config {
    unsafe {
        let config_ptr = CONFIG.get(0).unwrap();
        *config_ptr
    }
}

#[inline(always)]
fn get_timestamp() -> u64 {
    unsafe {
        let mut ts: u64 = 0;
        aya_bpf::helpers::bpf_ktime_get_boot_ns(&mut ts);
        ts
    }
}

#[inline(always)]
fn get_current_pid_tgid() -> u64 {
    unsafe {
        let mut pid_tgid: u64 = 0;
        aya_bpf::helpers::bpf_get_current_pid_tgid(&mut pid_tgid);
        pid_tgid
    }
}

#[inline(always)]
fn get_pid() -> u32 {
    (get_current_pid_tgid() & 0xFFFFFFFF) as u32
}

#[inline(always)]
fn get_tid() -> u32 {
    (get_current_pid_tgid() >> 32) as u32
}

#[inline(always)]
fn get_current_uid_gid() -> u64 {
    unsafe {
        let mut uid_gid: u64 = 0;
        aya_bpf::helpers::bpf_get_current_uid_gid(&mut uid_gid);
        uid_gid
    }
}

#[inline(always)]
fn get_uid() -> u32 {
    (get_current_uid_gid() & 0xFFFFFFFF) as u32
}

#[inline(always)]
fn get_gid() -> u32 {
    (get_current_uid_gid() >> 32) as u32
}

#[inline(always)]
fn get_comm(comm: &mut [u8; 16]) {
    unsafe {
        aya_bpf::helpers::bpf_get_current_comm(comm.as_mut_ptr() as *mut c_char, 16);
    }
}

#[inline(always)]
fn copy_string(dst: &mut [u8], src: &[u8], max_len: usize) -> usize {
    let mut len = 0;
    for i in 0..max_len.min(src.len()) {
        if src[i] == 0 {
            break;
        }
        dst[i] = src[i];
        len += 1;
    }
    len
}

// ============================================================================
// Tracepoint: Syscall Monitoring
// ============================================================================

#[tracepoint(name = "sys_enter_execve")]
pub fn trace_execve_enter(ctx: TracepointContext) -> i32 {
    let config = get_config();
    if config.enable_syscall_tracing == 0 {
        return 0;
    }

    let pid = get_pid();
    let tid = get_tid();
    let uid = get_uid();
    let gid = get_gid();
    let timestamp = get_timestamp();

    let mut event = SyscallTraceEvent::default();
    event.version = 1;
    event.sysnum = 59; // __NR_execve on x86_64
    event.timestamp_ns = timestamp;
    event.pid = pid;
    event.tid = tid;
    event.return_value = 0;
    event.duration_ns = 0;
    event.arg_count = 0;

    get_comm(&mut event.comm);

    unsafe {
        EVENTS.output(&ctx, &event, 0);
    }

    0
}

#[tracepoint(name = "sys_exit_execve")]
pub fn trace_execve_exit(ctx: TracepointContext) -> i32 {
    let config = get_config();
    if config.enable_syscall_tracing == 0 {
        return 0;
    }

    let pid = get_pid();
    let tid = get_tid();
    let timestamp = get_timestamp();

    let mut event = SyscallTraceEvent::default();
    event.version = 1;
    event.sysnum = 59;
    event.timestamp_ns = timestamp;
    event.pid = pid;
    event.tid = tid;

    unsafe {
        let ret: i64 = ctx.read_at::<i64>(8).unwrap_or(0);
        event.return_value = ret;
    }

    get_comm(&mut event.comm);

    unsafe {
        EVENTS.output(&ctx, &event, 0);
    }

    0
}

#[tracepoint(name = "sys_enter_openat")]
pub fn trace_openat_enter(ctx: TracepointContext) -> i32 {
    let config = get_config();
    if config.enable_syscall_tracing == 0 {
        return 0;
    }

    let pid = get_pid();
    let tid = get_tid();
    let timestamp = get_timestamp();

    let mut event = SyscallTraceEvent::default();
    event.version = 1;
    event.sysnum = 257; // __NR_openat on x86_64
    event.timestamp_ns = timestamp;
    event.pid = pid;
    event.tid = tid;
    event.arg_count = 3;

    unsafe {
        event.args[0] = ctx.read_at::<u64>(8).unwrap_or(0); // dfd
        event.args[1] = ctx.read_at::<u64>(16).unwrap_or(0); // filename
        event.args[2] = ctx.read_at::<u64>(24).unwrap_or(0); // flags
    }

    get_comm(&mut event.comm);

    unsafe {
        EVENTS.output(&ctx, &event, 0);
    }

    0
}

#[tracepoint(name = "sys_exit_openat")]
pub fn trace_openat_exit(ctx: TracepointContext) -> i32 {
    let config = get_config();
    if config.enable_syscall_tracing == 0 {
        return 0;
    }

    let pid = get_pid();
    let tid = get_tid();
    let timestamp = get_timestamp();

    let mut event = SyscallTraceEvent::default();
    event.version = 1;
    event.sysnum = 257;
    event.timestamp_ns = timestamp;
    event.pid = pid;
    event.tid = tid;

    unsafe {
        let ret: i64 = ctx.read_at::<i64>(8).unwrap_or(0);
        event.return_value = ret;
    }

    get_comm(&mut event.comm);

    unsafe {
        EVENTS.output(&ctx, &event, 0);
    }

    0
}

// ============================================================================
// LSM Hooks: File Access Monitoring
// ============================================================================

#[lsm(name = "file_open")]
pub fn lsm_file_open(ctx: LsmContext) -> i32 {
    let config = get_config();
    if config.enable_file_monitoring == 0 {
        return 0;
    }

    let pid = get_pid();
    let tid = get_tid();
    let uid = get_uid();
    let gid = get_gid();
    let timestamp = get_timestamp();

    let mut event = FileAccessEvent::default();
    event.version = 1;
    event.timestamp_ns = timestamp;
    event.pid = pid;
    event.tid = tid;
    event.uid = uid;
    event.gid = gid;

    unsafe {
        let file_ptr = ctx.arg::<u64>(0);
        let inode_ptr = aya_bpf::helpers::bpf_probe_read_kernel(
            &mut event.inode as *mut u64 as *mut c_void,
            8,
            (file_ptr + 40) as *const c_void,
        );
        let mode_ptr = aya_bpf::helpers::bpf_probe_read_kernel(
            &mut event.mode as *mut u32 as *mut c_void,
            4,
            (file_ptr + 8) as *const c_void,
        );

        let dentry_ptr = aya_bpf::helpers::bpf_probe_read_kernel(
            &mut (0u64) as *mut u64 as *mut c_void,
            8,
            (file_ptr + 64) as *const c_void,
        );

        let dentry: u64 = 0;
        let d_inode_ptr = aya_bpf::helpers::bpf_probe_read_kernel(
            &mut (0u64) as *mut u64 as *mut c_void,
            8,
            (dentry + 16) as *const c_void,
        );

        let i_sb_ptr = aya_bpf::helpers::bpf_probe_read_kernel(
            &mut (0u64) as *mut u64 as *mut c_void,
            8,
            (d_inode_ptr + 40) as *const c_void,
        );

        let s_dev_ptr = aya_bpf::helpers::bpf_probe_read_kernel(
            &mut event.device_id as *mut u32 as *mut c_void,
            4,
            (i_sb_ptr + 24) as *const c_void,
        );

        let d_iname_ptr = aya_bpf::helpers::bpf_probe_read_kernel(
            &mut (0u64) as *mut u64 as *mut c_void,
            8,
            (dentry_ptr + 56) as *const c_void,
        );

        event.path_len = copy_string(
            &mut event.path,
            &std::slice::from_raw_parts(d_iname_ptr as *const u8, 256),
            256,
        ) as u16;
    }

    event.permission_result = 1;

    unsafe {
        EVENTS.output(&ctx, &event, 0);
    }

    0
}

// ============================================================================
// LSM Hooks: Network Monitoring
// ============================================================================

#[lsm(name = "socket_connect")]
pub fn lsm_socket_connect(ctx: LsmContext) -> i32 {
    let config = get_config();
    if config.enable_network_monitoring == 0 {
        return 0;
    }

    let pid = get_pid();
    let tid = get_tid();
    let timestamp = get_timestamp();

    let mut event = NetworkEvent::default();
    event.version = 1;
    event.timestamp_ns = timestamp;
    event.pid = pid;
    event.tid = tid;
    event.direction = NetworkDirection::Outbound as u8;

    unsafe {
        let sock_ptr = ctx.arg::<u64>(0);
        let address_ptr = ctx.arg::<u64>(1);
        let addrlen_ptr = ctx.arg::<u64>(2);

        let family: u16 = 0;
        aya_bpf::helpers::bpf_probe_read_kernel(
            &mut family as *mut u16 as *mut c_void,
            2,
            address_ptr as *const c_void,
        );

        if family == 2 {
            event.is_ipv4 = 1;
            event.protocol = NetworkProtocol::Tcp as u8;

            let sin_addr_ptr = address_ptr + 4;
            aya_bpf::helpers::bpf_probe_read_kernel(
                event.dst_ip.as_mut_ptr() as *mut c_void,
                4,
                sin_addr_ptr as *const c_void,
            );

            let sin_port_ptr = address_ptr + 2;
            let port: u16 = 0;
            aya_bpf::helpers::bpf_probe_read_kernel(
                &mut port as *mut u16 as *mut c_void,
                2,
                sin_port_ptr as *const c_void,
            );
            event.dst_port = u16::from_be(port);
        } else if family == 10 {
            event.is_ipv4 = 0;
            event.protocol = NetworkProtocol::Tcp as u8;

            let sin6_addr_ptr = address_ptr + 8;
            aya_bpf::helpers::bpf_probe_read_kernel(
                event.dst_ip.as_mut_ptr() as *mut c_void,
                16,
                sin6_addr_ptr as *const c_void,
            );

            let sin6_port_ptr = address_ptr + 2;
            let port: u16 = 0;
            aya_bpf::helpers::bpf_probe_read_kernel(
                &mut port as *mut u16 as *mut c_void,
                2,
                sin6_port_ptr as *const c_void,
            );
            event.dst_port = u16::from_be(port);
        }
    }

    unsafe {
        EVENTS.output(&ctx, &event, 0);
    }

    0
}

// ============================================================================
// Cgroup Hooks: Resource Monitoring
// ============================================================================

#[cgroup_skb(name = "cgroup_skb_ingress")]
pub fn cgroup_skb_ingress(ctx: CgroupSkbContext) -> i32 {
    let config = get_config();
    if config.enable_cgroup_monitoring == 0 {
        return 0;
    }

    let pid = get_pid();
    let tid = get_tid();
    let timestamp = get_timestamp();

    let mut event = NetworkEvent::default();
    event.version = 1;
    event.timestamp_ns = timestamp;
    event.pid = pid;
    event.tid = tid;
    event.direction = NetworkDirection::Inbound as u8;

    unsafe {
        let skb_ptr = ctx.skb();
        let len: u32 = 0;
        aya_bpf::helpers::bpf_probe_read_kernel(
            &mut len as *mut u32 as *mut c_void,
            4,
            (skb_ptr + 96) as *const c_void,
        );
        event.packet_size = len;

        let protocol: u8 = 0;
        aya_bpf::helpers::bpf_probe_read_kernel(
            &mut protocol as *mut u8 as *mut c_void,
            1,
            (skb_ptr + 49) as *const c_void,
        );

        match protocol {
            6 => event.protocol = NetworkProtocol::Tcp as u8,
            17 => event.protocol = NetworkProtocol::Udp as u8,
            1 => event.protocol = NetworkProtocol::Icmp as u8,
            58 => event.protocol = NetworkProtocol::IcmpV6 as u8,
            _ => event.protocol = NetworkProtocol::Unknown as u8,
        }
    }

    unsafe {
        EVENTS.output(&ctx, &event, 0);
    }

    0
}

#[cgroup_skb(name = "cgroup_skb_egress")]
pub fn cgroup_skb_egress(ctx: CgroupSkbContext) -> i32 {
    let config = get_config();
    if config.enable_cgroup_monitoring == 0 {
        return 0;
    }

    let pid = get_pid();
    let tid = get_tid();
    let timestamp = get_timestamp();

    let mut event = NetworkEvent::default();
    event.version = 1;
    event.timestamp_ns = timestamp;
    event.pid = pid;
    event.tid = tid;
    event.direction = NetworkDirection::Outbound as u8;

    unsafe {
        let skb_ptr = ctx.skb();
        let len: u32 = 0;
        aya_bpf::helpers::bpf_probe_read_kernel(
            &mut len as *mut u32 as *mut c_void,
            4,
            (skb_ptr + 96) as *const c_void,
        );
        event.packet_size = len;

        let protocol: u8 = 0;
        aya_bpf::helpers::bpf_probe_read_kernel(
            &mut protocol as *mut u8 as *mut c_void,
            1,
            (skb_ptr + 49) as *const c_void,
        );

        match protocol {
            6 => event.protocol = NetworkProtocol::Tcp as u8,
            17 => event.protocol = NetworkProtocol::Udp as u8,
            1 => event.protocol = NetworkProtocol::Icmp as u8,
            58 => event.protocol = NetworkProtocol::IcmpV6 as u8,
            _ => event.protocol = NetworkProtocol::Unknown as u8,
        }
    }

    unsafe {
        EVENTS.output(&ctx, &event, 0);
    }

    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
