use aya::{
    include_bytes_aligned,
    maps::{RingBuffer, PerCpuArray, HashMap},
    programs::{Lsm, TracePoint, CgroupSkb},
    Bpf, Btf,
};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn, error};
use tokio::signal;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

mod events;
mod bpf;

use events::{
    AnomalyEvent, SyscallTraceEvent, FileAccessEvent, NetworkEvent, CgroupEvent,
    EventType, SeverityCode, FileOperation, NetworkProtocol, NetworkDirection,
    CgroupMetricType, EventId,
};

use bpf::main::Config;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::init();

    info!("ClawOS eBPF Agent starting...");

    let bpf = load_bpf_program()?;

    let mut bpf = attach_programs(bpf)?;

    configure_programs(&mut bpf)?;

    let mut ring_buffer = create_ring_buffer(&bpf)?;

    info!("eBPF programs loaded and attached successfully");
    info!("Starting event processing loop...");

    let ctrl_c = signal::ctrl_c();
    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, shutting down...");
        }
        _ = process_events(&mut ring_buffer) => {
            info!("Event processing loop ended");
        }
    }

    Ok(())
}

fn load_bpf_program() -> Result<Bpf> {
    #[cfg(debug_assertions)]
    let bpf = Bpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/release/clawos-ebpf"))?;

    #[cfg(not(debug_assertions))]
    let bpf = Bpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/release/clawos-ebpf"))?;

    if let Err(e) = BpfLogger::init(&bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    Ok(bpf)
}

fn attach_programs(mut bpf: Bpf) -> Result<Bpf> {
    info!("Attaching tracepoint programs...");

    let program: &mut TracePoint = bpf.program_mut("trace_execve_enter")
        .context("Failed to get trace_execve_enter program")?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")
        .context("Failed to attach trace_execve_enter")?;

    let program: &mut TracePoint = bpf.program_mut("trace_execve_exit")
        .context("Failed to get trace_execve_exit program")?;
    program.load()?;
    program.attach("syscalls", "sys_exit_execve")
        .context("Failed to attach trace_execve_exit")?;

    let program: &mut TracePoint = bpf.program_mut("trace_openat_enter")
        .context("Failed to get trace_openat_enter program")?;
    program.load()?;
    program.attach("syscalls", "sys_enter_openat")
        .context("Failed to attach trace_openat_enter")?;

    let program: &mut TracePoint = bpf.program_mut("trace_openat_exit")
        .context("Failed to get trace_openat_exit program")?;
    program.load()?;
    program.attach("syscalls", "sys_exit_openat")
        .context("Failed to attach trace_openat_exit")?;

    info!("Attaching LSM programs...");

    let program: &mut Lsm = bpf.program_mut("lsm_file_open")
        .context("Failed to get lsm_file_open program")?;
    program.load()?;
    program.attach()
        .context("Failed to attach lsm_file_open")?;

    let program: &mut Lsm = bpf.program_mut("lsm_socket_connect")
        .context("Failed to get lsm_socket_connect program")?;
    program.load()?;
    program.attach()
        .context("Failed to attach lsm_socket_connect")?;

    info!("Attaching cgroup programs...");

    let cgroup_path = "/sys/fs/cgroup";
    if !Path::new(cgroup_path).exists() {
        warn!("Cgroup v2 path {} does not exist, skipping cgroup programs", cgroup_path);
    } else {
        let program: &mut CgroupSkb = bpf.program_mut("cgroup_skb_ingress")
            .context("Failed to get cgroup_skb_ingress program")?;
        program.load()?;
        program.attach(cgroup_path, aya::programs::CgroupSkbAttachType::Ingress)
            .context("Failed to attach cgroup_skb_ingress")?;

        let program: &mut CgroupSkb = bpf.program_mut("cgroup_skb_egress")
            .context("Failed to get cgroup_skb_egress program")?;
        program.load()?;
        program.attach(cgroup_path, aya::programs::CgroupSkbAttachType::Egress)
            .context("Failed to attach cgroup_skb_egress")?;
    }

    Ok(bpf)
}

fn configure_programs(bpf: &mut Bpf) -> Result<()> {
    info!("Configuring eBPF programs...");

    let mut config_map: PerCpuArray<Config> = bpf.map_mut("CONFIG")
        .context("Failed to get CONFIG map")?;

    let config = Config::default();
    config_map.set(0, config, 0)
        .context("Failed to set CONFIG")?;

    info!("Configuration applied successfully");

    Ok(())
}

fn create_ring_buffer(bpf: &Bpf) -> Result<RingBuffer> {
    let events_map: &RingBuffer = bpf.map("EVENTS")
        .context("Failed to get EVENTS map")?;

    let ring_buffer = RingBuffer::from(events_map)
        .context("Failed to create ring buffer")?;

    Ok(ring_buffer)
}

async fn process_events(ring_buffer: &mut RingBuffer) -> Result<()> {
    let mut event_count = 0u64;
    let mut last_stats = std::time::Instant::now();

    loop {
        match ring_buffer.read::<u8, _>(|data| {
            if data.len() < 12 {
                warn!("Received event too short: {} bytes", data.len());
                return 0;
            }

            let event_id = data[1];
            let timestamp = u64::from_le_bytes([
                data[4], data[5], data[6], data[7],
                data[8], data[9], data[10], data[11],
            ]);

            match event_id {
                1 => handle_anomaly_event(data),
                2 => handle_syscall_trace_event(data),
                3 => handle_file_access_event(data),
                4 => handle_network_event(data),
                5 => handle_cgroup_event(data),
                _ => warn!("Unknown event ID: {}", event_id),
            }

            event_count += 1;
            0
        }, Duration::from_secs(1)) {
            Ok(_) => {}
            Err(e) => {
                if e.kind() != std::io::ErrorKind::TimedOut {
                    error!("Error reading from ring buffer: {}", e);
                }
            }
        }

        if last_stats.elapsed() >= Duration::from_secs(10) {
            info!("Processed {} events in last 10 seconds", event_count);
            event_count = 0;
            last_stats = std::time::Instant::now();
        }
    }
}

fn handle_anomaly_event(data: &[u8]) {
    if data.len() < std::mem::size_of::<AnomalyEvent>() {
        warn!("AnomalyEvent too short: {} bytes", data.len());
        return;
    }

    let event: AnomalyEvent = unsafe { std::ptr::read(data.as_ptr() as *const AnomalyEvent) };

    if event.version != 1 {
        warn!("AnomalyEvent has invalid version: {}", event.version);
        return;
    }

    let event_type = event.get_event_type();
    let severity = event.get_severity();
    let description = event.description_str();

    info!(
        "[ANOMALY] pid={} tid={} type={:?} severity={:?} description={}",
        event.pid, event.tid, event_type, severity, description
    );

    if severity >= SeverityCode::High {
        warn!(
            "HIGH SEVERITY ANOMALY: pid={} type={:?} {}",
            event.pid, event_type, description
        );
    }
}

fn handle_syscall_trace_event(data: &[u8]) {
    if data.len() < std::mem::size_of::<SyscallTraceEvent>() {
        warn!("SyscallTraceEvent too short: {} bytes", data.len());
        return;
    }

    let event: SyscallTraceEvent = unsafe { std::ptr::read(data.as_ptr() as *const SyscallTraceEvent) };

    if event.version != 1 {
        warn!("SyscallTraceEvent has invalid version: {}", event.version);
        return;
    }

    let comm = event.comm_str();

    info!(
        "[SYSCALL] pid={} tid={} sysnum={} comm={} ret={} duration_ns={}",
        event.pid, event.tid, event.sysnum, comm, event.return_value, event.duration_ns
    );

    if event.return_value < 0 {
        warn!(
            "SYSCALL FAILED: pid={} sysnum={} comm={} ret={}",
            event.pid, event.sysnum, comm, event.return_value
        );
    }
}

fn handle_file_access_event(data: &[u8]) {
    if data.len() < std::mem::size_of::<FileAccessEvent>() {
        warn!("FileAccessEvent too short: {} bytes", data.len());
        return;
    }

    let event: FileAccessEvent = unsafe { std::ptr::read(data.as_ptr() as *const FileAccessEvent) };

    if event.version != 1 {
        warn!("FileAccessEvent has invalid version: {}", event.version);
        return;
    }

    let operation = event.get_operation();
    let path = event.path_str();

    info!(
        "[FILE] pid={} tid={} operation={:?} path={} granted={}",
        event.pid, event.tid, operation, path, event.is_granted()
    );

    if !event.is_granted() {
        warn!(
            "FILE ACCESS DENIED: pid={} operation={:?} path={}",
            event.pid, operation, path
        );
    }
}

fn handle_network_event(data: &[u8]) {
    if data.len() < std::mem::size_of::<NetworkEvent>() {
        warn!("NetworkEvent too short: {} bytes", data.len());
        return;
    }

    let event: NetworkEvent = unsafe { std::ptr::read(data.as_ptr() as *const NetworkEvent) };

    if event.version != 1 {
        warn!("NetworkEvent has invalid version: {}", event.version);
        return;
    }

    let protocol = event.get_protocol();
    let direction = event.get_direction();
    let src_ip = event.src_ip_str();
    let dst_ip = event.dst_ip_str();

    info!(
        "[NETWORK] pid={} tid={} protocol={:?} direction={:?} {}:{} -> {}:{} size={}",
        event.pid, event.tid, protocol, direction,
        src_ip, event.src_port, dst_ip, event.dst_port, event.packet_size
    );

    if direction == NetworkDirection::Outbound && event.dst_port < 1024 {
        warn!(
            "OUTBOUND CONNECTION TO PRIVILEGED PORT: pid={} {}:{}",
            event.pid, dst_ip, event.dst_port
        );
    }
}

fn handle_cgroup_event(data: &[u8]) {
    if data.len() < std::mem::size_of::<CgroupEvent>() {
        warn!("CgroupEvent too short: {} bytes", data.len());
        return;
    }

    let event: CgroupEvent = unsafe { std::ptr::read(data.as_ptr() as *const CgroupEvent) };

    if event.version != 1 {
        warn!("CgroupEvent has invalid version: {}", event.version);
        return;
    }

    let metric_type = event.get_metric_type();
    let cgroup_path = event.cgroup_path_str();

    info!(
        "[CGROUP] cgroup_id={} metric={:?} value={} threshold={} pid_count={} path={}",
        event.cgroup_id, metric_type, event.value, event.threshold, event.pid_count, cgroup_path
    );

    if event.is_alert() {
        warn!(
            "CGROUP THRESHOLD EXCEEDED: cgroup={} metric={:?} value={} threshold={}",
            cgroup_path, metric_type, event.value, event.threshold
        );
    }
}
