//use aya::programs::ProgramError::Btf;
use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::RingBuf,
    programs::{Lsm, TracePoint},
    Ebpf,
};
use aya_log::EbpfLogger;
use serde_json::json;
use std::{sync::Arc, time::Duration};
use tokio::{io::AsyncWriteExt, net::UnixStream, sync::Mutex};
use tracing::{debug, error, info};

mod anomaly;
use anomaly::AnomalyEngine;
mod metrics;

// FIX BUG-6: kernel-side ClawOsEvent has _final_pad: u64 (total 256 bytes),
// but the userspace mirror was missing that field (248 bytes).
// The struct mismatch caused the item.len() < EVENT_SIZE check to drop
// legitimately-sized events. Both sides are now 256 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ClawOsEvent {
    kind: u32,
    severity: u8,
    _pad: [u8; 3],
    pid: u32,
    tgid: u32,
    uid: u32,
    gid: u32,
    ppid: u32,
    _pad2: u32,
    timestamp_ns: u64,
    syscall_nr: u64,
    syscall_arg0: u64,
    comm: [u8; 16],
    details: [u8; 176],
    _final_pad: u64, // mirrors kernel-side padding; total = 256 bytes
}

// Use size_of so the constant tracks the struct automatically (FIX BUG-6).
const EVENT_SIZE: usize = core::mem::size_of::<ClawOsEvent>();
const _: () = assert!(EVENT_SIZE == 256, "ClawOsEvent size mismatch — update kernel and userspace together");

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("clawos_ebpf=info,debug")
        .json()
        .init();

    info!("ClawOS eBPF daemon starting");

    #[cfg(feature = "ebpf-embed")]
    {
        // 使用相對路徑，確保 include_bytes_aligned 獲取正確對齊的數據
        let ebpf_bytes = include_bytes_aligned!("../../../target/bpfel-unknown-none/release/clawos-ebpf");
        info!("EBPF bytes length: {}", ebpf_bytes.len());

        // 核心修正：直接使用 Ebpf::load，它會自動處理 BTF 映射
        let mut bpf = Ebpf::load(ebpf_bytes).context("Failed to load eBPF object")?;

        EbpfLogger::init(&mut bpf).ok();

        // 附加掛鉤
        attach_tracepoint(&mut bpf, "clawos_execve", "syscalls", "sys_enter_execve")?;
        attach_tracepoint(&mut bpf, "clawos_openat", "syscalls", "sys_enter_openat")?;
        attach_lsm(&mut bpf, "clawos_lsm_file_open", "file_open")?;
        attach_lsm(&mut bpf, "clawos_lsm_socket_connect", "socket_connect")?;

        info!("eBPF programs loaded and attached");

        let metrics = Arc::new(Mutex::new(metrics::ClawOsMetrics::new()));
        let metrics_clone = Arc::clone(&metrics);
        tokio::spawn(async move { metrics::serve_prometheus("127.0.0.1:9090", metrics_clone).await });

        let mut anomaly = AnomalyEngine::new();

        // 寫入 PID 文件
        let pid = std::process::id();
        tokio::fs::create_dir_all("/var/run/clawos").await.ok();
        tokio::fs::write("/var/run/clawos/ebpf.pid", pid.to_string()).await.ok();
        info!(pid, "PID file written");

        // 設置 RingBuffer
        let mut ring_buf: RingBuf<_> = bpf
            .take_map("EVENTS")
            .context("EVENTS map not found")?
            .try_into()
            .context("Failed to open ring buffer")?;

        info!("Reading eBPF ring buffer...");
        loop {
            while let Some(item) = ring_buf.next() {
                let evt = unsafe { *(item.as_ptr() as *const ClawOsEvent) };

                if item.len() < EVENT_SIZE {
                    info!("Received eBPF ring buffer: {}",item.len());
                    continue;
                }

                if item.len() >= EVENT_SIZE {
                    let comm = String::from_utf8_lossy(&evt.comm).trim_matches(char::from(0)).to_string();
                    let details = String::from_utf8_lossy(&evt.details).trim_matches(char::from(0)).to_string();
                    info!("SUCCESS! EVENT : Kind={}, PID={}, Comm={}, Details={}", evt.kind, evt.pid, comm, details);
                    //info!("SUCCESS! Event Detail: Kind={}, PID={}", evt.kind, evt.pid);
                }
                let kind = evt.kind;
                let severity = evt.severity;
                let pid = evt.pid;
                let comm = cstr(&evt.comm);

                debug!(kind, severity, pid, comm, "eBPF event received");
                metrics.lock().await.record_event(kind, severity);

                if let Some(alert) = anomaly.score(&evt) {
                    error!(kind, severity, pid, comm, score = alert.score, "ANOMALY DETECTED");
                    send_security_alert(&alert).await.ok();
                }
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    #[cfg(not(feature = "ebpf-embed"))]
    {
        warn!("eBPF bytecode not embedded - running in stub mode.");
        loop { tokio::time::sleep(Duration::from_secs(60)).await; }
    }
}

fn attach_tracepoint(bpf: &mut Ebpf, prog: &str, category: &str, name: &str) -> Result<()> {
    let program: &mut TracePoint = bpf
        .program_mut(prog)
        .with_context(|| format!("Program '{}' not found", prog))?
        .try_into()?;
    program.load()?;
    program.attach(category, name)?;
    info!(program = prog, "Tracepoint attached: {}/{}", category, name);
    Ok(())
}

fn attach_lsm(bpf: &mut Ebpf, prog: &str, hook: &str) -> Result<()> {
    let program: &mut Lsm = bpf
        .program_mut(prog)
        .with_context(|| format!("LSM program '{}' not found", prog))?
        .try_into()?;
    
    // 直接從載入後的 bpf 實例獲取 BTF 資料，不從系統重複讀取
    let btf = aya::Btf::from_sys_fs()
        .context("Failed to load BTF from /sys/kernel/btf/vmlinux")?;

    program.load(hook, &btf)?;
    program.attach()?;
    
    info!(program = prog, hook, "LSM hook attached");
    Ok(())
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

async fn send_security_alert(alert: &anomaly::Alert) -> Result<()> {
    let ipc_path = "/var/run/clawos/ipc/agent.sock";
    let mut stream = UnixStream::connect(ipc_path).await?;
    let msg = json!({
        "type": "security.alert",
        "payload": alert
    });
    stream.write_all(format!("{}\n", msg).as_bytes()).await?;
    Ok(())
}

