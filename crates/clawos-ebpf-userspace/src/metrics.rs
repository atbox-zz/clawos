// crates/clawos-ebpf-userspace/src/metrics.rs
//
// Prometheus metrics — B-06
// Exposes ClawOS eBPF telemetry on :9090/metrics
// Labels: event_kind, severity, pid_comm

use anyhow::Result;
use axum::{routing::get, Router};
use prometheus_client::{
    encoding::text::encode,
    metrics::{counter::Counter, family::Family, gauge::Gauge},
    registry::Registry,
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct EventLabels {
    kind: String,
    severity: String,
}

pub struct ClawOsMetrics {
    registry: Registry,
    event_total: Family<EventLabels, Counter>,
    active_alerts: Gauge,
    queue_depth: Gauge,
    recent_window: HashMap<u32, u64>,
}

impl ClawOsMetrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();

        let event_total = Family::<EventLabels, Counter>::default();
        registry.register(
            "clawos_ebpf_events_total",
            "Total eBPF events observed by kind and severity",
            event_total.clone(),
        );

        let active_alerts = Gauge::default();
        registry.register(
            "clawos_active_alerts",
            "Number of currently active security alerts",
            active_alerts.clone(),
        );

        let queue_depth = Gauge::default();
        registry.register(
            "clawos_agent_queue_depth",
            "Current agent job queue depth",
            queue_depth.clone(),
        );

        Self {
            registry,
            event_total,
            active_alerts,
            queue_depth,
            recent_window: HashMap::new(),
        }
    }

    pub fn record_event(&mut self, kind: u32, severity: u8) {
        let labels = EventLabels {
            kind: kind_name(kind),
            severity: severity_name(severity),
        };
        self.event_total.get_or_create(&labels).inc();
        *self.recent_window.entry(kind).or_default() += 1;
    }
    pub fn set_queue_depth(&mut self, depth: i64) {
        self.queue_depth.set(depth);
    }

    pub fn inc_alerts(&mut self) {
        self.active_alerts.inc();
    }

    pub fn dec_alerts(&mut self) {
        self.active_alerts.dec();
    }
    pub fn render(&self) -> String {
        let mut out = String::new();
        encode(&mut out, &self.registry).unwrap_or_default();
        out
    }
}

pub async fn serve_prometheus(addr: &str, metrics: Arc<Mutex<ClawOsMetrics>>) -> Result<()> {
    let app = Router::new()
        .route(
            "/metrics",
            get(move || {
                let metrics = Arc::clone(&metrics);
                async move { metrics.lock().await.render() }
            }),
        )
        .route("/healthz", get(|| async { "ok" }));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(addr, "Prometheus metrics server listening");
    axum::serve(listener, app).await?;
    Ok(())
}

fn kind_name(k: u32) -> String {
    match k {
        1 => "syscall_violation",
        2 => "suspicious_file_open",
        3 => "unexpected_execve",
        4 => "network_unknown_dest",
        5 => "excessive_syscall_rate",
        6 => "wasm_memory_spike",
        7 => "ptrace_attempt",
        8 => "secrets_access",
        9 => "unauthorized_write",
        10 => "capability_violation",
        _ => "unknown",
    }
    .into()
}

fn severity_name(s: u8) -> String {
    match s {
        0 => "info",
        1 => "low",
        2 => "medium",
        3 => "high",
        _ => "critical",
    }
    .into()
}
