// crates/clawos-ebpf-userspace/src/anomaly.rs
//
// Anomaly Engine — B-05
// Sliding window event scoring per PID.
// Produces an Alert when score exceeds threshold.
use serde::Serialize;
use crate::ClawOsEvent;
use std::collections::HashMap;
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60); // 60-second sliding window
const ALERT_THRESHOLD: f64 = 8.0;

// EventKind discriminants (must match ebpf-event-structs.rs P1.3)
const KIND_SYSCALL_VIOLATION: u32 = 1;
const KIND_SUSPICIOUS_FILE_OPEN: u32 = 2;
const KIND_UNEXPECTED_EXECVE: u32 = 3;
const KIND_NETWORK_UNKNOWN_DEST: u32 = 4;
const KIND_EXCESSIVE_SYSCALL_RATE: u32 = 5;
const KIND_WASM_MEMORY_SPIKE: u32 = 6;
const KIND_PTRACE_ATTEMPT: u32 = 7;
const KIND_SECRETS_ACCESS: u32 = 8;
const KIND_UNAUTHORIZED_WRITE: u32 = 9;
const KIND_CAPABILITY_VIOLATION: u32 = 10;

#[derive(Debug, Serialize, Clone)]
pub struct Alert {
    pub kind_name: String,
    pub pid: u32,
    pub severity_name: String,
    pub details: String,
    pub score: f64,
    pub action_taken: String,
}

struct PidState {
    events: Vec<(Instant, u32, f64)>, // (time, kind, weight)
    total_score: f64,
}

impl PidState {
    fn new() -> Self {
        Self {
            events: vec![],
            total_score: 0.0,
        }
    }

    fn add(&mut self, kind: u32, weight: f64) {
        let now = Instant::now();
        self.events.push((now, kind, weight));
        self.total_score += weight;
    }

    fn evict_old(&mut self) {
        let cutoff = Instant::now() - WINDOW;
        // Accumulate removed weight before mutating total_score to avoid double-borrow.
        let mut removed_weight = 0.0f64;
        self.events.retain(|(t, _, w)| {
            if *t < cutoff {
                removed_weight += w;
                false
            } else {
                true
            }
        });
        self.total_score -= removed_weight;
        // Clamp to 0 to guard against floating-point drift
        if self.total_score < 0.0 {
            self.total_score = 0.0;
        }
    }
}

pub struct AnomalyEngine {
    per_pid: HashMap<u32, PidState>,
    last_cleanup: Instant,
}

impl AnomalyEngine {
    pub fn new() -> Self {
        Self {
            per_pid: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }

    pub fn score(&mut self, evt: &ClawOsEvent) -> Option<Alert> {
        let weight = event_weight(evt.kind);
        if weight == 0.0 {
            return None;
        }

        let state = self.per_pid.entry(evt.pid).or_insert_with(PidState::new);
        state.add(evt.kind, weight);
        state.evict_old();

        let score = state.total_score;

        // Periodic cleanup of dead PIDs
        if self.last_cleanup.elapsed() > Duration::from_secs(120) {
            self.cleanup_dead_pids();
        }

        if score >= ALERT_THRESHOLD {
            let action = determine_action(score, evt.kind);
            Some(Alert {
                pid: evt.pid,
                kind_name: kind_name(evt.kind),
                severity_name: severity_name(evt.severity),
                details: cstr(&evt.details),
                score,
                action_taken: action,
            })
        } else {
            None
        }
    }

    fn cleanup_dead_pids(&mut self) {
        self.per_pid.retain(|pid, state| {
            state.evict_old();
            // Check if PID still exists in /proc
            std::path::Path::new(&format!("/proc/{pid}")).exists() && state.total_score > 0.0
        });
        self.last_cleanup = Instant::now();
    }
}

/// Higher weight = more suspicious.
fn event_weight(kind: u32) -> f64 {
    match kind {
        KIND_PTRACE_ATTEMPT => 10.0, // Immediate alert
        KIND_SYSCALL_VIOLATION => 5.0,
        KIND_CAPABILITY_VIOLATION => 5.0,
        KIND_SECRETS_ACCESS => 4.0,
        KIND_NETWORK_UNKNOWN_DEST => 3.0,
        KIND_UNEXPECTED_EXECVE => 3.0,
        KIND_UNAUTHORIZED_WRITE => 3.0,
        KIND_SUSPICIOUS_FILE_OPEN => 2.0,
        KIND_WASM_MEMORY_SPIKE => 1.5,
        KIND_EXCESSIVE_SYSCALL_RATE => 1.0,
        _ => 0.0,
    }
}

fn determine_action(score: f64, kind: u32) -> String {
    if score >= 15.0 || kind == KIND_PTRACE_ATTEMPT {
        "killed".into()
    } else if score >= 10.0 {
        "blocked".into()
    } else {
        "warned".into()
    }
}

fn kind_name(k: u32) -> String {
    match k {
        KIND_SYSCALL_VIOLATION => "SyscallViolation",
        KIND_SUSPICIOUS_FILE_OPEN => "SuspiciousFileOpen",
        KIND_UNEXPECTED_EXECVE => "UnexpectedExecve",
        KIND_NETWORK_UNKNOWN_DEST => "NetworkToUnknownDest",
        KIND_EXCESSIVE_SYSCALL_RATE => "ExcessiveSyscallRate",
        KIND_WASM_MEMORY_SPIKE => "WasmMemorySpike",
        KIND_PTRACE_ATTEMPT => "PtraceAttempt",
        KIND_SECRETS_ACCESS => "SecretsAccess",
        KIND_UNAUTHORIZED_WRITE => "UnauthorizedWrite",
        KIND_CAPABILITY_VIOLATION => "CapabilityViolation",
        _ => "Unknown",
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

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ClawOsEvent;

    fn make_event(kind: u32, pid: u32) -> ClawOsEvent {
        ClawOsEvent {
            kind,
            severity: 3,
            _pad: [0; 3],
            pid,
            tgid: pid,
            uid: 1000,
            gid: 1000,
            ppid: 1,
            _pad2: 0,
            timestamp_ns: 0,
            syscall_nr: 0,
            syscall_arg0: 0,
            comm: [0; 16],
            details: [0; 176],
        }
    }

    #[test]
    fn no_alert_below_threshold() {
        let mut engine = AnomalyEngine::new();
        // single suspicious file open (weight 2.0) — below threshold 8.0
        let evt = make_event(KIND_SUSPICIOUS_FILE_OPEN, 1234);
        assert!(engine.score(&evt).is_none());
    }

    #[test]
    fn alert_on_ptrace() {
        let mut engine = AnomalyEngine::new();
        let evt = make_event(KIND_PTRACE_ATTEMPT, 5678);
        let alert = engine.score(&evt);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().kind_name, "PtraceAttempt");
    }

    #[test]
    fn cumulative_score_triggers_alert() {
        let mut engine = AnomalyEngine::new();
        let pid = 9999u32;
        // 4 × SyscallViolation (weight 5.0 each) = 20.0 → alert
        for _ in 0..4 {
            engine.score(&make_event(KIND_SYSCALL_VIOLATION, pid));
        }
        let alert = engine.score(&make_event(KIND_SUSPICIOUS_FILE_OPEN, pid));
        assert!(alert.is_some(), "Should alert after cumulative score ≥ 8.0");
    }

    #[test]
    fn different_pids_isolated() {
        let mut engine = AnomalyEngine::new();
        // PID 1 accumulates high score
        for _ in 0..3 {
            engine.score(&make_event(KIND_SYSCALL_VIOLATION, 111));
        }
        // PID 2 has only 1 event — should NOT alert
        let alert = engine.score(&make_event(KIND_SUSPICIOUS_FILE_OPEN, 222));
        assert!(
            alert.is_none(),
            "PID 2 should not be affected by PID 1's score"
        );
    }
}
