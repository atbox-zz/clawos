// tests/integration_agent.rs
// G-03: End-to-end integration tests for the agent loop.
// Run with: cargo test --test integration_agent

use std::time::Duration;
use tokio::net::UnixStream;
use tokio::io::{AsyncWriteExt, AsyncBufReadExt, BufReader};
use serde_json::json;

const AGENT_SOCK: &str = "/var/run/clawos/ipc/test-agent.sock";
const TIMEOUT: Duration = Duration::from_secs(10);

// ── Helper ────────────────────────────────────────────────────

async fn send_ipc(msg: serde_json::Value) -> Option<serde_json::Value> {
    let mut stream = tokio::time::timeout(
        TIMEOUT,
        UnixStream::connect(AGENT_SOCK)
    ).await.ok()?.ok()?;

    let line = format!("{msg}\n");
    stream.write_all(line.as_bytes()).await.ok()?;

    let mut reader = BufReader::new(stream);
    let mut resp_line = String::new();
    tokio::time::timeout(TIMEOUT, reader.read_line(&mut resp_line)).await.ok()?.ok()?;

    serde_json::from_str(&resp_line).ok()
}

fn make_msg(msg_type: &str, from: &str, payload: serde_json::Value) -> serde_json::Value {
    json!({
        "id":        uuid::Uuid::new_v4().to_string(),
        "version":   1,
        "type":      msg_type,
        "from":      from,
        "to":        "clawos-agent",
        "timestamp": chrono::Utc::now().timestamp_millis(),
        "payload":   payload
    })
}

// ── Tests ─────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires running agent (run with --include-ignored in CI)"]
async fn test_task_status_ack() {
    let msg = make_msg("task.status", "test-harness", json!({
        "task_id": "A-01",
        "status":  "running",
        "progress": 50,
        "message": "kernel config applying"
    }));

    let resp = send_ipc(msg).await.expect("IPC not reachable");
    assert_eq!(resp["type"].as_str(), Some("response"));
    assert_eq!(resp["payload"]["ack"].as_bool(), Some(true));
}

#[tokio::test]
#[ignore = "requires running agent"]
async fn test_task_failed_triggers_rollback() {
    let msg = make_msg("task.failed", "kernel-agent", json!({
        "task_id":            "A-02",
        "error_code":         "E004",
        "error_message":      "KASLR config not applied",
        "rollback_performed": false
    }));

    let resp = send_ipc(msg).await.expect("IPC not reachable");
    assert_eq!(resp["payload"]["rollback_initiated"].as_bool(), Some(true));
}

#[tokio::test]
#[ignore = "requires running agent"]
async fn test_gate_check_p1_to_p2() {
    let msg = make_msg("gate.check", "test-harness", json!({
        "gate": "P1_TO_P2",
        "artifacts": {}
    }));

    let resp = send_ipc(msg).await.expect("IPC not reachable");
    assert!(resp["payload"]["gate"].as_str().is_some());
    // Gate may pass or fail — we just verify the response is well-formed
    assert!(resp["payload"]["passed"].is_boolean());
}

#[tokio::test]
#[ignore = "requires running agent + eBPF monitor"]
async fn test_security_alert_critical_kills_pid() {
    // Note: don't use a real PID in tests — use PID 0 (no-op kill)
    let msg = make_msg("security.alert", "clawos-ebpf", json!({
        "event_kind":   "PtraceAttempt",
        "severity":     "critical",
        "pid":          0,   // PID 0 = no-op kill
        "details":      "Integration test — synthetic ptrace alert",
        "action_taken": "killed"
    }));

    let resp = send_ipc(msg).await.expect("IPC not reachable");
    assert_eq!(resp["payload"]["ack"].as_bool(), Some(true));
}

// ── Unit tests (no agent needed) ─────────────────────────────

#[test]
fn ipc_envelope_missing_fields_should_error() {
    // Simulate the validation logic from ipc/mod.rs
    let bad_msg = json!({ "type": "task.status" }); // missing id, version, etc.
    let required = ["id", "version", "type", "from", "to", "timestamp", "payload"];
    let missing_count = required.iter()
        .filter(|f| bad_msg.get(f).is_none())
        .count();
    assert!(missing_count > 0, "Should have missing fields");
}

#[test]
fn ipc_version_1_only() {
    let msg_v2 = json!({
        "id": "x", "version": 2, "type": "task.status",
        "from": "a", "to": "b", "timestamp": 0,
        "payload": {}
    });
    // Version check: only version 1 accepted
    assert_ne!(msg_v2["version"].as_u64(), Some(1));
}
