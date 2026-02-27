// crates/clawos-agent/src/ipc/mod.rs
//
// IPC Server: Unix domain socket listener.
// Implements the P1.7 IPC protocol (NDJSON over Unix socket).

use anyhow::Result;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{info, warn, error, debug};
use std::path::Path;

pub struct Server {
    socket_path: String,
}

impl Server {
    /// Start the IPC listener and return a handle.
    pub async fn start(socket_path: &str) -> Result<Self> {
        // Remove stale socket
        if Path::new(socket_path).exists() {
            std::fs::remove_file(socket_path)?;
        }

        // Ensure parent directory exists
        if let Some(parent) = Path::new(socket_path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(socket_path)?;
        info!(socket = socket_path, "IPC server listening");

        let path_clone = socket_path.to_string();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        tokio::spawn(handle_connection(stream, path_clone.clone()));
                    }
                    Err(e) => {
                        error!(error = %e, "IPC accept error");
                        break;
                    }
                }
            }
        });

        Ok(Self { socket_path: socket_path.to_string() })
    }
}

async fn handle_connection(mut stream: UnixStream, socket_path: String) {
    let (reader, mut writer) = stream.split();
    let mut lines = BufReader::new(reader).lines();

    debug!(socket = %socket_path, "New IPC connection");

    while let Ok(Some(line)) = lines.next_line().await {
        match process_message(&line).await {
            Ok(response) => {
                let resp_str = serde_json::to_string(&response).unwrap_or_default();
                if let Err(e) = writer.write_all(format!("{resp_str}\n").as_bytes()).await {
                    warn!(error = %e, "Failed to write IPC response");
                    break;
                }
            }
            Err(e) => {
                let err_resp = error_envelope(&e.to_string());
                let _ = writer.write_all(
                    format!("{}\n", serde_json::to_string(&err_resp).unwrap_or_default()).as_bytes()
                ).await;
            }
        }
    }
}

async fn process_message(raw: &str) -> Result<Value> {
    let msg: Value = serde_json::from_str(raw)
        .map_err(|e| anyhow::anyhow!("Invalid JSON: {e}"))?;

    let msg_type = msg.get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let from = msg.get("from")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    debug!(msg_type, from, "IPC message received");

    // Validate envelope fields (P1.7 protocol)
    validate_envelope(&msg)?;

    // Route by type
    let response_payload = match msg_type {
        "task.status"   => handle_task_status(&msg).await?,
        "task.complete" => handle_task_complete(&msg).await?,
        "task.failed"   => handle_task_failed(&msg).await?,
        "gate.check"    => handle_gate_check(&msg).await?,
        "security.alert"=> handle_security_alert(&msg).await?,
        other => {
            warn!(msg_type = other, "Unknown IPC message type");
            serde_json::json!({ "status": "unknown_type", "type": other })
        }
    };

    Ok(make_response(&msg, response_payload))
}

fn validate_envelope(msg: &Value) -> Result<()> {
    for required in &["id", "version", "type", "from", "to", "timestamp", "payload"] {
        if msg.get(required).is_none() {
            anyhow::bail!("Missing required envelope field: {required}");
        }
    }
    let version = msg["version"].as_u64().unwrap_or(0);
    if version != 1 {
        anyhow::bail!("Unsupported IPC protocol version: {version}");
    }
    Ok(())
}

async fn handle_task_status(msg: &Value) -> Result<Value> {
    let payload = &msg["payload"];
    let task_id = payload["task_id"].as_str().unwrap_or("?");
    let status  = payload["status"].as_str().unwrap_or("?");
    info!(task_id, status, "Task status update received");
    Ok(serde_json::json!({ "ack": true }))
}

async fn handle_task_complete(msg: &Value) -> Result<Value> {
    let payload = &msg["payload"];
    let task_id = payload["task_id"].as_str().unwrap_or("?");
    info!(task_id, "Task completed");
    // TODO P2: update task registry in ClawFS, trigger downstream deps
    Ok(serde_json::json!({ "ack": true, "task_id": task_id }))
}

async fn handle_task_failed(msg: &Value) -> Result<Value> {
    let payload  = &msg["payload"];
    let task_id  = payload["task_id"].as_str().unwrap_or("?");
    let err_msg  = payload["error_message"].as_str().unwrap_or("unknown");
    error!(task_id, error = err_msg, "Task FAILED — initiating rollback");
    // TODO P2: execute rollback_cmd from task spec, notify Security Agent
    Ok(serde_json::json!({ "ack": true, "rollback_initiated": true }))
}

async fn handle_gate_check(msg: &Value) -> Result<Value> {
    let gate = msg["payload"]["gate"].as_str().unwrap_or("?");
    info!(gate, "Gate check requested");
    // TODO P2: run actual gate validation logic
    Ok(serde_json::json!({
        "gate":   gate,
        "passed": false,
        "reason": "Gate checks not yet implemented (P2 task G-01)"
    }))
}

async fn handle_security_alert(msg: &Value) -> Result<Value> {
    let payload   = &msg["payload"];
    let severity  = payload["severity"].as_str().unwrap_or("?");
    let event     = payload["event_kind"].as_str().unwrap_or("?");
    let details   = payload["details"].as_str().unwrap_or("");

    // Security alerts are always logged at ERROR level regardless of severity
    error!(severity, event_kind = event, details, "⚠️  SECURITY ALERT from eBPF monitor");

    // Critical alerts → kill the offending PID
    if severity == "critical" {
        let pid = payload["pid"].as_u64().unwrap_or(0) as u32;
        if pid > 0 {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGKILL,
            );
            warn!(pid, "Sent SIGKILL to process due to critical security event");
        }
    }

    Ok(serde_json::json!({ "ack": true, "action": "logged" }))
}

fn make_response(request: &Value, payload: Value) -> Value {
    serde_json::json!({
        "id":             uuid::Uuid::new_v4().to_string(),
        "version":        1,
        "type":           "response",
        "from":           "clawos-agent",
        "to":             request.get("from").cloned().unwrap_or(Value::Null),
        "timestamp":      chrono::Utc::now().timestamp_millis(),
        "correlation_id": request.get("id").cloned().unwrap_or(Value::Null),
        "payload":        payload
    })
}

fn error_envelope(err: &str) -> Value {
    serde_json::json!({
        "id":        uuid::Uuid::new_v4().to_string(),
        "version":   1,
        "type":      "error",
        "from":      "clawos-agent",
        "to":        "unknown",
        "timestamp": chrono::Utc::now().timestamp_millis(),
        "payload":   { "error": err, "code": "E001" }
    })
}
