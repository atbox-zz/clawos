// crates/clawos-agent/src/agent/mod.rs
//
// The main Agent Loop — ported from IronClaw src/agent/loop.rs
// Receives messages via IPC, classifies intent, schedules jobs,
// and streams results back to callers.

use chrono::{Timelike, Datelike};
use anyhow::Result;
use parking_lot::RwLock;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, instrument, warn};

use crate::{
    config::Config,
    ipc::Server as IpcServer,
    router::{Intent, Router},
    scheduler::{Job, JobKind, Priority, Scheduler},
    worker::Worker,
};
use clawfs::ClawFs;
use clawos_llm::{LlmClient, LlmConfig as LlmClientConfig};

pub mod agentic;
pub mod gate;
mod memory;
mod tool_registry;

pub use memory::Memory;
pub use tool_registry::ToolRegistry;

// ── Agent State ───────────────────────────────────────────────

pub struct AgentState {
    pub config: Config,
    pub router: Router,
    pub scheduler: Scheduler,
    pub memory: Arc<RwLock<Memory>>,
    pub tool_registry: Arc<RwLock<ToolRegistry>>,
    pub clawfs: Arc<tokio::sync::Mutex<ClawFs>>,
    pub wasm_engine: wasmtime::Engine,
}

// ── Entry Point ───────────────────────────────────────────────

pub async fn run(
    wasm_engine: wasmtime::Engine,
    clawfs: ClawFs,
    _ipc: IpcServer,
    config: Config,
) -> Result<()> {
    info!("Initialising agent components");

    // Load tool registry from ClawFS
    let tool_registry = {
        let mut registry = ToolRegistry::new(&config.wasm.tools_dir);
        registry.scan().await?;
        info!(tools = registry.len(), "Tool registry loaded");
        Arc::new(RwLock::new(registry))
    };

    // Build router with known tools
    let known_tools: Vec<String> = tool_registry.read().tool_names();
    let router = Router::new(known_tools);

    // Boot memory (ClawFS-backed)
    let memory = Arc::new(RwLock::new(Memory::new()));

    // Build LLM client (P3: real provider, not stub)
    let llm_client = match LlmClient::new(LlmClientConfig::default()).await {
        Ok(c) => {
            info!(backend = "near_ai", "LLM client connected");
            Some(c)
        }
        Err(e) => {
            warn!(error = %e, "LLM client init failed — LLM jobs will return error responses");
            None
        }
    };

    // Build scheduler (D-02 / D-03: cgroup-aware worker pool)
    let (mut scheduler, sched_worker) = Scheduler::new(config_max_concurrent(&config));
    tokio::spawn(sched_worker.run());

    let clawfs_for_worker = clawfs.clone();
    let clawfs_arc = Arc::new(tokio::sync::Mutex::new(clawfs));

    // Build WASM worker with real LLM + ClawFS handles, wire into scheduler
    {
        let mut w = Worker::new(
            wasm_engine.clone(),
            config.wasm.clone(),
            config.security.clone(),
        );
        if let Some(client) = llm_client.clone() {
            w = w.with_llm_client(client);
        }
        w = w.with_clawfs(clawfs_for_worker);
        scheduler.set_worker(w);
    }

    let state = Arc::new(AgentState {
        config,
        router,
        scheduler,
        memory,
        tool_registry,
        clawfs: clawfs_arc,
        wasm_engine,
    });

    // Main message loop (from IPC channel)
    let (msg_tx, mut msg_rx) = mpsc::channel::<AgentMessage>(128);

    // Wire IPC server to agent loop (previously disconnected)
    {
        let tx = msg_tx.clone();
        let mut ipc = _ipc;
        ipc.agent_tx = Some(tx);
        std::mem::forget(ipc); // keep the Arc-backed server alive
    }

    // Spawn heartbeat (D-08)
    spawn_heartbeat(Arc::clone(&state));

    // Spawn routine engine (D-07)
    spawn_routine_engine(Arc::clone(&state));

    info!("Agent loop ready");

    while let Some(msg) = msg_rx.recv().await {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_message(msg, state).await {
                error!(error = %e, "Error handling agent message");
            }
        });
    }

    Ok(())
}

// ── Message Dispatch ──────────────────────────────────────────

#[derive(Debug)]
pub struct AgentMessage {
    pub id: String,
    pub content: String,
    pub reply_tx: tokio::sync::oneshot::Sender<AgentReply>,
}

#[derive(Debug)]
pub struct AgentReply {
    pub content: String,
    pub tool_calls: Vec<ToolCallResult>,
    pub tokens: u32,
}

#[derive(Debug)]
pub struct ToolCallResult {
    pub tool: String,
    pub input: String,
    pub output: String,
    pub ok: bool,
}

#[instrument(skip_all, fields(msg_id = %msg.id))]
async fn handle_message(msg: AgentMessage, state: Arc<AgentState>) -> Result<()> {
    debug!(content = %msg.content, "Classifying message");

    let intent = state.router.classify(&msg.content);
    info!(intent = ?std::mem::discriminant(&intent), "Intent classified");

    let reply = match intent {
        Intent::ToolCall { tool, args } => dispatch_tool_call(&state, tool, args).await?,
        Intent::Query { text } => dispatch_llm_query(&state, text).await?,
        Intent::Admin { command } => dispatch_admin(&state, command).await?,
        Intent::Routine { routine_id, .. } => dispatch_routine(&state, routine_id).await?,
        Intent::Ambiguous { raw, candidates } => AgentReply {
            content: format!(
                "Ambiguous request. Did you mean one of: {}?\n\nOriginal: {}",
                candidates.join(", "),
                raw
            ),
            tool_calls: vec![],
            tokens: 0,
        },
    };

    let _ = msg.reply_tx.send(reply);
    Ok(())
}

async fn dispatch_tool_call(
    state: &AgentState,
    tool: String,
    args: serde_json::Value,
) -> Result<AgentReply> {
    let input_json = serde_json::to_string(&args)?;

    // Verify tool is registered (security check)
    if !state.tool_registry.read().has_tool(&tool) {
        warn!(tool = %tool, "Unknown tool requested");
        return Ok(AgentReply {
            content: format!("Unknown tool: {tool}"),
            tool_calls: vec![],
            tokens: 0,
        });
    }

    let job = Job::new(
        JobKind::ToolExecution {
            tool: tool.clone(),
            input_json: input_json.clone(),
        },
        Priority::Normal,
        state.config.wasm.max_stack_bytes, // timeout rough proxy; will be config field
    );

    let handle = state.scheduler.submit(job).await?;
    let result = handle.result_rx.await?;

    let output_str = serde_json::to_string(&result.output)?;

    Ok(AgentReply {
        content: output_str.clone(),
        tool_calls: vec![ToolCallResult {
            tool,
            input: input_json,
            output: output_str,
            ok: result.error.is_none(),
        }],
        tokens: 0,
    })
}

async fn dispatch_llm_query(state: &AgentState, text: String) -> Result<AgentReply> {
    // Lock acquisition order (must be consistent everywhere to prevent deadlock):
    //   1. memory (parking_lot RwLock)  — short-lived, released before ClawFS call
    //   2. clawfs (tokio Mutex)         — FTS search, released before building messages
    // Never hold both locks simultaneously.

    // 1. Fetch recent memories (lock released immediately)
    let memories = { state.memory.read().recent(5) };

    // 1b. ClawFS hybrid search — FTS only (no embedding yet), top 3 results.
    //     Lock acquired and released here, before any message building.
    let clawfs_context: Option<String> = {
        let clawfs = state.clawfs.lock().await;
        match clawfs.hybrid_search(Some(text.clone()), None, 3).await {
            Ok(results) if !results.is_empty() => {
                let snippets: Vec<String> = results
                    .iter()
                    .map(|r| {
                        let chunk = r.chunk.as_deref().unwrap_or("").chars().take(400).collect::<String>();
                        format!("[{}]\n{}", r.path, chunk)
                    })
                    .collect();
                let block = snippets.join("\n\n");
                debug!(hits = results.len(), "ClawFS FTS results injected into LLM context");
                Some(block)
            }
            Ok(_) => {
                debug!("ClawFS FTS: no results for query");
                None
            }
            Err(e) => {
                warn!(error = %e, "ClawFS hybrid_search failed — proceeding without long-term memory");
                None
            }
        }
    }; // clawfs lock dropped here

    // 2. Build message context.
    //    System prompt includes ClawFS snippets when available.
    let system_content = match &clawfs_context {
        Some(ctx) => format!(
            "You are ClawOS, an AI-native operating system assistant. Be concise and precise.\n\
             \n\
             Relevant entries from long-term memory (ClawFS):\n\
             ---\n\
             {ctx}\n\
             ---\n\
             Use the above only if relevant to the user's question."
        ),
        None => "You are ClawOS, an AI-native operating system assistant. Be concise and precise.".to_string(),
    };

    let mut messages = vec![serde_json::json!({
        "role": "system",
        "content": system_content
    })];

    for mem in &memories {
        messages.push(serde_json::json!({ "role": "user",      "content": &mem.user }));
        messages.push(serde_json::json!({ "role": "assistant", "content": &mem.assistant }));
    }

    messages.push(serde_json::json!({ "role": "user", "content": &text }));

    let job = Job::new(
        JobKind::LlmQuery {
            messages,
            model: None,
        },
        Priority::Normal,
        120,
    );

    let handle = state.scheduler.submit(job).await?;
    let result = handle.result_rx.await?;
    let reply_text = result.output["content"]
        .as_str()
        .unwrap_or("(no response)")
        .to_string();

    // Store in memory
    state.memory.write().push(memory::Turn {
        user: text,
        assistant: reply_text.clone(),
    });

    Ok(AgentReply {
        content: reply_text,
        tool_calls: vec![],
        tokens: result.output["usage_tokens"].as_u64().unwrap_or(0) as u32,
    })
}

async fn dispatch_admin(
    state: &AgentState,
    command: crate::router::AdminCommand,
) -> Result<AgentReply> {
    use crate::router::AdminCommand::*;
    let content = match command {
        ListJobs => {
            let depth = state.scheduler.queue_depth();
            format!("Queue depth: {depth} jobs pending")
        }
        CancelJob { job_id } => {
            state.scheduler.cancel(&job_id).await;
            format!("Cancel requested for job {job_id} (removed from queue if still pending)")
        }
        ShowMemory { query: _ } => {
            let turns = state.memory.read().recent(10);
            if turns.is_empty() {
                "No memory yet.".to_string()
            } else {
                turns
                    .iter()
                    .map(|t| format!("User: {}\nAssistant: {}", t.user, t.assistant))
                    .collect::<Vec<_>>()
                    .join("\n---\n")
            }
        }
        AgentStatus => {
            let tools = state.tool_registry.read().len();
            let queue = state.scheduler.queue_depth();
            format!(
                "ClawOS Agent v{}\nTools: {tools}\nQueue: {queue} jobs",
                env!("CARGO_PKG_VERSION")
            )
        }
        GateCheck { phase } => match gate::GateId::from_str(&phase) {
            Some(gate_id) => {
                let result = gate::run_gate(gate_id).await;
                let summary: Vec<String> = result
                    .checks
                    .iter()
                    .map(|c| {
                        format!(
                            "[{}] {} — {}",
                            if c.passed { "PASS" } else { "FAIL" },
                            c.name,
                            c.detail
                        )
                    })
                    .collect();
                format!(
                    "Gate {}: {}
{}
Blockers: {}",
                    result.gate,
                    if result.passed {
                        "PASSED ✅"
                    } else {
                        "BLOCKED ❌"
                    },
                    summary.join(
                        "
"
                    ),
                    result.blockers,
                )
            }
            None => format!(
                "Unknown gate '{phase}'. Valid: P1_TO_P2, P2_TO_P3, P3_TO_P4, P4_TO_RELEASE"
            ),
        },
    };

    Ok(AgentReply {
        content,
        tool_calls: vec![],
        tokens: 0,
    })
}

async fn dispatch_routine(state: &AgentState, routine_id: String) -> Result<AgentReply> {
    info!(routine = %routine_id, "Dispatching routine");
    let job = Job::new(
        JobKind::Routine {
            routine_id: routine_id.clone(),
        },
        Priority::Low,
        300,
    );
    let _ = state.scheduler.submit(job).await?;
    Ok(AgentReply {
        content: format!("Routine {routine_id} scheduled"),
        tool_calls: vec![],
        tokens: 0,
    })
}

// ── Heartbeat (D-08) ─────────────────────────────────────────

fn spawn_heartbeat(state: Arc<AgentState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            let queue_depth = state.scheduler.queue_depth();
            info!(queue_depth, "Heartbeat ♥♥♥");

            // Write heartbeat to /var/run/clawos/agent.heartbeat
            let ts = chrono::Utc::now().timestamp();
            let content = serde_json::json!({
                "ts": ts, "queue": queue_depth,
                "tools": state.tool_registry.read().len()
            });
            if let Err(e) = tokio::fs::write("/var/run/clawos/agent.heartbeat", content.to_string()).await {
                warn!(error = %e, "Heartbeat write failed — /var/run/clawos/ may not exist");
            }
        }
    });
}

// ── Routine Engine (D-07) ─────────────────────────────────────

// ── Routine definition (stored as JSON in ClawFS at /routines/*.json) ──

#[derive(Debug, serde::Deserialize, Clone)]
struct Routine {
    id: String,
    name: String,
    cron: String,       // cron expression: "*/5 * * * *"
    tool: String,       // tool name to invoke
    input_json: String, // static input for the tool
    enabled: bool,
}

fn spawn_routine_engine(state: Arc<AgentState>) {
    tokio::spawn(async move {
        info!("Routine engine starting — loading routines from ClawFS");

        // Load routines on startup, then reload every 5 minutes
        let mut reload_interval = tokio::time::interval(std::time::Duration::from_secs(300));
        let mut tick_interval = tokio::time::interval(std::time::Duration::from_secs(60));
        let mut routines: Vec<Routine> = vec![];

        loop {
            tokio::select! {
                _ = reload_interval.tick() => {
                    let fresh = load_routines_from_clawfs(&state).await;
                    routines.clear();
                    routines.extend(fresh);
                    info!(count = routines.len(), "Routines reloaded from ClawFS");
                }
                _ = tick_interval.tick() => {
                    let now = chrono::Utc::now();
                    for routine in &routines {
                        if !routine.enabled { continue; }
                        if should_run_now(&routine.cron, &now) {
                            let state2 = Arc::clone(&state);
                            let r = routine.clone();
                            tokio::spawn(async move {
                                info!(routine_id = %r.id, tool = %r.tool, "Dispatching scheduled routine");
                                let job = crate::scheduler::Job::new(
                                    crate::scheduler::JobKind::ToolExecution {
                                        tool:       r.tool.clone(),
                                        input_json: r.input_json.clone(),
                                    },
                                    crate::scheduler::Priority::Low,
                                    120,
                                );
                                if let Ok(handle) = state2.scheduler.submit(job).await {
                                    match handle.result_rx.await {
                                        Ok(result) => info!(routine_id = %r.id, error = ?result.error, "Routine complete"),
                                        Err(_)     => warn!(routine_id = %r.id, "Routine result channel closed"),
                                    }
                                }
                            });
                        }
                    }
                }
            }
        }
    });
}

/// Load all routines from /routines/*.json in ClawFS.
async fn load_routines_from_clawfs(state: &AgentState) -> Vec<Routine> {
    let clawfs = state.clawfs.lock().await;
    let paths = match clawfs.list_dir("/routines/".to_string()).await {
        Ok(p) => p,
        Err(e) => {
            debug!(error = %e, "No routines directory in ClawFS (expected on first start)");
            return vec![];
        }
    };
    drop(clawfs);

    let mut routines = vec![];
    for path in paths {
        if !path.ends_with(".json") {
            continue;
        }
        let clawfs = state.clawfs.lock().await;
        match clawfs.read_file(path.clone()).await {
            Ok(bytes) => match serde_json::from_slice::<Routine>(&bytes) {
                Ok(r) => routines.push(r),
                Err(e) => warn!(path, error = %e, "Invalid routine JSON"),
            },
            Err(e) => warn!(path, error = %e, "Failed to read routine"),
        }
    }
    routines
}

/// Minimal cron check: matches the current minute against a 5-field cron expression.
/// Supports '*', exact values, and '*/n' step syntax.
fn should_run_now(cron: &str, now: &chrono::DateTime<chrono::Utc>) -> bool {
    let parts: Vec<&str> = cron.split_whitespace().collect();
    if parts.len() != 5 {
        return false;
    }

    let fields = [
        (parts[0], now.minute() as u32, 0, 59),
        (parts[1], now.hour() as u32, 0, 23),
        (parts[2], now.day() as u32, 1, 31),
        (parts[3], now.month() as u32, 1, 12),
        (parts[4], now.weekday().num_days_from_sunday(), 0, 6),
    ];

    fields
        .iter()
        .all(|(expr, val, _min, _max)| match_cron_field(expr, *val))
}

fn match_cron_field(expr: &str, val: u32) -> bool {
    if expr == "*" {
        return true;
    }
    if let Some(step_str) = expr.strip_prefix("*/") {
        if let Ok(step) = step_str.parse::<u32>() {
            return step > 0 && val % step == 0;
        }
    }
    if let Ok(n) = expr.parse::<u32>() {
        return n == val;
    }
    // Range: e.g. "1-5"
    if let Some((lo, hi)) = expr.split_once('-') {
        if let (Ok(lo), Ok(hi)) = (lo.parse::<u32>(), hi.parse::<u32>()) {
            return val >= lo && val <= hi;
        }
    }
    false
}

#[cfg(test)]
mod routine_tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn every_minute_matches() {
        let t = chrono::Utc
            .with_ymd_and_hms(2025, 6, 15, 10, 30, 0)
            .unwrap();
        assert!(should_run_now("* * * * *", &t));
    }

    #[test]
    fn every_5_minutes_matches_on_0() {
        let t = chrono::Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap();
        assert!(should_run_now("*/5 * * * *", &t));
    }

    #[test]
    fn every_5_minutes_no_match_on_1() {
        let t = chrono::Utc.with_ymd_and_hms(2025, 6, 15, 10, 1, 0).unwrap();
        assert!(!should_run_now("*/5 * * * *", &t));
    }

    #[test]
    fn hourly_at_30() {
        let t = chrono::Utc
            .with_ymd_and_hms(2025, 6, 15, 10, 30, 0)
            .unwrap();
        assert!(should_run_now("30 * * * *", &t));
        let t2 = chrono::Utc
            .with_ymd_and_hms(2025, 6, 15, 10, 31, 0)
            .unwrap();
        assert!(!should_run_now("30 * * * *", &t2));
    }
}

/// Run the agent for exactly one message (--single-shot mode).
/// Returns the reply text.
pub async fn run_single_shot(
    wasm_engine: wasmtime::Engine,
    clawfs: ClawFs,
    config: Config,
    input: String,
) -> Result<String> {
    let tool_registry = {
        let mut registry = ToolRegistry::new(&config.wasm.tools_dir);
        registry.scan().await?;
        Arc::new(RwLock::new(registry))
    };
    let known_tools = tool_registry.read().tool_names();
    let router = Router::new(known_tools);
    let memory = Arc::new(RwLock::new(Memory::new()));
    let (scheduler, sched_worker) = Scheduler::new(config_max_concurrent(&config));
    tokio::spawn(sched_worker.run());
    let clawfs_arc = Arc::new(tokio::sync::Mutex::new(clawfs));
    let state = Arc::new(AgentState {
        config,
        router,
        scheduler,
        memory,
        tool_registry,
        clawfs: clawfs_arc,
        wasm_engine,
    });

    let intent = state.router.classify(&input);
    let reply = match intent {
        Intent::ToolCall { tool, args } => dispatch_tool_call(&state, tool, args).await?,
        Intent::Query { text } => dispatch_llm_query(&state, text).await?,
        Intent::Admin { command } => dispatch_admin(&state, command).await?,
        Intent::Routine { routine_id, .. } => dispatch_routine(&state, routine_id).await?,
        Intent::Ambiguous { raw, candidates } => AgentReply {
            content: format!(
                "Ambiguous. Did you mean: {}?\nInput: {}",
                candidates.join(", "),
                raw
            ),
            tool_calls: vec![],
            tokens: 0,
        },
    };
    Ok(reply.content)
}

fn config_max_concurrent(config: &Config) -> usize {
    // Allow explicit override for testing.
    if let Ok(val) = std::env::var("CLAWOS_MAX_CONCURRENT") {
        if let Ok(n) = val.parse::<usize>() {
            return n.max(1).min(64);
        }
    }

    // Read pids.max from the agent cgroup slice set by setup-cgroups.sh.
    // Reserve: ~8 tokio runtime threads + 10 buffer = 18 overhead.
    // Each WASM worker needs ~5 PIDs. Max concurrent = (pids_max - 18) / 5.
    let pids_path = format!("{}/pids.max", config.cgroup_path);
    if let Ok(raw) = std::fs::read_to_string(&pids_path) {
        let raw = raw.trim();
        if raw != "max" {
            if let Ok(pids_max) = raw.parse::<usize>() {
                const OVERHEAD: usize = 18;
                const PER_WORKER: usize = 5;
                let available = pids_max.saturating_sub(OVERHEAD);
                let computed = (available / PER_WORKER).max(1).min(64);
                debug!(
                    pids_max,
                    computed, "Max concurrent derived from cgroup pids.max"
                );
                return computed;
            }
        }
    }

    // Fallback: spec value from resource-quotas.json (pids.max=128 → 20 workers).
    debug!("cgroup pids.max not readable — using default max_concurrent=20");
    20
}
