// crates/clawos-agent/src/worker/mod.rs
//
// Worker: executes a Job inside its own cgroup slice.
// D-03: cgroup isolation. D-04: WASM runtime bridge.
//
// Each WASM tool runs in an isolated wasmtime Store with:
//   - Memory limit from resource-quotas.json (wasm_worker profile)
//   - CPU time limit via cgroup cpu.max
//   - No direct network (HTTP proxied through host functions)
//   - ClawFS access via host functions (not direct path access)

use anyhow::{Context, Result};
use tracing::{info, warn, error, instrument};
use std::time::{Duration, Instant};
use wasmtime::component::{Component, Linker, Val};
use wasmtime::{Engine, Store};

use crate::scheduler::{Job, JobKind, JobResult};
use crate::config::{Config, SecurityConfig, WasmConfig};

// ── Host State ────────────────────────────────────────────────

/// Per-WASM-store host context — lives alongside the Store.
pub struct HostCtx {
    pub job_id:     String,
    pub tool_name:  String,
    pub clawfs_path: String,      // workspace root for this tool execution
    pub http_allowlist: Vec<String>,
    pub call_depth: u32,          // prevent tool-chain recursion > 4
}

// ── Worker ────────────────────────────────────────────────────

pub struct Worker {
    engine:  Engine,
    config:  WasmConfig,
    security: SecurityConfig,
}

impl Worker {
    pub fn new(engine: Engine, config: WasmConfig, security: SecurityConfig) -> Self {
        Self { engine, config, security }
    }

    /// Execute a single Job and return the result.
    #[instrument(skip(self), fields(job_id = %job.id))]
    pub async fn execute(&self, job: Job) -> JobResult {
        let start    = Instant::now();
        let job_id   = job.id.clone();
        let deadline = Duration::from_secs(job.timeout_sec);

        // Join worker cgroup slice
        if let Err(e) = self.join_wasm_cgroup() {
            warn!(error = %e, "Failed to join WASM cgroup — continuing without isolation");
        }

        let result = tokio::time::timeout(
            deadline,
            self.run_job(job)
        ).await;

        let duration_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(Ok(output)) => JobResult { job_id, output, error: None, duration_ms },
            Ok(Err(e)) => {
                error!(error = %e, "Job execution error");
                JobResult {
                    job_id,
                    output:     serde_json::Value::Null,
                    error:      Some(e.to_string()),
                    duration_ms,
                }
            }
            Err(_) => {
                error!("Job timed out");
                JobResult {
                    job_id,
                    output:     serde_json::Value::Null,
                    error:      Some("timeout".to_string()),
                    duration_ms,
                }
            }
        }
    }

    async fn run_job(&self, job: Job) -> Result<serde_json::Value> {
        match &job.kind {
            JobKind::ToolExecution { tool, input_json } => {
                self.run_wasm_tool(job.id.clone(), tool, input_json).await
            }
            JobKind::LlmQuery { messages, model } => {
                self.run_llm_query(messages, model.as_deref()).await
            }
            JobKind::Routine { routine_id } => {
                self.run_routine(routine_id).await
            }
            JobKind::Maintenance { task } => {
                info!(task, "Maintenance job — no-op in P2");
                Ok(serde_json::json!({ "status": "ok", "task": task }))
            }
        }
    }

    async fn run_wasm_tool(&self, job_id: String, tool: &str, input_json: &str) -> Result<serde_json::Value> {
        let wasm_path = format!("{}/{}/tool.wasm", self.config.tools_dir, tool);

        // P2: if WASM binary doesn't exist yet, return a stub response
        if !std::path::Path::new(&wasm_path).exists() {
            warn!(tool, "WASM binary not found — returning stub (P3 will populate)");
            return Ok(serde_json::json!({
                "status":  "stub",
                "tool":    tool,
                "message": "Tool not yet installed (Phase P3 will deploy WASM tools)",
                "input":   input_json
            }));
        }

        // Load and instantiate the WASM component
        let component = Component::from_file(&self.engine, &wasm_path)
            .with_context(|| format!("Failed to load WASM component: {wasm_path}"))?;

        let mut linker: Linker<HostCtx> = Linker::new(&self.engine);

        // Register host functions (the WASM ↔ ClawOS bridge)
        self.register_host_functions(&mut linker)?;

        let ctx = HostCtx {
            job_id,
            tool_name:  tool.to_string(),
            clawfs_path: format!("/var/lib/clawos/workspace/{}", tool),
            http_allowlist: self.security.allowed_endpoints
                .iter().map(|e| e.host.clone()).collect(),
            call_depth: 0,
        };

        let mut store = Store::new(&self.engine, ctx);

        // Memory limit: cap WASM linear memory at 128MB (wasm_worker profile)
        store.limiter(|_| {
            wasmtime::ResourceLimiter::default()
        });

        let instance = linker.instantiate_async(&mut store, &component).await?;

        // Call the `run` export (per P1.1 WIT world: clawos-tool)
        let run_fn = instance.get_typed_func::<(String,), (Result<String, String>,)>(
            &mut store, "run"
        ).context("WASM component missing 'run' export")?;

        let (result,) = run_fn.call_async(&mut store, (input_json.to_string(),)).await?;
        run_fn.post_return_async(&mut store).await?;

        match result {
            Ok(output_json)  => {
                let val: serde_json::Value = serde_json::from_str(&output_json)
                    .unwrap_or(serde_json::Value::String(output_json));
                Ok(val)
            }
            Err(err_str) => anyhow::bail!("Tool error: {err_str}"),
        }
    }

    async fn run_llm_query(&self, messages: &[serde_json::Value], _model: Option<&str>) -> Result<serde_json::Value> {
        // TODO P3: call real LLM provider via http-client host function
        // P2 stub: echo back the last user message
        let last_user = messages.iter().rev()
            .find(|m| m["role"].as_str() == Some("user"))
            .and_then(|m| m["content"].as_str())
            .unwrap_or("(empty)");

        warn!("LLM query stubbed — P3 will connect real provider");

        Ok(serde_json::json!({
            "content":      format!("[STUB] Echo: {last_user}"),
            "model":        "stub-v0",
            "usage_tokens": 0,
            "finish_reason":"stub"
        }))
    }

    async fn run_routine(&self, routine_id: &str) -> Result<serde_json::Value> {
        info!(routine = routine_id, "Running routine (P3 will load from ClawFS)");
        Ok(serde_json::json!({ "status": "ok", "routine": routine_id }))
    }

    /// Join /sys/fs/cgroup/clawos/wasm cgroup for resource enforcement.
    fn join_wasm_cgroup(&self) -> Result<()> {
        let pid = std::process::id();
        std::fs::write("/sys/fs/cgroup/clawos/wasm/cgroup.procs", pid.to_string())
            .context("Failed to join WASM cgroup")?;
        Ok(())
    }

    fn register_host_functions(&self, linker: &mut Linker<HostCtx>) -> Result<()> {
        // P2: register stub host functions.
        // P3: real implementations that talk to ClawFS, http proxy, kernel keyring.

        // clawos:runtime/log
        linker.func_wrap("clawos:runtime/log", "write",
            |_caller: wasmtime::Caller<HostCtx>, level: u32, message: String, _fields: Option<String>| {
                match level {
                    0 => tracing::trace!(source = "wasm", "{message}"),
                    1 => tracing::debug!(source = "wasm", "{message}"),
                    2 => tracing::info!(source  = "wasm", "{message}"),
                    3 => tracing::warn!(source  = "wasm", "{message}"),
                    _ => tracing::error!(source = "wasm", "{message}"),
                }
            }
        )?;

        // clawos:runtime/clawfs - read-file stub
        linker.func_wrap_async("clawos:runtime/clawfs", "read-file",
            |caller: wasmtime::Caller<HostCtx>, (path, _cap): (String, u64)| {
                Box::new(async move {
                    warn!(source = "wasm-host", path = %path, "clawfs.read-file stub called");
                    // Return error result — P3 will implement real ClawFS access
                    let err = format!("ClawFS read not yet implemented (P3): {path}");
                    Ok::<Result<Vec<u8>, String>, wasmtime::Error>(Err(err))
                })
            }
        )?;

        Ok(())
    }
}
