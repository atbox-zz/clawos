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
//
// ABI NOTE: WASM tools are compiled as cdylib (core wasm module, flat C ABI).
// They use extern "C" symbols for host functions:
//   clawos_http_fetch, clawos_clawfs_read, clawos_llm_complete, etc.
// NOT the WIT component model — so we use wasmtime::{Module, Linker},
// NOT wasmtime::component::{Component, Linker}.

use anyhow::{Context, Result};
use std::time::{Duration, Instant};
use tracing::{error, info, instrument, warn};
use wasmtime::{Caller, Engine, Linker, Module, Store};

//use crate::config::{AllowedEndpoint, Config, SecurityConfig, WasmConfig};
use crate::config::{                           SecurityConfig, WasmConfig};
//use crate::scheduler::{Job, JobKind, JobResult, Scheduler};
use crate::scheduler::{Job, JobKind, JobResult             };
use clawfs::ClawFs;
//use clawos_llm::{CompletionRequest, LlmBackend, LlmClient, LlmConfig, Message};
use clawos_llm::{CompletionRequest,               LlmClient,            Message};
use reqwest::Client as HttpClient;
//use std::sync::Arc;

// ── WASM Memory Limiter ───────────────────────────────────────

/// Enforces a hard cap on WASM linear memory growth.
pub(crate) struct WasmMemoryLimiter {
    max_bytes: usize,
}

impl wasmtime::ResourceLimiter for WasmMemoryLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        if desired > self.max_bytes {
            tracing::warn!(
                current_mb = current / 1024 / 1024,
                desired_mb = desired / 1024 / 1024,
                max_mb = self.max_bytes / 1024 / 1024,
                "WASM memory growth denied — limit reached"
            );
            Ok(false)
        } else {
            Ok(true)
        }
    }

    fn table_growing(
        &mut self,
        _current: usize,
        _desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        Ok(true)
    }
}

// ── Host State ────────────────────────────────────────────────

/// Per-WASM-store host context — lives alongside the Store.
pub struct HostCtx {
    pub job_id: String,
    pub tool_name: String,
    pub clawfs_path: String,
    pub http_allowlist: Vec<String>,
    pub allowed_read_paths: Vec<String>,
    pub allowed_write_paths: Vec<String>,
    pub call_depth: u32,
    pub memory_limiter: WasmMemoryLimiter,
    pub scheduler_tx: Option<tokio::sync::mpsc::Sender<crate::scheduler::DispatchMsg>>,
    // Real service handles — injected by Worker
    pub clawfs: Option<ClawFs>,
    pub llm_client: Option<LlmClient>,
    pub http_client: HttpClient,
    pub security: SecurityConfig,
}

// ── Worker ────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Worker {
    engine: Engine,
    config: WasmConfig,
    security: SecurityConfig,
    llm_client: Option<LlmClient>,
    clawfs: Option<ClawFs>,
    http_client: HttpClient,
    scheduler_tx: Option<tokio::sync::mpsc::Sender<crate::scheduler::DispatchMsg>>,
    current_invoke_depth: u32,
}

impl Worker {
    pub fn new(engine: Engine, config: WasmConfig, security: SecurityConfig) -> Self {
        let http_client = HttpClient::builder()
            .timeout(std::time::Duration::from_secs(30))
            .https_only(true)
            .user_agent("ClawOS-WASM-Host/0.1.0")
            .build()
            .expect("Failed to build HTTP client");
        Self {
            engine,
            config,
            security,
            llm_client: None,
            clawfs: None,
            http_client,
            scheduler_tx: None,
            current_invoke_depth: 0,
        }
    }

    pub fn with_llm_client(mut self, client: LlmClient) -> Self {
        self.llm_client = Some(client);
        self
    }

    pub fn with_clawfs(mut self, fs: ClawFs) -> Self {
        self.clawfs = Some(fs);
        self
    }

    pub fn with_scheduler(
        mut self,
        tx: tokio::sync::mpsc::Sender<crate::scheduler::DispatchMsg>,
    ) -> Self {
        self.scheduler_tx = Some(tx);
        self
    }

    #[instrument(skip(self), fields(job_id = %job.id))]
    pub async fn execute(&self, job: Job) -> JobResult {
        self.execute_with_depth(job, 0).await
    }

    pub async fn execute_with_depth(&self, job: Job, call_depth: u32) -> JobResult {
        let mut worker_with_depth = self.clone();
        worker_with_depth.current_invoke_depth = call_depth;

        let start = Instant::now();
        let job_id = job.id.clone();
        let deadline = Duration::from_secs(job.timeout_sec);

        if let Err(e) = worker_with_depth.join_wasm_cgroup() {
            warn!(error = %e, "Failed to join WASM cgroup — continuing without isolation");
        }

        let result = tokio::time::timeout(deadline, worker_with_depth.run_job(job)).await;
        let duration_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(Ok(output)) => JobResult { job_id, output, error: None, duration_ms },
            Ok(Err(e)) => {
                error!(error = %e, "Job execution error");
                JobResult { job_id, output: serde_json::Value::Null, error: Some(e.to_string()), duration_ms }
            }
            Err(_) => {
                error!("Job timed out");
                JobResult { job_id, output: serde_json::Value::Null, error: Some("timeout".to_string()), duration_ms }
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
            JobKind::Routine { routine_id } => self.run_routine(routine_id).await,
            JobKind::Maintenance { task } => {
                info!(task, "Maintenance job");
                Ok(serde_json::json!({ "status": "ok", "task": task }))
            }
        }
    }

    async fn run_wasm_tool(
        &self,
        job_id: String,
        tool: &str,
        input_json: &str,
    ) -> Result<serde_json::Value> {
        let wasm_path = format!("{}/{}/tool.wasm", self.config.tools_dir, tool);

        if !std::path::Path::new(&wasm_path).exists() {
            warn!(tool, "WASM binary not found — returning stub");
            return Ok(serde_json::json!({
                "status":  "stub",
                "tool":    tool,
                "message": "Tool not yet installed",
                "input":   input_json
            }));
        }

        // Tools are core wasm modules (cdylib, flat C ABI) — NOT component model.
        let module = Module::from_file(&self.engine, &wasm_path)
            .with_context(|| format!("Failed to load WASM module: {wasm_path}"))?;

        let workspace = format!("/var/lib/clawos/workspace/{}", tool);
        let ctx = HostCtx {
            job_id,
            tool_name: tool.to_string(),
            clawfs_path: workspace.clone(),
            http_allowlist: self.security.allowed_endpoints.iter().map(|e| e.host.clone()).collect(),
            allowed_read_paths: {
                let mut p = self.security.allowed_read_paths.clone();
                p.push(workspace.clone());
                p
            },
            allowed_write_paths: {
                let mut p = self.security.allowed_write_paths.clone();
                p.push(workspace.clone());
                p
            },
            call_depth: self.current_invoke_depth,
            memory_limiter: WasmMemoryLimiter {
                max_bytes: self.config.max_memory_bytes as usize,
            },
            scheduler_tx: self.scheduler_tx.clone(),
            clawfs: self.clawfs.clone(),
            llm_client: self.llm_client.clone(),
            http_client: self.http_client.clone(),
            security: self.security.clone(),
        };

        let mut store = Store::new(&self.engine, ctx);
        store.limiter(|ctx: &mut HostCtx| &mut ctx.memory_limiter);

        // Build linker with all ClawOS host functions + WASI
        let mut linker: Linker<HostCtx> = Linker::new(&self.engine);
        register_host_functions(&mut linker)?;

        // WASI is required for cdylib tools (memory allocator, stdout, etc.)

        let instance = linker
            .instantiate(&mut store, &module)
            .context("Failed to instantiate WASM module")?;

        // Call run(input_ptr, input_len) -> result via shared memory ABI
        let output_json = call_wasm_run(&mut store, &instance, input_json)
            .with_context(|| format!("WASM tool '{tool}' run() failed"))?;

        let val: serde_json::Value = serde_json::from_str(&output_json)
            .unwrap_or(serde_json::Value::String(output_json));
        Ok(val)
    }

    async fn run_llm_query(
        &self,
        messages: &[serde_json::Value],
        model: Option<&str>,
    ) -> Result<serde_json::Value> {
        if let Some(client) = &self.llm_client {
            let typed_messages: Vec<Message> = messages
                .iter()
                .filter_map(|m| {
                    Some(Message {
                        role: m["role"].as_str()?.to_string(),
                        content: m["content"].as_str().unwrap_or("").to_string(),
                    })
                })
                .collect();

            let req = CompletionRequest {
                model: model.unwrap_or("default").to_string(),
                messages: typed_messages,
                max_tokens: 1024,
                temperature: 0.2,
                tools: None,
                stream: false,
            };

            let resp = client.complete(req).await?;
            let content = LlmClient::extract_text(&resp);
            let tokens = resp.usage.total_tokens;

            return Ok(serde_json::json!({
                "content":       content,
                "model":         resp.model,
                "usage_tokens":  tokens,
                "finish_reason": resp.choices.first()
                    .map(|c| c.finish_reason.as_str())
                    .unwrap_or("unknown"),
            }));
        }

        warn!("LLM query requested but no LlmClient configured");
        Ok(serde_json::json!({
            "content":      "LLM provider not configured.",
            "model":        "none",
            "usage_tokens": 0,
            "finish_reason":"error",
        }))
    }

    async fn run_routine(&self, routine_id: &str) -> Result<serde_json::Value> {
        info!(routine = routine_id, "Running routine");
        Ok(serde_json::json!({ "status": "ok", "routine": routine_id }))
    }

    fn join_wasm_cgroup(&self) -> Result<()> {
        let pid = std::process::id();
        // Path derived from WasmConfig; falls back to hardcoded default.
        let cgroup_path = format!("{}/cgroup.procs", self.config.wasm_cgroup_path());
        match std::fs::write(&cgroup_path, pid.to_string()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!(path = %cgroup_path, "WASM cgroup not found — skipping");
                Ok(())
            }
            Err(e) => {
                tracing::warn!(path = %cgroup_path, error = %e, "WASM cgroup join failed — continuing");
                Ok(())
            }
        }
    }
}

// ── Core wasm run() caller ────────────────────────────────────
//
// Tools export: run(input_ptr: i32, input_len: i32) -> i32
// The return value is a pointer into WASM memory to a length-prefixed result:
//   [4 bytes LE u32 = length][length bytes JSON string]
// On error the JSON is: {"error": "..."}
//
// Tools also export: alloc(size: i32) -> i32  (malloc wrapper)
//                    dealloc(ptr: i32, size: i32)
//
// This matches the cdylib / wasm-bindgen-style ABI used in tools/.

fn call_wasm_run(
    store: &mut Store<HostCtx>,
    instance: &wasmtime::Instance,
    input_json: &str,
) -> Result<String> {
    let memory = instance
        .get_memory(&mut *store, "memory")
        .context("WASM module has no 'memory' export")?;

    let alloc_fn = instance.get_typed_func::<i32, i32>(&mut *store, "alloc")
        .context("WASM module missing 'alloc' export")?;
    let run_fn = instance.get_typed_func::<(i32, i32), i32>(&mut *store, "run")
        .context("WASM module missing 'run' export")?;
    let dealloc_fn = instance.get_typed_func::<(i32, i32), ()>(&mut *store, "dealloc").ok();

    let input_bytes = input_json.as_bytes();
    let input_len = input_bytes.len() as i32;

    // Allocate memory in WASM for the input string
    let input_ptr = alloc_fn.call(&mut *store, input_len)
        .context("WASM alloc() failed")?;

    // Write input into WASM memory
    memory.write(&mut *store, input_ptr as usize, input_bytes)
        .context("Failed to write input to WASM memory")?;

    // Call run(ptr, len) -> result_ptr
    let result_ptr = run_fn.call(&mut *store, (input_ptr, input_len))
        .context("WASM run() call failed")?;

    // Deallocate input buffer
    if let Some(dealloc) = &dealloc_fn {
        let _ = dealloc.call(&mut *store, (input_ptr, input_len));
    }

    if result_ptr == 0 {
        anyhow::bail!("WASM run() returned null pointer");
    }

    // Read result: [u32 LE length][json bytes]
    let mem_data = memory.data(&*store);
    let offset = result_ptr as usize;

    if offset + 4 > mem_data.len() {
        anyhow::bail!("WASM result pointer out of bounds");
    }
    let result_len = u32::from_le_bytes(
        mem_data[offset..offset + 4].try_into().unwrap()
    ) as usize;

    if offset + 4 + result_len > mem_data.len() {
        anyhow::bail!("WASM result length exceeds memory bounds");
    }
    let result_bytes = &mem_data[offset + 4..offset + 4 + result_len];
    let result_str = std::str::from_utf8(result_bytes)
        .context("WASM result is not valid UTF-8")?
        .to_string();

    // Deallocate result buffer (4 + len bytes)
    if let Some(dealloc) = &dealloc_fn {
        let _ = dealloc.call(&mut *store, (result_ptr, (4 + result_len) as i32));
    }

    Ok(result_str)
}

// ── Host function registration ────────────────────────────────
//
// Registers all ClawOS host functions into the core-wasm Linker.
// Symbol names match the extern "C" declarations in tools/*/src/lib.rs:
//
//   clawos_http_fetch    (web-search)
//   clawos_clawfs_read   (file-read, summarise)
//   clawos_clawfs_write  (future tools)
//   clawos_llm_complete  (summarise)
//   clawos_log_write     (all tools)
//
// Memory ABI for all functions (in/out):
//   *_ptr: pointer into WASM linear memory
//   *_len: byte length
//   out_ptr: pre-allocated output buffer (64 KiB)
//   return i32: bytes written into out buffer, or < 0 on error

fn register_host_functions(linker: &mut Linker<HostCtx>) -> Result<()> {
    // ── clawos_log_write ─────────────────────────────────────
    // fn clawos_log_write(level: i32, msg_ptr: *const u8, msg_len: usize)
    linker.func_wrap(
        "env",
        "clawos_log_write",
        |mut caller: Caller<'_, HostCtx>, level: i32, msg_ptr: i32, msg_len: i32| {
            let mem = match caller.get_export("memory") {
                Some(wasmtime::Extern::Memory(m)) => m,
                _ => return,
            };
            let data = mem.data(&caller);
            let s = read_wasm_str(data, msg_ptr, msg_len).unwrap_or_default();
            let tool = caller.data().tool_name.clone();
            match level {
                0 => tracing::trace!(source = "wasm", tool, "{s}"),
                1 => tracing::debug!(source = "wasm", tool, "{s}"),
                2 => tracing::info!(source = "wasm", tool, "{s}"),
                3 => tracing::warn!(source = "wasm", tool, "{s}"),
                _ => tracing::error!(source = "wasm", tool, "{s}"),
            }
        },
    )?;


    // ── clawos_secrets_get ─────────────────────────────────────
    // fn clawos_secrets_get(name_ptr, name_len, out_ptr, out_len) -> i32
    linker.func_wrap(
        "env",
        "clawos_secrets_get",
        |mut caller: Caller<'_, HostCtx>,
         name_ptr: i32,
         name_len: i32,
         out_ptr:  i32,
         out_len:  i32|
         -> i32 {
            let mem = match caller.get_export("memory") {
                Some(wasmtime::Extern::Memory(m)) => m,
                _ => return -1,
            };
            let name = {
                let data = mem.data(&caller);
                match read_wasm_str(data, name_ptr, name_len) {
                    Some(s) => s,
                    None    => return -1,
                }
            };
            let secret = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(
                    host_read_secret(&name)
                )
            });
            match secret {
                Ok(val) => write_wasm_output(mem, &mut caller, out_ptr, out_len, val.as_bytes()),
                Err(e)  => { warn!(error = %e, secret = %name, "WASM secrets_get failed"); -2 }
            }
        },
    )?;

    // ── clawos_http_fetch ─────────────────────────────────────
    // fn clawos_http_fetch(req_ptr, req_len, out_ptr, out_len) -> i32
    linker.func_wrap(
        "env",
        "clawos_http_fetch",
        |mut caller: Caller<'_, HostCtx>,
         req_ptr: i32,
         req_len: i32,
         out_ptr: i32,
         out_len: i32|
         -> i32 {
            let mem = match caller.get_export("memory") {
                Some(wasmtime::Extern::Memory(m)) => m,
                _ => return -1,
            };

            // Read request JSON from WASM memory
            let req_json = {
                let data = mem.data(&caller);
                match read_wasm_str(data, req_ptr, req_len) {
                    Some(s) => s,
                    None => return -1,
                }
            };

            // Perform HTTP fetch synchronously (we're in a sync WASM call context)
            let security = caller.data().security.clone();
            let http_client = caller.data().http_client.clone();

            let result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(
                    host_http_fetch(&http_client, &req_json, &security.allowed_endpoints)
                )
            });

            let response = match result {
                Ok(json) => json,
                Err(e) => {
                    warn!(error = %e, "WASM http_fetch failed");
                    serde_json::json!({"error": e}).to_string()
                }
            };

            write_wasm_output(mem, &mut caller, out_ptr, out_len, response.as_bytes())
        },
    )?;

    // ── clawos_clawfs_read ─────────────────────────────────────
    // fn clawos_clawfs_read(path_ptr, path_len, out_ptr, out_len) -> i32
    linker.func_wrap(
        "env",
        "clawos_clawfs_read",
        |mut caller: Caller<'_, HostCtx>,
         path_ptr: i32,
         path_len: i32,
         out_ptr: i32,
         out_len: i32|
         -> i32 {
            let mem = match caller.get_export("memory") {
                Some(wasmtime::Extern::Memory(m)) => m,
                _ => return -1,
            };

            let path = {
                let data = mem.data(&caller);
                match read_wasm_str(data, path_ptr, path_len) {
                    Some(s) => s,
                    None => return -1,
                }
            };

            // Path allowlist check
            let allowed = {
                let ctx = caller.data();
                ctx.allowed_read_paths.iter().any(|p| path.starts_with(p.as_str()))
            };
            if !allowed {
                warn!(path, "WASM clawfs_read blocked — path not in allowlist");
                return -2; // EPERM
            }

            let clawfs = caller.data().clawfs.clone();
            let data_bytes = match clawfs {
                Some(fs) => tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(fs.read_file(path.clone()))
                })
                .unwrap_or_else(|e| {
                    warn!(error = %e, path, "clawfs_read failed");
                    vec![]
                }),
                None => {
                    warn!("WASM clawfs_read called but no ClawFs handle attached");
                    vec![]
                }
            };

            write_wasm_output(mem, &mut caller, out_ptr, out_len, &data_bytes)
        },
    )?;

    // ── clawos_clawfs_write ────────────────────────────────────
    // fn clawos_clawfs_write(path_ptr, path_len, data_ptr, data_len) -> i32
    linker.func_wrap(
        "env",
        "clawos_clawfs_write",
        |mut caller: Caller<'_, HostCtx>,
         path_ptr: i32,
         path_len: i32,
         data_ptr: i32,
         data_len: i32|
         -> i32 {
            let mem = match caller.get_export("memory") {
                Some(wasmtime::Extern::Memory(m)) => m,
                _ => return -1,
            };

            let (path, data_bytes) = {
                let raw = mem.data(&caller);
                let path = match read_wasm_str(raw, path_ptr, path_len) {
                    Some(s) => s,
                    None => return -1,
                };
                let bytes = match read_wasm_bytes(raw, data_ptr, data_len) {
                    Some(b) => b,
                    None => return -1,
                };
                (path, bytes)
            };

            let allowed = {
                let ctx = caller.data();
                ctx.allowed_write_paths.iter().any(|p| path.starts_with(p.as_str()))
            };
            if !allowed {
                warn!(path, "WASM clawfs_write blocked — path not in allowlist");
                return -2;
            }

            let clawfs = caller.data().clawfs.clone();
            match clawfs {
                Some(fs) => {
                    let result = tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(fs.write_file(path.clone(), data_bytes))
                    });
                    match result {
                        Ok(()) => 0,
                        Err(e) => {
                            warn!(error = %e, path, "clawfs_write failed");
                            -3
                        }
                    }
                }
                None => {
                    warn!("WASM clawfs_write called but no ClawFs handle attached");
                    -1
                }
            }
        },
    )?;

    // ── clawos_llm_complete ────────────────────────────────────
    // fn clawos_llm_complete(req_ptr, req_len, out_ptr, out_len) -> i32
    linker.func_wrap(
        "env",
        "clawos_llm_complete",
        |mut caller: Caller<'_, HostCtx>,
         req_ptr: i32,
         req_len: i32,
         out_ptr: i32,
         out_len: i32|
         -> i32 {
            let mem = match caller.get_export("memory") {
                Some(wasmtime::Extern::Memory(m)) => m,
                _ => return -1,
            };

            let req_json = {
                let data = mem.data(&caller);
                match read_wasm_str(data, req_ptr, req_len) {
                    Some(s) => s,
                    None => return -1,
                }
            };

            let llm_client = caller.data().llm_client.clone();
            let result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(
                    host_llm_complete(&llm_client, &req_json)
                )
            });

            let response = match result {
                Ok(json) => json,
                Err(e) => {
                    warn!(error = %e, "WASM llm_complete failed");
                    serde_json::json!({"error": e}).to_string()
                }
            };

            write_wasm_output(mem, &mut caller, out_ptr, out_len, response.as_bytes())
        },
    )?;

    Ok(())
}

// ── Memory helpers ────────────────────────────────────────────

fn read_wasm_str(data: &[u8], ptr: i32, len: i32) -> Option<String> {
    let bytes = read_wasm_bytes(data, ptr, len)?;
    String::from_utf8(bytes).ok()
}

fn read_wasm_bytes(data: &[u8], ptr: i32, len: i32) -> Option<Vec<u8>> {
    if ptr < 0 || len < 0 { return None; }
    let start = ptr as usize;
    let end = start.checked_add(len as usize)?;
    if end > data.len() { return None; }
    Some(data[start..end].to_vec())
}

/// Write bytes into the WASM out_ptr buffer.
/// Returns number of bytes written, or -1 if buffer too small.
fn write_wasm_output(
    mem: wasmtime::Memory,
    caller: &mut Caller<'_, HostCtx>,
    out_ptr: i32,
    out_len: i32,
    bytes: &[u8],
) -> i32 {
    if out_ptr < 0 || out_len < 0 { return -1; }
    let write_len = bytes.len().min(out_len as usize);
    if mem.write(caller, out_ptr as usize, &bytes[..write_len]).is_err() {
        return -1;
    }
    write_len as i32
}

// ── Host function implementations ─────────────────────────────

async fn host_http_fetch(
    client: &HttpClient,
    req_json: &str,
    allowlist: &[crate::config::AllowedEndpoint],
) -> Result<String, String> {
    let req: serde_json::Value =
        serde_json::from_str(req_json).map_err(|e| format!("Invalid request JSON: {e}"))?;

    let method = req["method"].as_str().unwrap_or("GET").to_uppercase();
    let url = req["url"].as_str().ok_or("Missing 'url' field")?;
    let body = req["body"].as_str().map(|s| s.to_string());

    let parsed = url
        .parse::<reqwest::Url>()
        .map_err(|e| format!("Invalid URL: {e}"))?;
    let host = parsed.host_str().unwrap_or("");
    let path = parsed.path();

    let allowed = allowlist.iter().any(|ep| {
        ep.host == host
            && ep.methods.iter().any(|m| m.eq_ignore_ascii_case(&method))
            && (ep.paths.is_empty() || ep.paths.iter().any(|p| path.starts_with(p.as_str())))
    });

    if !allowed {
        warn!(host, method, path, "WASM HTTP fetch blocked — not in allowlist");
        return Err(format!("Host '{host}' not in allowed_endpoints"));
    }

    let mut rb = client.request(
        method.parse::<reqwest::Method>().map_err(|e| e.to_string())?,
        url,
    );

    if let Some(headers) = req["headers"].as_array() {
        for pair in headers {
            if let (Some(k), Some(v_raw)) = (pair[0].as_str(), pair[1].as_str()) {
                let v = substitute_secrets(v_raw).await;
                rb = rb.header(k, v);
            }
        }
    }

    if let Some(b) = body {
        rb = rb.body(b).header("Content-Type", "application/json");
    }

    let resp = rb.send().await.map_err(|e| format!("HTTP error: {e}"))?;
    let status = resp.status().as_u16();
    let resp_body = resp.text().await.unwrap_or_default();

    Ok(serde_json::json!({
        "status": status,
        "body":   resp_body,
        "headers": []
    })
    .to_string())
}

async fn substitute_secrets(value: &str) -> String {
    if !value.contains("{{") {
        return value.to_string();
    }
    let mut result = value.to_string();
    let mut start = 0;
    while let Some(open) = result[start..].find("{{") {
        let abs_open = start + open;
        if let Some(close) = result[abs_open..].find("}}") {
            let name = &result[abs_open + 2..abs_open + close];
            if let Ok(secret) = host_read_secret(name).await {
                result = format!(
                    "{}{}{}",
                    &result[..abs_open],
                    secret,
                    &result[abs_open + close + 2..]
                );
                start = abs_open + secret.len();
            } else {
                start = abs_open + close + 2;
            }
        } else {
            break;
        }
    }
    result
}

async fn host_read_secret(name: &str) -> Result<String, String> {
    // 1. Try kernel keyring via keyctl
    let keyctl = tokio::process::Command::new("keyctl")
        .args(["search", "@s", "user", name])
        .output()
        .await;

    if let Ok(out) = keyctl {
        if out.status.success() {
            let key_id = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let pipe = tokio::process::Command::new("keyctl")
                .args(["pipe", &key_id])
                .output()
                .await;
            if let Ok(pipe_out) = pipe {
                if pipe_out.status.success() {
                    return Ok(String::from_utf8_lossy(&pipe_out.stdout).trim().to_string());
                }
            }
        }
    }

    // 2. Env fallback (dev mode)
    let env_name = name.to_uppercase().replace('-', "_");
    if let Ok(val) = std::env::var(&env_name) {
        if !val.is_empty() {
            return Ok(val);
        }
    }

    Err(format!("Secret '{name}' not found in keyring or environment"))
}

async fn host_llm_complete(client: &Option<LlmClient>, req_json: &str) -> Result<String, String> {
    let client = client.as_ref().ok_or("LLM client not configured")?;

    let req_val: serde_json::Value =
        serde_json::from_str(req_json).map_err(|e| format!("Invalid LLM request JSON: {e}"))?;

    let messages: Vec<Message> = req_val["messages"]
        .as_array()
        .ok_or("Missing messages array")?
        .iter()
        .filter_map(|m| {
            Some(Message {
                role: m["role"].as_str()?.to_string(),
                content: m["content"].as_str().unwrap_or("").to_string(),
            })
        })
        .collect();

    let max_tokens = req_val["max_tokens"].as_u64().unwrap_or(512) as u32;
    let temperature = req_val["temperature"].as_f64().unwrap_or(0.3) as f32;
    let model = req_val["model"].as_str().unwrap_or("default").to_string();

    let req = CompletionRequest {
        model,
        messages,
        max_tokens,
        temperature,
        tools: None,
        stream: false,
    };

    let resp = client.complete(req).await.map_err(|e| e.to_string())?;

    serde_json::to_string(&serde_json::json!({
        "choices": [{
            "message": {
                "role":    "assistant",
                "content": LlmClient::extract_text(&resp)
            },
            "finish_reason": resp.choices.first().map(|c| c.finish_reason.as_str()).unwrap_or("stop")
        }],
        "usage": {
            "total_tokens": resp.usage.total_tokens
        }
    })).map_err(|e| e.to_string())
}
