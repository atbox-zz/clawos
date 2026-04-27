// ClawOS Agent — main entry point
// Phase: P2 skeleton (engine structure, no business data)
//
// Startup order (MUST follow this sequence):
//   1. Load config (before seccomp — needs file reads)
//   2. Join cgroup (before seccomp — needs /sys writes)
//   3. Apply seccomp filter (lock down syscalls)
//   4. Init WASM runtime (under seccomp protection)
//   5. Init ClawFS connection
//   6. Start IPC listener
//   7. Run agent loop

#![allow(dead_code)]
use anyhow::Result;
//use tracing::{error, info, warn, Level};
use tracing::{error, info, warn};

mod agent;
mod config;
mod ipc;
mod router;
mod scheduler;
mod shell;
mod worker;

#[tokio::main]
async fn main() -> Result<()> {
    // ── Parse flags before logging init ─────────────────────
    let args: Vec<String> = std::env::args().collect();
    let smoke_test  = args.iter().any(|a| a == "--smoke-test");
    let single_shot = args.iter().any(|a| a == "--single-shot");
    let shell_mode  = args.iter().any(|a| a == "--shell");
    let migrate_enc = args.iter().any(|a| a == "--migrate-encrypt-pass");

    // ── 1. Logging ───────────────────────────────────────────
    init_tracing();
    info!(
        version = env!("CARGO_PKG_VERSION"),
        pid = std::process::id(),
        "1. Claw Agent starting"
    );

    // ── 2. Config ────────────────────────────────────────────
    let config = config::Config::load().await
        .map_err(|e| {
            error!(error = %e, "Config load failed — set CLAWOS_CONFIG or create /etc/clawos/config.toml");
            e
        })?;
    info!(profile = %config.profile, "2. Config loaded");

    // Smoke test: verify we can start cleanly, then exit
    if smoke_test {
        info!("2. Smoke test: startup OK");
        std::process::exit(0);
    }

    // ── 3. Join cgroup ───────────────────────────────────────
    join_cgroup(&config)?;
    info!("3. Joined cgroup: {}", config.cgroup_path);

    // ── 4. Apply seccomp ─────────────────────────────────────
    clawos_seccomp::apply_filter()?;
    info!("4. seccomp-BPF filter loaded — locked to whitelist v1.0");

    // ── 5. Init WASM runtime ─────────────────────────────────
    let wasm_engine = init_wasm_engine(&config)?;
    info!("5. WASM engine initialized");

    // ── 6. Init ClawFS ───────────────────────────────────────
    let clawfs = clawfs::ClawFs::connect(&config.clawfs).await?;
    info!("6. ClawFS connected");

    // Migration re-encryption pass
    if migrate_enc {
        info!("Running encryption migration pass (--migrate-encrypt-pass)");
        run_migration_reencrypt(&clawfs).await?;
        return Ok(());
    }

    // ── 7. Start IPC listener ─────────────────────────────────
    let ipc_handle = ipc::Server::start(&config.ipc_socket).await?;
    info!(socket = %config.ipc_socket, "7. IPC listener started");


    // ── 8. Start channels ────────────────────────────────────
    let (broadcast_tx, _) = tokio::sync::broadcast::channel::<web_gateway::GatewayEvent>(256);

    if config.channels.web_gateway.enabled {
        match web_gateway::load_bearer_token() {
            Ok(token) => {
                let (gw_tx, mut gw_rx) = tokio::sync::mpsc::channel::<web_gateway::InboundMsg>(128);
                let state = web_gateway::GatewayState {
                    agent_tx:     gw_tx,
                    broadcast:    broadcast_tx.clone(),
                    bearer_token: std::sync::Arc::new(token),
                };
                let bind = config.channels.web_gateway.bind.clone();
                tokio::spawn(async move {
                    if let Err(e) = web_gateway::serve(&bind, state).await {
                        tracing::error!(error = %e, "8. Web gateway exited");
                    }
                });
                info!(bind = %config.channels.web_gateway.bind, "8. Web gateway started");
                // Forward gateway messages to IPC socket
                let ipc_socket = config.ipc_socket.clone();
                tokio::spawn(async move {
                    while let Some(msg) = gw_rx.recv().await {
                        forward_to_ipc(&ipc_socket, &msg.session_id, &msg.content).await;
                    }
                });
            }
            Err(e) => warn!(error = %e, "8. Web gateway disabled — no bearer token"),
        }
    }

    if config.channels.telegram.enabled {
        let port = config.channels.telegram.webhook_port;
        let ipc_socket = config.ipc_socket.clone();
        tokio::spawn(async move {
            if let Err(e) = start_telegram_webhook(port, ipc_socket).await {
                tracing::error!(error = %e, "Telegram webhook exited");
            }
        });
        info!(port, "Telegram webhook started");
    }

    // ── 9. Shell or agent loop ───────────────────────────────
    if shell_mode {
        info!("9. Starting clawsh (Layer 7 AI Shell)");
        let (agent_tx, _agent_rx) = tokio::sync::mpsc::channel(128);
        let mut sh = shell::Shell::new(agent_tx);
        sh.run().await?;
    } else if single_shot {
        // Read one message from stdin, send to agent, print reply, exit
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let input = line.trim().to_string();
        if input.is_empty() {
            error!("Single-shot mode: no input provided on stdin");
            std::process::exit(1);
        }
        info!(input = %input, "9. Single-shot mode");
        let reply = agent::run_single_shot(wasm_engine, clawfs, config, input).await?;
        println!("{reply}");
    } else {
        info!("9. Entering agent loop");
        agent::run(wasm_engine, clawfs, ipc_handle, config).await?;
    }

    info!("ClawOS Agent shutting down cleanly");
    Ok(())
}

/// Re-encrypt all files written by the migration script as plaintext.
/// The migration script wraps plaintext with CLAWFS_MIGRATION_PLAINTEXT_TAG
/// (first 28 bytes) to signal they need AES-256-GCM encryption.
async fn run_migration_reencrypt(clawfs: &clawfs::ClawFs) -> Result<()> {
    const TAG: &[u8] = b"\x00CLAWFS_MIGRATION_PLAINTEXT\x00";
    const TAG_LEN: usize = 28;

    info!("Re-encryption pass: scanning for migration-plaintext files");

    let paths = clawfs.list_dir("/".to_string()).await?;
    let mut re_encrypted = 0usize;

    for path in &paths {
        // Read raw blob — ClawFS read_file will decrypt; migration blobs are
        // "encrypted" as passthrough (key_source=dev_random or the migration tag).
        // We detect by attempting to read and checking for the magic header.
        // In practice the migration wrote with migration_wrap(), so the stored blob
        // starts with TAG. We read via the underlying DB directly here.
        match clawfs.read_file(path.clone()).await {
            Ok(plaintext) if plaintext.starts_with(TAG) => {
                let real_data = &plaintext[TAG_LEN..];
                match clawfs.write_file(path.clone(), real_data.to_vec()).await {
                    Ok(()) => {
                        info!(path, "Re-encrypted migration file");
                        re_encrypted += 1;
                    }
                    Err(e) => {
                        error!(path, error = %e, "Failed to re-encrypt migration file");
                    }
                }
            }
            Ok(_) => {} // already encrypted, skip
            Err(e) => {
                warn!(path, error = %e, "Could not read file during re-encryption pass");
            }
        }
    }

    info!(
        re_encrypted,
        total = paths.len(),
        "Re-encryption pass complete"
    );
    Ok(())
}

fn join_cgroup(config: &config::Config) -> Result<()> {
    let pid = std::process::id();
    // Try the scope subdir first (systemd-managed), fall back to the slice root.
    // Failure is non-fatal in dev — agent continues without cgroup membership.
    let candidates = [
        format!("{}/clawos-agent.scope/cgroup.procs", config.cgroup_path),
        format!("{}/cgroup.procs", config.cgroup_path),
    ];
    for procs_path in &candidates {
        match std::fs::write(procs_path, pid.to_string()) {
            Ok(()) => {
                tracing::debug!(path = %procs_path, pid, "Joined cgroup");
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                tracing::warn!(path = %procs_path, error = %e, "cgroup join failed — continuing without isolation");
                return Ok(());
            }
        }
    }
    tracing::warn!(cgroup_path = %config.cgroup_path, "cgroup not found — run scripts/setup-cgroups.sh");
    Ok(()) // non-fatal
}

fn init_wasm_engine(config: &config::Config) -> Result<wasmtime::Engine> {
    let mut wasm_config = wasmtime::Config::new();
    wasm_config
        .async_support(true)

        .memory_init_cow(true) // CoW pages for efficiency
        .max_wasm_stack(config.wasm.max_stack_bytes as usize)
        .cranelift_opt_level(wasmtime::OptLevel::Speed);

    Ok(wasmtime::Engine::new(&wasm_config)?)
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    fmt()
        .with_env_filter(
            EnvFilter::try_from_env("CLAWOS_LOG").unwrap_or_else(|_| EnvFilter::new("clawos=info")),
        )
        .with_target(true)
        .with_thread_ids(true)
        .json() // structured JSON logs for ClawFS ingestion
        .init();
}


async fn forward_to_ipc(socket_path: &str, session_id: &str, content: &str) {
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;

    let msg = serde_json::json!({
        "id":        uuid::Uuid::new_v4().to_string(),
        "version":   1,
        "type":      "task.status",
        "from":      "clawos-channel-web-gateway",
        "to":        "clawos-agent",
        "timestamp": chrono::Utc::now().timestamp_millis(),
        "payload":   { "task_id": session_id, "status": "pending", "input": content }
    });

    if let Ok(mut stream) = UnixStream::connect(socket_path).await {
        let line = format!("{}\n", msg);
        let _ = stream.write_all(line.as_bytes()).await;
    }
}

async fn start_telegram_webhook(port: u16, ipc_socket: String) -> anyhow::Result<()> {
  //use axum::{extract::State, routing::post, Json, Router};
    use axum::{                routing::post, Json, Router};

    let state = std::sync::Arc::new(ipc_socket);

    async fn webhook(
        axum::extract::State(sock): axum::extract::State<std::sync::Arc<String>>,
        Json(update): Json<serde_json::Value>,
    ) {
        let chat_id  = update["message"]["chat"]["id"].as_i64().unwrap_or(0).to_string();
        let text     = update["message"]["text"].as_str().unwrap_or("").to_string();
        if !text.is_empty() {
            forward_to_ipc(&sock, &chat_id, &text).await;
        }
    }

    let app = Router::new()
        .route("/webhook", post(webhook))
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    tracing::info!(addr, "Telegram webhook listening");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
