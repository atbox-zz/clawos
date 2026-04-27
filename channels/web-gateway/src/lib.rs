// channels/web-gateway/src/lib.rs
//
// ClawOS Web Gateway channel — P3.2
// SSE (Server-Sent Events) + WebSocket gateway.
// Replaces IronClaw channels-src/web_gateway.
// Runs as an axum HTTP server inside the agent's network namespace.
//
// Security hardening (audit #4 — patch):
//   FIX C-03: bearer token authentication on all non-health endpoints.
//             Token is loaded from the kernel keyring (secret name
//             "clawos-gateway-token") at startup; callers must supply
//             `Authorization: Bearer <token>` on every request.
//   FIX M-04: message length cap (MAX_MESSAGE_LEN = 4096 bytes) applied
//             to both REST body and SSE query parameter before the message
//             is forwarded to the agent.
#![allow(dead_code)]
use anyhow::Result;
use axum::response::IntoResponse;
use axum::{
    http::{header, StatusCode, HeaderValue},
    extract::{Request, State, WebSocketUpgrade, ws::{WebSocket, Message}},
    middleware::{self, Next},
    response::{Sse, sse::Event, Response},
    routing::{get, post},
    Json, Router,
};

//use axum::{
//    extract::Request,
//    middleware::Next,
//    response::{Response, IntoResponse},
//    http::{header, StatusCode, HeaderValue},
//};
use futures_util::{stream::StreamExt};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, convert::Infallible, time::Duration};
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::BroadcastStream;
use tracing::{info, warn, debug};
use uuid::Uuid;

// ── Constants ─────────────────────────────────────────────────

/// Maximum allowed message length in bytes (applies to all inbound paths).
/// Prevents memory exhaustion and LLM token abuse.
const MAX_MESSAGE_LEN: usize = 4096;

// ── Types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    pub message:    String,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    pub id:         String,
    pub content:    String,
    pub session_id: String,
    pub done:       bool,
}

#[derive(Debug, Clone)]
pub struct GatewayEvent {
    pub session_id: String,
    pub content:    String,
    pub done:       bool,
}

// ── Gateway State ─────────────────────────────────────────────

#[derive(Clone)]
pub struct GatewayState {
    /// Send messages to the agent
    pub agent_tx: mpsc::Sender<InboundMsg>,
    /// Receive streamed responses from the agent
    pub broadcast: broadcast::Sender<GatewayEvent>,
    /// Pre-shared bearer token for authenticating requests (FIX C-03).
    /// Loaded from kernel keyring / env at startup; never logged.
    pub bearer_token: Arc<String>,
}

pub struct InboundMsg {
    pub session_id: String,
    pub content:    String,
}

// ── FIX C-03: Bearer token authentication middleware ──────────
//
// All routes except /health require a valid `Authorization: Bearer <token>`
// header.  The token is compared in constant time to prevent timing attacks.

// 修改 before
//async fn require_bearer<B>( State(state): State<Arc<GatewayState>>, req: Request<B>, next: Next<B>,) -> Result<Response, StatusCode> {
// 修改 after (Axum 0.7 寫法)
//use axum::{extract::Request, middleware::Next, response::Response};
async fn require_bearer(
    State(state): State<Arc<GatewayState>>,
    req: Request,
    next: Next,
) -> Response {
    let auth_header = req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|v: &HeaderValue| v.to_str().ok());

    let token_matches = auth_header
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|token| {
            constant_time_eq(token.as_bytes(), state.bearer_token.as_bytes())
        })
        .unwrap_or(false);

    if token_matches {
        next.run(req).await
    } else {
        warn!("Web gateway: unauthorized request — invalid or missing bearer token");
        StatusCode::UNAUTHORIZED.into_response()
    }
}
/// Constant-time byte-slice comparison to prevent timing side-channels.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ── Token loading ─────────────────────────────────────────────
//
// Priority order (mirrors crypto.rs key loading):
//   1. Kernel keyring  (keyctl pipe @s user clawos-gateway-token)
//   2. CLAWOS_GATEWAY_TOKEN environment variable
//
// If neither is available the server refuses to start.  This prevents
// accidental unauthenticated deployments.

// ❌ 現在（錯誤）：
//pub fn load_bearer_token() -> Result<String> {
    // Try kernel keyring first
    //let keyring_result = std::process::Command::new("keyctl")
    //    .args(["pipe", "@s", "user", "clawos-gateway-token"])
    //    .output();

    //if let Ok(out) = keyring_result {
    //    if out.status.success() && !out.stdout.is_empty() {
    //        let token = String::from_utf8(out.stdout)
    //            .map(|s| s.trim().to_string())
    //            .map_err(|e| anyhow::anyhow!("keyring token not valid UTF-8: {e}"))?;
    //        if !token.is_empty() {
    //            info!("Web gateway: bearer token loaded from kernel keyring");
    //            return Ok(token);
    //        }
    //    }
    //}
// ✅ 修復：兩步驟 — 先 search 取得 key-id，再 pipe
pub fn load_bearer_token() -> Result<String> {
    // Step 1: 取得 key-id
    let search = std::process::Command::new("keyctl")
        .args(["search", "@u", "user", "clawos-gateway-token"])  // @u 對齊 install.sh
        .output();

    if let Ok(out) = search {
        if out.status.success() {
            let key_id = String::from_utf8_lossy(&out.stdout).trim().to_string();
            // Step 2: 用 key-id 讀取值
            let pipe = std::process::Command::new("keyctl")
                .args(["pipe", &key_id])
                .output();
            if let Ok(p) = pipe {
                if p.status.success() && !p.stdout.is_empty() {
                    let token = String::from_utf8(p.stdout)
                        .map(|s| s.trim().to_string())
                        .map_err(|e| anyhow::anyhow!("keyring token not valid UTF-8: {e}"))?;
                    if !token.is_empty() {
                        info!("Web gateway: bearer token loaded from kernel keyring");
                        return Ok(token);
                    }
                }
            }
        }
    }
    // Fallback: environment variable
    match std::env::var("CLAWOS_GATEWAY_TOKEN") {
        Ok(token) if !token.is_empty() => {
            // Error-level so operators notice in production logs.
            tracing::error!(
                "Web gateway: bearer token loaded from CLAWOS_GATEWAY_TOKEN env var. \
                 Set up kernel keyring for production deployments."
            );
            Ok(token)
        }
        _ => anyhow::bail!(
            "Web gateway bearer token not configured. \
             Set kernel keyring key 'clawos-gateway-token' or env var CLAWOS_GATEWAY_TOKEN."
        ),
    }
}

// ── Router / Server ───────────────────────────────────────────

pub fn build_router(state: GatewayState) -> Router {
    let shared = Arc::new(state);

    // Authenticated sub-router (all chat endpoints)
    let authenticated = Router::new()
        .route("/v1/chat",        post(chat_rest))
        .route("/v1/chat/stream", get(chat_sse))
        .route("/v1/ws",          get(chat_ws))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&shared),
            require_bearer,
        ));

    Router::new()
        .route("/health", get(health))   // unauthenticated health probe
        .merge(authenticated)
        .with_state(shared)
}

/// Start the web gateway on the given address.
/// Typically: 127.0.0.1:8080 inside the network namespace.
pub async fn serve(addr: &str, state: GatewayState) -> Result<()> {
    let app = build_router(state);
    info!(addr, "Web gateway listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// ── Handlers ──────────────────────────────────────────────────

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "clawos-web-gateway" }))
}

/// Truncate a message to MAX_MESSAGE_LEN bytes (FIX M-04).
/// Truncation is on a UTF-8 char boundary to avoid splitting multibyte sequences.
fn truncate_message(s: String) -> String {
    if s.len() <= MAX_MESSAGE_LEN {
        return s;
    }
    warn!(
        original_len = s.len(),
        max = MAX_MESSAGE_LEN,
        "Web gateway: message truncated to MAX_MESSAGE_LEN"
    );
    // Find the largest char boundary ≤ MAX_MESSAGE_LEN
    let mut end = MAX_MESSAGE_LEN;
    while !s.is_char_boundary(end) { end -= 1; }
    s[..end].to_string()
}

/// POST /v1/chat — synchronous REST endpoint
async fn chat_rest(
    State(state): State<Arc<GatewayState>>,
    Json(req): Json<ChatRequest>,
) -> Json<ChatResponse> {
    let session_id = req.session_id.clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    // FIX M-04: cap message length before forwarding to agent
    let message = truncate_message(req.message);

    let _ = state.agent_tx.send(InboundMsg {
        session_id: session_id.clone(),
        content:    message,
    }).await;

    // Wait for response on broadcast channel (take first matching done event)
    let mut rx = state.broadcast.subscribe();
    let content = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(evt) = rx.recv().await {
                if evt.session_id == session_id && evt.done {
                    return evt.content;
                }
            }
        }
    }).await.unwrap_or_else(|_| "Request timed out".to_string());

    Json(ChatResponse {
        id: Uuid::new_v4().to_string(),
        content,
        session_id,
        done: true,
    })
}

/// GET /v1/chat/stream?message=...&session_id=... — SSE streaming
async fn chat_sse(
    State(state): State<Arc<GatewayState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let session_id = params.get("session_id")
        .cloned()
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    // FIX M-04: cap message length
    let message = truncate_message(params.get("message").cloned().unwrap_or_default());

    let _ = state.agent_tx.send(InboundMsg {
        session_id: session_id.clone(),
        content:    message,
    }).await;

    let rx = state.broadcast.subscribe();
    let sid = session_id.clone();

    let stream = BroadcastStream::new(rx)
        .filter_map(move |result| {
            let sid = sid.clone();
            async move {
                let evt = result.ok()?;
                if evt.session_id != sid { return None; }

                let data = serde_json::json!({
                    "content":    evt.content,
                    "session_id": evt.session_id,
                    "done":       evt.done,
                });

                Some(Ok::<Event, Infallible>(
                    Event::default().data(data.to_string())
                ))
            }
        });

    Sse::new(stream)
        .keep_alive(axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("heartbeat"))
}

/// GET /v1/ws — WebSocket connection
async fn chat_ws(
    State(state): State<Arc<GatewayState>>,
    ws: WebSocketUpgrade,
) -> impl axum::response::IntoResponse {
    ws.on_upgrade(move |socket| handle_websocket(socket, state))
}

async fn handle_websocket(mut socket: WebSocket, state: Arc<GatewayState>) {
    let session_id = Uuid::new_v4().to_string();
    let mut broadcast_rx = state.broadcast.subscribe();
    info!(session_id, "WebSocket connected");

    loop {
        tokio::select! {
            Some(msg_result) = socket.recv() => {
                match msg_result {
                    Ok(Message::Text(text)) => {
                        // FIX M-04: cap inbound WS message length
                        let content = truncate_message(text);
                        debug!(session_id, "WS message received");
                        let _ = state.agent_tx.send(InboundMsg {
                            session_id: session_id.clone(),
                            content,
                        }).await;
                    }
                    Ok(Message::Close(_)) | Err(_) => {
                        info!(session_id, "WebSocket disconnected");
                        break;
                    }
                    _ => {}
                }
            }

            Ok(evt) = broadcast_rx.recv() => {
                if evt.session_id != session_id { continue; }
                let payload = serde_json::json!({
                    "content": evt.content,
                    "done":    evt.done,
                }).to_string();

                if socket.send(Message::Text(payload)).await.is_err() {
                    break;
                }

                if evt.done { break; }
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn health_returns_ok() {
        let resp = health().await;
        assert_eq!(resp.0["status"].as_str(), Some("ok"));
    }

    #[test]
    fn gateway_event_clone() {
        let evt = GatewayEvent {
            session_id: "test".into(),
            content:    "hello".into(),
            done:       false,
        };
        let cloned = evt.clone();
        assert_eq!(cloned.session_id, "test");
    }

    // ── C-03: constant_time_eq ──────────────────────────────────

    #[test]
    fn constant_time_eq_correct() {
        assert!( constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"Secret"));
        assert!(!constant_time_eq(b"secret", b"secre"));
        assert!(!constant_time_eq(b"",       b"x"));
        assert!( constant_time_eq(b"",       b""));
    }

    // ── M-04: message truncation ────────────────────────────────

    #[test]
    fn short_message_not_truncated() {
        let msg = "hello world".to_string();
        assert_eq!(truncate_message(msg.clone()), msg);
    }

    #[test]
    fn long_message_truncated_at_char_boundary() {
        let long = "x".repeat(MAX_MESSAGE_LEN + 100);
        let result = truncate_message(long);
        assert_eq!(result.len(), MAX_MESSAGE_LEN);
    }

    #[test]
    fn multibyte_message_truncated_at_valid_boundary() {
        // "日" is 3 bytes in UTF-8; fill to just over MAX_MESSAGE_LEN
        let n = MAX_MESSAGE_LEN / 3 + 5;
        let long: String = "日".repeat(n);
        let result = truncate_message(long);
        // Must be valid UTF-8 (no panic) and ≤ MAX_MESSAGE_LEN bytes
        assert!(result.len() <= MAX_MESSAGE_LEN);
        assert!(std::str::from_utf8(result.as_bytes()).is_ok());
    }
}
