// ClawOS Core Development Library
// Agent Loop Service - systemd-like daemon orchestrator
//
// This library provides the core orchestration service for ClawOS,
// implementing the Agent Loop as a systemd-like daemon with:
// - IPC protocol (Unix Domain Sockets)
// - Heartbeat monitoring (30s interval, 90s watchdog)
// - seccomp-BPF security filtering
// - Namespace isolation
// - ClawFS integration (SQLite + HNSW)
// - Public API mapping (P1.8)

pub mod agent_loop_service;
pub mod ipc;
pub mod security;
pub mod clawfs;
pub mod public_api;
pub mod error;
pub mod channels;

pub use agent_loop_service::{AgentLoopService, ServiceConfig};
pub use ipc::{Message, MessageType, Error as IpcError, ErrorCode};
pub use security::{SeccompFilter, NamespaceIsolator};
pub use clawfs::ClawFS;
pub use public_api::{ClawOSApi, ProcSpawnArgs, MetricValue};
pub use channels::{ChannelConfig, ChannelType, InterfaceType, SseEvent, WsMessage};
pub use error::{Error, Result, VERSION, PROTOCOL_VERSION};


