// ClawOS Agent Loop Service
// systemd-like daemon orchestrator for ClawOS
//
// This service implements the core orchestration layer for ClawOS, replacing
// the IronClaw agent loop with a systemd-like daemon that:
// - Manages inter-component communication via IPC (P1.7)
// - Integrates with ClawFS for persistent storage (P1.4)
// - Applies seccomp-BPF security filters (P1.2, P2.2)
// - Enforces namespace isolation (P2.4)
// - Exposes public API surface (P1.8)
// - Implements heartbeat monitoring (30s interval, 90s watchdog)
// - Integrates with systemd for service management (Phase 2, G-02)

use crate::error::{Error, Result};
use crate::ipc::{Message, MessageType, ErrorCode, IpcClient, IpcServer};
use crate::security::{SeccompFilter, NamespaceIsolator};
use crate::clawfs::ClawFS;
use crate::public_api::{ClawOSApi, ProcSpawnArgs, MetricValue};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, mpsc, oneshot};
use tokio::time::{interval, Instant};
use uuid::Uuid;
use log::{debug, info, warn, error};

// ============================================================================
// Configuration
// ============================================================================

/// Service configuration for the Agent Loop daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// IPC socket path (abstract namespace)
    pub ipc_socket_path: String,

    /// ClawFS root directory
    pub clawfs_root: PathBuf,

    /// Heartbeat interval in seconds (default: 30)
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,

    /// Watchdog timeout in seconds (default: 90)
    #[serde(default = "default_watchdog_timeout")]
    pub watchdog_timeout_secs: u64,

    /// Maximum concurrent tasks
    #[serde(default = "default_max_concurrent_tasks")]
    pub max_concurrent_tasks: usize,

    /// Enable systemd integration
    #[serde(default = "default_systemd_integration")]
    pub systemd_integration: bool,

    /// seccomp filter path (JSON format from P1.2)
    pub seccomp_filter_path: Option<PathBuf>,

    /// Enable namespace isolation
    #[serde(default = "default_namespace_isolation")]
    pub namespace_isolation: bool,
}

fn default_heartbeat_interval() -> u64 { 30 }
fn default_watchdog_timeout() -> u64 { 90 }
fn default_max_concurrent_tasks() -> usize { 100 }
fn default_systemd_integration() -> bool { true }
fn default_namespace_isolation() -> bool { true }

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            ipc_socket_path: "@clawos-ipc-agent-loop".to_string(),
            clawfs_root: PathBuf::from("/clawfs"),
            heartbeat_interval_secs: default_heartbeat_interval(),
            watchdog_timeout_secs: default_watchdog_timeout(),
            max_concurrent_tasks: default_max_concurrent_tasks(),
            systemd_integration: default_systemd_integration(),
            seccomp_filter_path: None,
            namespace_isolation: default_namespace_isolation(),
        }
    }
}

// ============================================================================
// Component Health Status
// ============================================================================

/// Health status of a connected component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component identifier
    pub component_id: String,

    /// Last heartbeat timestamp
    pub last_heartbeat: DateTime<Utc>,

    /// Health status
    pub status: HealthStatus,

    /// Component metrics
    pub metrics: ComponentMetrics,

    /// Number of missed heartbeats
    pub missed_heartbeats: u32,
}

/// Health status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Component operating normally
    Ok,
    /// Component experiencing issues but functional
    Degraded,
    /// Component near failure
    Critical,
    /// Component unresponsive
    Unresponsive,
}

/// Component metrics from heartbeat
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentMetrics {
    /// Uptime in nanoseconds
    pub uptime_ns: u64,

    /// Total messages processed
    pub messages_processed: u64,

    /// Total messages failed
    pub messages_failed: u64,

    /// Memory usage in bytes
    pub memory_usage_bytes: u64,

    /// CPU usage percentage (0-100)
    pub cpu_usage_percent: f64,

    /// Active connections
    pub active_connections: u32,
}

impl Default for ComponentMetrics {
    fn default() -> Self {
        Self {
            uptime_ns: 0,
            messages_processed: 0,
            messages_failed: 0,
            memory_usage_bytes: 0,
            cpu_usage_percent: 0.0,
            active_connections: 0,
        }
    }
}

// ============================================================================
// Task Management
// ============================================================================

/// Task execution context
#[derive(Debug, Clone)]
pub struct TaskContext {
    /// Unique task ID
    pub task_id: Uuid,

    /// Task type
    pub task_type: TaskType,

    /// Task creation time
    pub created_at: DateTime<Utc>,

    /// Task status
    pub status: TaskStatus,

    /// Associated component
    pub component_id: Option<String>,
}

/// Task type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskType {
    /// Tool execution task
    ToolExecution,
    /// File operation task
    FileOperation,
    /// Network operation task
    NetworkOperation,
    /// Process management task
    ProcessManagement,
    /// Monitoring task
    Monitoring,
    /// Security task
    Security,
}

/// Task status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskStatus {
    /// Task pending
    Pending,
    /// Task running
    Running,
    /// Task completed successfully
    Completed,
    /// Task failed
    Failed,
    /// Task cancelled
    Cancelled,
}

// ============================================================================
// Agent Loop Service
// ============================================================================

/// Agent Loop Service - systemd-like daemon orchestrator
///
/// This is the core orchestrator for ClawOS, managing:
/// - Inter-component IPC communication
/// - Component health monitoring (heartbeat)
/// - Task scheduling and execution
/// - Security policy enforcement
/// - Resource management via cgroups
pub struct AgentLoopService {
    /// Service configuration
    config: ServiceConfig,

    /// ClawFS storage backend
    clawfs: Arc<ClawFS>,

    /// IPC server for receiving messages
    ipc_server: Option<IpcServer>,

    /// IPC clients for sending messages to components
    ipc_clients: Arc<RwLock<HashMap<String, IpcClient>>>,

    /// Component health status
    component_health: Arc<RwLock<HashMap<String, ComponentHealth>>>,

    /// Active tasks
    active_tasks: Arc<RwLock<HashMap<Uuid, TaskContext>>>,

    /// seccomp filter
    seccomp_filter: Option<SeccompFilter>,

    /// Namespace isolator
    namespace_isolator: Option<NamespaceIsolator>,

    /// Service shutdown signal
    shutdown_tx: Option<mpsc::Sender<()>>,

    /// Service running state
    running: Arc<RwLock<bool>>,
}

impl AgentLoopService {
    /// Create a new Agent Loop Service
    pub fn new(config: ServiceConfig) -> Result<Self> {
        info!("Initializing Agent Loop Service");

        // Initialize ClawFS
        let clawfs = Arc::new(ClawFS::new(&config.clawfs_root)?);

        // Load seccomp filter if path provided
        let seccomp_filter = if let Some(ref path) = config.seccomp_filter_path {
            Some(SeccompFilter::from_file(path)?)
        } else {
            None
        };

        // Initialize namespace isolator if enabled
        let namespace_isolator = if config.namespace_isolation {
            Some(NamespaceIsolator::new()?)
        } else {
            None
        };

        Ok(Self {
            config,
            clawfs,
            ipc_server: None,
            ipc_clients: Arc::new(RwLock::new(HashMap::new())),
            component_health: Arc::new(RwLock::new(HashMap::new())),
            active_tasks: Arc::new(RwLock::new(HashMap::new())),
            seccomp_filter,
            namespace_isolator,
            shutdown_tx: None,
            running: Arc::new(RwLock::new(false)),
        })
    }

    /// Start the Agent Loop Service
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting Agent Loop Service");

        // Apply seccomp filter if configured
        if let Some(ref filter) = self.seccomp_filter {
            info!("Applying seccomp-BPF filter");
            filter.apply()?;
        }

        // Setup namespace isolation if enabled
        if let Some(ref isolator) = self.namespace_isolator {
            info!("Setting up namespace isolation");
            isolator.setup()?;
        }

        // Initialize IPC server
        let ipc_server = IpcServer::new(&self.config.ipc_socket_path)?;
        self.ipc_server = Some(ipc_server);

        // Mark service as running
        *self.running.write().await = true;

        // Setup shutdown channel
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        // Spawn heartbeat monitor task
        let health = Arc::clone(&self.component_health);
        let running = Arc::clone(&self.running);
        let heartbeat_interval = self.config.heartbeat_interval_secs;
        let watchdog_timeout = self.config.watchdog_timeout_secs;

        tokio::spawn(async move {
            Self::heartbeat_monitor_task(health, running, heartbeat_interval, watchdog_timeout).await;
        });

        // Spawn IPC message handler task
        let ipc_server = self.ipc_server.as_ref().unwrap().clone();
        let clawfs = Arc::clone(&self.clawfs);
        let clients = Arc::clone(&self.ipc_clients);
        let tasks = Arc::clone(&self.active_tasks);

        tokio::spawn(async move {
            Self::ipc_message_handler_task(ipc_server, clawfs, clients, tasks, shutdown_rx).await;
        });

        // Notify systemd if integration enabled
        if self.config.systemd_integration {
            Self::notify_systemd_ready()?;
        }

        info!("Agent Loop Service started successfully");
        Ok(())
    }

    /// Stop the Agent Loop Service
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping Agent Loop Service");

        // Mark service as not running
        *self.running.write().await = false;

        // Send shutdown signal
        if let Some(ref tx) = self.shutdown_tx {
            let _ = tx.send(()).await;
        }

        // Notify systemd if integration enabled
        if self.config.systemd_integration {
            Self::notify_systemd_stopping()?;
        }

        info!("Agent Loop Service stopped");
        Ok(())
    }

    /// Get component health status
    pub async fn get_component_health(&self, component_id: &str) -> Option<ComponentHealth> {
        let health = self.component_health.read().await;
        health.get(component_id).cloned()
    }

    /// Get all component health statuses
    pub async fn get_all_component_health(&self) -> Vec<ComponentHealth> {
        let health = self.component_health.read().await;
        health.values().cloned().collect()
    }

    /// Get active tasks
    pub async fn get_active_tasks(&self) -> Vec<TaskContext> {
        let tasks = self.active_tasks.read().await;
        tasks.values().cloned().collect()
    }

    // ========================================================================
    // Internal Tasks
    // ========================================================================

    /// Heartbeat monitor task
    ///
    /// Monitors component heartbeats and marks components as unhealthy
    /// if they miss the watchdog timeout (90 seconds = 3x heartbeat interval)
    async fn heartbeat_monitor_task(
        health: Arc<RwLock<HashMap<String, ComponentHealth>>>,
        running: Arc<RwLock<bool>>,
        interval_secs: u64,
        watchdog_timeout_secs: u64,
    ) {
        let mut interval = interval(Duration::from_secs(interval_secs));

        loop {
            interval.tick().await;

            // Check if service is still running
            if !*running.read().await {
                debug!("Heartbeat monitor: service stopped, exiting");
                break;
            }

            let now = Utc::now();
            let watchdog_threshold = now - chrono::Duration::seconds(watchdog_timeout_secs as i64);

            let mut health_write = health.write().await;

            for (_, component_health) in health_write.iter_mut() {
                let time_since_heartbeat = now.signed_duration_since(component_health.last_heartbeat);

                if component_health.last_heartbeat < watchdog_threshold {
                    // Component missed watchdog timeout
                    warn!(
                        "Component {} missed watchdog timeout (last heartbeat: {:?})",
                        component_health.component_id,
                        component_health.last_heartbeat
                    );
                    component_health.status = HealthStatus::Unresponsive;
                    component_health.missed_heartbeats += 1;
                } else if time_since_heartbeat.num_seconds() > (interval_secs * 2) as i64 {
                    // Component missed 2 heartbeats
                    warn!(
                        "Component {} missed heartbeat (last heartbeat: {:?})",
                        component_health.component_id,
                        component_health.last_heartbeat
                    );
                    component_health.status = HealthStatus::Critical;
                    component_health.missed_heartbeats += 1;
                } else if time_since_heartbeat.num_seconds() > interval_secs as i64 {
                    // Component missed 1 heartbeat
                    debug!(
                        "Component {} missed heartbeat (last heartbeat: {:?})",
                        component_health.component_id,
                        component_health.last_heartbeat
                    );
                    component_health.status = HealthStatus::Degraded;
                    component_health.missed_heartbeats += 1;
                } else {
                    // Component is healthy
                    component_health.status = HealthStatus::Ok;
                    component_health.missed_heartbeats = 0;
                }
            }
        }
    }

    /// IPC message handler task
    ///
    /// Handles incoming IPC messages from other components
    async fn ipc_message_handler_task(
        mut ipc_server: IpcServer,
        clawfs: Arc<ClawFS>,
        clients: Arc<RwLock<HashMap<String, IpcClient>>>,
        tasks: Arc<RwLock<HashMap<Uuid, TaskContext>>>,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                // Handle incoming messages
                result = ipc_server.accept() => {
                    match result {
                        Ok(message) => {
                            debug!("Received IPC message from {}: {:?}", message.sender, message.message_type);

                            // Handle message based on type
                            if let Err(e) = Self::handle_message(
                                message,
                                &clawfs,
                                &clients,
                                &tasks,
                            ).await {
                                error!("Failed to handle IPC message: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("Failed to accept IPC connection: {}", e);
                        }
                    }
                }

                // Handle shutdown signal
                _ = shutdown_rx.recv() => {
                    debug!("IPC message handler: received shutdown signal, exiting");
                    break;
                }
            }
        }
    }

    /// Handle incoming IPC message
    async fn handle_message(
        message: Message,
        clawfs: &Arc<ClawFS>,
        clients: &Arc<RwLock<HashMap<String, IpcClient>>>,
        tasks: &Arc<RwLock<HashMap<Uuid, TaskContext>>>,
    ) -> Result<()> {
        match message.message_type {
            MessageType::Event => {
                // Handle event messages (heartbeat, anomaly detection, etc.)
                if let Some(event_name) = message.payload.get("event_name").and_then(|v| v.as_str()) {
                    match event_name {
                        "heartbeat" => {
                            Self::handle_heartbeat(message, clawfs).await?;
                        }
                        "anomaly_detected" => {
                            Self::handle_anomaly(message).await?;
                        }
                        "component_ready" => {
                            Self::handle_component_ready(message, clients).await?;
                        }
                        "component_shutdown" => {
                            Self::handle_component_shutdown(message, clients).await?;
                        }
                        _ => {
                            debug!("Unhandled event: {}", event_name);
                        }
                    }
                }
            }
            MessageType::Request => {
                // Handle request messages (tool execution, file operations, etc.)
                Self::handle_request(message, clawfs, tasks).await?;
            }
            MessageType::Response => {
                // Handle response messages
                debug!("Received response message");
            }
            MessageType::Error => {
                // Handle error messages
                error!("Received error message from {}: {:?}", message.sender, message.payload);
            }
        }

        Ok(())
    }

    /// Handle heartbeat event
    async fn handle_heartbeat(message: Message, clawfs: &Arc<ClawFS>) -> Result<()> {
        let component_id = message.sender.clone();

        // Extract metrics from payload
        let event_data = message.payload.get("event_data").ok_or_else(|| {
            Error::Service("Missing event_data in heartbeat".to_string())
        })?;

        let status_str = event_data.get("status").and_then(|v| v.as_str()).unwrap_or("ok");
        let status = match status_str {
            "ok" => HealthStatus::Ok,
            "degraded" => HealthStatus::Degraded,
            "critical" => HealthStatus::Critical,
            _ => HealthStatus::Ok,
        };

        let metrics_obj = event_data.get("metrics").ok_or_else(|| {
            Error::Service("Missing metrics in heartbeat".to_string())
        })?;

        let metrics = ComponentMetrics {
            uptime_ns: metrics_obj.get("uptime_ns").and_then(|v| v.as_u64()).unwrap_or(0),
            messages_processed: metrics_obj.get("messages_processed").and_then(|v| v.as_u64()).unwrap_or(0),
            messages_failed: metrics_obj.get("messages_failed").and_then(|v| v.as_u64()).unwrap_or(0),
            memory_usage_bytes: metrics_obj.get("memory_usage_bytes").and_then(|v| v.as_u64()).unwrap_or(0),
            cpu_usage_percent: metrics_obj.get("cpu_usage_percent").and_then(|v| v.as_f64()).unwrap_or(0.0),
            active_connections: metrics_obj.get("active_connections").and_then(|v| v.as_u32()).unwrap_or(0),
        };

        // Update component health
        let health = ComponentHealth {
            component_id: component_id.clone(),
            last_heartbeat: Utc::now(),
            status,
            metrics,
            missed_heartbeats: 0,
        };

        // Store in ClawFS for persistence
        let health_path = format!("/clawfs/agents/{}/health.json", component_id);
        let health_json = serde_json::to_string(&health)?;
        clawfs.write(&health_path, health_json.as_bytes()).await?;

        debug!("Updated health for component {}", component_id);

        Ok(())
    }

    /// Handle anomaly detection event
    async fn handle_anomaly(message: Message) -> Result<()> {
        warn!("Anomaly detected: {:?}", message.payload);

        // TODO: Implement anomaly handling logic
        // - Log to observability
        // - Notify security agent
        // - Take corrective action if needed

        Ok(())
    }

    /// Handle component ready event
    async fn handle_component_ready(message: Message, clients: &Arc<RwLock<HashMap<String, IpcClient>>>) -> Result<()> {
        let component_id = message.sender.clone();

        info!("Component {} is ready", component_id);

        // Establish IPC client connection to the component
        let socket_path = format!("@clawos-ipc-{}", component_id);
        let client = IpcClient::new(&socket_path)?;

        let mut clients_write = clients.write().await;
        clients_write.insert(component_id.clone(), client);

        Ok(())
    }

    /// Handle component shutdown event
    async fn handle_component_shutdown(message: Message, clients: &Arc<RwLock<HashMap<String, IpcClient>>>) -> Result<()> {
        let component_id = message.sender.clone();

        info!("Component {} is shutting down", component_id);

        // Remove IPC client connection
        let mut clients_write = clients.write().await;
        clients_write.remove(&component_id);

        Ok(())
    }

    /// Handle request message
    async fn handle_request(
        message: Message,
        clawfs: &Arc<ClawFS>,
        tasks: &Arc<RwLock<HashMap<Uuid, TaskContext>>>,
    ) -> Result<()> {
        let method = message.payload.get("method").and_then(|v| v.as_str())
            .ok_or_else(|| Error::Service("Missing method in request".to_string()))?;

        debug!("Handling request method: {}", method);

        match method {
            "execute_tool" => {
                // TODO: Implement tool execution via WASM daemon
                // This will be implemented in D-04 (WASM Runtime bridge)
            }
            "read_file" => {
                // TODO: Implement file read via ClawFS
            }
            "write_file" => {
                // TODO: Implement file write via ClawFS
            }
            "get_metrics" => {
                // TODO: Implement metrics query
            }
            "check_policy" => {
                // TODO: Implement policy check via security agent
            }
            _ => {
                debug!("Unhandled request method: {}", method);
            }
        }

        Ok(())
    }

    // ========================================================================
    // Systemd Integration
    // ========================================================================

    /// Notify systemd that service is ready
    fn notify_systemd_ready() -> Result<()> {
        Self::sd_notify("READY=1")
    }
    /// Notify systemd that service is stopping
    fn notify_systemd_stopping() -> Result<()> {
        Self::sd_notify("STOPPING=1")
    }

    /// Send notification to systemd via sd_notify protocol
    ///
    /// Implements the sd_notify() protocol from libsystemd.
    /// If NOTIFY_SOCKET is not set, this is a no-op (running outside systemd).
    fn sd_notify(state: &str) -> Result<()> {
        use std::os::unix::io::AsRawFd;
        use std::os::unix::net::UnixDatagram;

        // Get NOTIFY_SOCKET environment variable
        let socket_path = match std::env::var("NOTIFY_SOCKET") {
            Ok(path) if !path.is_empty() => {
                // systemd abstract namespace socket starts with @
                if path.starts_with('@') {
                    let mut s = String::from("\0");
                    s.push_str(&path[1..]);
                    s
                } else {
                    path
                }
            },
            _ => {
                // Not running under systemd, no-op
                debug!("NOTIFY_SOCKET not set, skipping systemd notification: {}", state);
                return Ok(());
            }
        };

        // Create Unix domain socket for datagram
        let socket = UnixDatagram::unbound()
            .map_err(|e| Error::Service(format!("Failed to create systemd notify socket: {}", e)))?;

        // Send the notification state
        socket.send_to(state.as_bytes(), &socket_path)
            .map_err(|e| Error::Service(format!("Failed to send systemd notification: {}", e)))?;

        debug!("Sent systemd notification: {}", state);
        Ok(())
}

// ============================================================================
// Public API Implementation (P1.8)
// ============================================================================

/// ClawOS Public API implementation
///
/// Maps to P1.8 public API surface, providing syscall-like interface
/// for userspace tools and components.
pub struct ClawOSApiImpl {
    /// Reference to the agent loop service
    service: Arc<AgentLoopService>,
}

impl ClawOSApiImpl {
    /// Create a new ClawOS API implementation
    pub fn new(service: Arc<AgentLoopService>) -> Self {
        Self { service }
    }
}

#[async_trait]
impl ClawOSApi for ClawOSApiImpl {
    /// Spawn a new process in an isolated namespace
    async fn proc_spawn(&self, args: &ProcSpawnArgs) -> Result<i32> {
        debug!("Spawning process: {:?}", args.executable);

        // TODO: Implement process spawning with namespace isolation
        // This will integrate with the namespace isolator

        Ok(0) // Placeholder PID
    }

    /// Query system or tool metrics
    async fn metric_query(&self, metric_name: &str) -> Result<MetricValue> {
        debug!("Querying metric: {}", metric_name);

        // TODO: Implement metrics query
        // This will integrate with the observability agent

        Ok(MetricValue {
            name: metric_name.to_string(),
            value: "0".to_string(),
            timestamp_ns: Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64,
        })
    }

    /// Write a log message
    async fn log_write(&self, level: u32, message: &str) -> Result<()> {
        match level {
            0 => debug!("{}", message),
            1 => info!("{}", message),
            2 => warn!("{}", message),
            3 => error!("{}", message),
            _ => info!("{}", message),
        }
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_config_default() {
        let config = ServiceConfig::default();
        assert_eq!(config.heartbeat_interval_secs, 30);
        assert_eq!(config.watchdog_timeout_secs, 90);
        assert_eq!(config.max_concurrent_tasks, 100);
        assert!(config.systemd_integration);
        assert!(config.namespace_isolation);
    }

    #[test]
    fn test_component_health_default() {
        let metrics = ComponentMetrics::default();
        assert_eq!(metrics.uptime_ns, 0);
        assert_eq!(metrics.messages_processed, 0);
        assert_eq!(metrics.messages_failed, 0);
        assert_eq!(metrics.memory_usage_bytes, 0);
        assert_eq!(metrics.cpu_usage_percent, 0.0);
        assert_eq!(metrics.active_connections, 0);
    }

    #[test]
    fn test_health_status_display() {
        assert_eq!(format!("{:?}", HealthStatus::Ok), "Ok");
        assert_eq!(format!("{:?}", HealthStatus::Degraded), "Degraded");
        assert_eq!(format!("{:?}", HealthStatus::Critical), "Critical");
        assert_eq!(format!("{:?}", HealthStatus::Unresponsive), "Unresponsive");
    }
}
