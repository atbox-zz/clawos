// Public API Surface (P1.8)

use crate::error::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Process spawn arguments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcSpawnArgs {
    pub executable: String,
    pub argv: Vec<String>,
    pub envp: Option<Vec<String>>,
    pub working_dir: Option<String>,
    pub flags: u32,
}

/// Metric value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricValue {
    pub name: String,
    pub value: String,
    pub timestamp_ns: u64,
}

/// ClawOS Public API trait
#[async_trait]
pub trait ClawOSApi: Send + Sync {
    async fn proc_spawn(&self, args: &ProcSpawnArgs) -> Result<i32>;
    async fn metric_query(&self, metric_name: &str) -> Result<MetricValue>;
    async fn log_write(&self, level: u32, message: &str) -> Result<()>;
}
