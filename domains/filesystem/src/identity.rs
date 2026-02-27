use crate::error::{ClawFSError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use chrono;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityFile {
    pub agent_id: String,
    pub version: u32,
    pub created_at: String,
    pub updated_at: String,
    pub state: IdentityState,
    pub memory: AgentMemory,
    pub history: AgentHistory,
    pub performance: PerformanceMetrics,
    pub checksum: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityState {
    pub current_phase: String,
    pub current_task: String,
    pub last_checkpoint: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMemory {
    pub learned_patterns: Vec<LearnedPattern>,
    pub heuristics: Vec<Heuristic>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedPattern {
    pub pattern_id: String,
    pub description: String,
    pub confidence: f64,
    pub learned_at: String,
    pub usage_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heuristic {
    pub heuristic_id: String,
    pub rule: String,
    pub accuracy: f64,
    pub last_validated: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHistory {
    pub completed_tasks: Vec<String>,
    pub failed_tasks: Vec<String>,
    pub total_executions: u32,
    pub success_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub avg_execution_time_ms: u64,
    pub peak_memory_mb: u64,
    pub last_benchmark: String,
}

impl IdentityFile {
    pub fn new(agent_id: &str) -> Self {
        let now = chrono::Utc::now().to_rfc3339();

        Self {
            agent_id: agent_id.to_string(),
            version: 1,
            created_at: now.clone(),
            updated_at: now.clone(),
            state: IdentityState {
                current_phase: "P1".to_string(),
                current_task: "initialization".to_string(),
                last_checkpoint: now.clone(),
                status: "initialized".to_string(),
            },
            memory: AgentMemory {
                learned_patterns: vec![],
                heuristics: vec![],
            },
            history: AgentHistory {
                completed_tasks: vec![],
                failed_tasks: vec![],
                total_executions: 0,
                success_rate: 1.0,
            },
            performance: PerformanceMetrics {
                avg_execution_time_ms: 0,
                peak_memory_mb: 0,
                last_benchmark: now,
            },
            checksum: String::new(),
        }
    }

    pub fn calculate_checksum(&self) -> String {
        let mut identity_without_checksum = self.clone();
        identity_without_checksum.checksum = String::new();

        let json = serde_json::to_string(&identity_without_checksum).unwrap();
        let hash = Sha256::digest(json);
        format!("sha256:{:x}", hash)
    }

    pub fn verify_checksum(&self) -> bool {
        let calculated = self.calculate_checksum();
        calculated == self.checksum
    }

    pub fn update_checksum(&mut self) {
        self.checksum = self.calculate_checksum();
    }

    pub fn update_timestamp(&mut self) {
        self.updated_at = chrono::Utc::now().to_rfc3339();
    }

    pub fn add_learned_pattern(&mut self, pattern: LearnedPattern) {
        self.memory.learned_patterns.push(pattern);
        self.update_timestamp();
    }

    pub fn add_heuristic(&mut self, heuristic: Heuristic) {
        self.memory.heuristics.push(heuristic);
        self.update_timestamp();
    }

    pub fn record_task_completion(&mut self, task_id: &str, success: bool) {
        if success {
            self.history.completed_tasks.push(task_id.to_string());
        } else {
            self.history.failed_tasks.push(task_id.to_string());
        }

        self.history.total_executions += 1;
        let completed = self.history.completed_tasks.len() as f64;
        let total = self.history.total_executions as f64;
        self.history.success_rate = completed / total;

        self.update_timestamp();
    }

    pub fn update_performance(&mut self, execution_time_ms: u64, memory_mb: u64) {
        let total = self.history.total_executions as u64;
        if total > 0 {
            let current_avg = self.performance.avg_execution_time_ms;
            self.performance.avg_execution_time_ms =
                (current_avg * (total - 1) + execution_time_ms) / total;
        }

        if memory_mb > self.performance.peak_memory_mb {
            self.performance.peak_memory_mb = memory_mb;
        }

        self.performance.last_benchmark = chrono::Utc::now().to_rfc3339();
        self.update_timestamp();
    }

    pub fn update_state(&mut self, phase: &str, task: &str, status: &str) {
        self.state.current_phase = phase.to_string();
        self.state.current_task = task.to_string();
        self.state.status = status.to_string();
        self.state.last_checkpoint = chrono::Utc::now().to_rfc3339();
        self.update_timestamp();
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if !self.verify_checksum() {
            return Err(ClawFSError::IdentityFile(
                "Checksum verification failed before save".to_string(),
            ));
        }

        let temp_path = path.with_extension("tmp");
        let json = serde_json::to_string_pretty(self)?;

        std::fs::write(&temp_path, json)?;

        std::fs::rename(&temp_path, path)?;

        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let identity: IdentityFile = serde_json::from_str(&json)?;

        if !identity.verify_checksum() {
            return Err(ClawFSError::IdentityFile(
                "Checksum verification failed on load".to_string(),
            ));
        }

        Ok(identity)
    }

    pub fn backup(&self, backup_dir: &Path) -> Result<String> {
        let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let backup_filename = format!("{}-{}.json", self.agent_id, timestamp);
        let backup_path = backup_dir.join(&backup_filename);

        self.save(&backup_path)?;

        Ok(backup_path.to_string_lossy().to_string())
    }
}

pub struct IdentityManager {
    base_path: std::path::PathBuf,
}

impl IdentityManager {
    pub fn new(base_path: &Path) -> Self {
        Self {
            base_path: base_path.to_path_buf(),
        }
    }

    pub fn get_identity_path(&self, agent_id: &str) -> std::path::PathBuf {
        self.base_path.join(format!("{}.json", agent_id))
    }

    pub fn load_or_create(&self, agent_id: &str) -> Result<IdentityFile> {
        let path = self.get_identity_path(agent_id);

        if path.exists() {
            IdentityFile::load(&path)
        } else {
            let mut identity = IdentityFile::new(agent_id);
            identity.update_checksum();
            identity.save(&path)?;
            Ok(identity)
        }
    }

    pub fn save_identity(&self, identity: &IdentityFile) -> Result<()> {
        let path = self.get_identity_path(&identity.agent_id);
        identity.save(&path)
    }

    pub fn backup_all(&self, backup_dir: &Path) -> Result<Vec<String>> {
        std::fs::create_dir_all(backup_dir)?;

        let mut backups = vec![];

        for entry in std::fs::read_dir(&self.base_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let identity = IdentityFile::load(&path)?;
                let backup_path = identity.backup(backup_dir)?;
                backups.push(backup_path);
            }
        }

        Ok(backups)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_identity_file_new() {
        let identity = IdentityFile::new("kernel-engine");
        assert_eq!(identity.agent_id, "kernel-engine");
        assert_eq!(identity.version, 1);
        assert_eq!(identity.state.status, "initialized");
        assert!(identity.memory.learned_patterns.is_empty());
    }

    #[test]
    fn test_identity_file_checksum() {
        let mut identity = IdentityFile::new("test-agent");
        identity.update_checksum();

        assert!(!identity.checksum.is_empty());
        assert!(identity.verify_checksum());
    }

    #[test]
    fn test_identity_file_checksum_invalid() {
        let mut identity = IdentityFile::new("test-agent");
        identity.update_checksum();

        identity.checksum = "invalid".to_string();
        assert!(!identity.verify_checksum());
    }

    #[test]
    fn test_identity_file_add_learned_pattern() {
        let mut identity = IdentityFile::new("test-agent");
        identity.update_checksum();

        let pattern = LearnedPattern {
            pattern_id: "pattern-001".to_string(),
            description: "Test pattern".to_string(),
            confidence: 0.95,
            learned_at: chrono::Utc::now().to_rfc3339(),
            usage_count: 0,
        };

        identity.add_learned_pattern(pattern);
        assert_eq!(identity.memory.learned_patterns.len(), 1);
    }

    #[test]
    fn test_identity_file_record_task_completion() {
        let mut identity = IdentityFile::new("test-agent");
        identity.update_checksum();

        identity.record_task_completion("task-001", true);
        assert_eq!(identity.history.completed_tasks.len(), 1);
        assert_eq!(identity.history.total_executions, 1);
        assert_eq!(identity.history.success_rate, 1.0);

        identity.record_task_completion("task-002", false);
        assert_eq!(identity.history.failed_tasks.len(), 1);
        assert_eq!(identity.history.total_executions, 2);
        assert_eq!(identity.history.success_rate, 0.5);
    }

    #[test]
    fn test_identity_file_update_performance() {
        let mut identity = IdentityFile::new("test-agent");
        identity.update_checksum();

        identity.record_task_completion("task-001", true);
        identity.update_performance(1000, 512);

        assert_eq!(identity.performance.avg_execution_time_ms, 1000);
        assert_eq!(identity.performance.peak_memory_mb, 512);

        identity.record_task_completion("task-002", true);
        identity.update_performance(2000, 256);

        assert_eq!(identity.performance.avg_execution_time_ms, 1500);
        assert_eq!(identity.performance.peak_memory_mb, 512);
    }

    #[test]
    fn test_identity_file_save_load() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test-agent.json");

        let mut identity = IdentityFile::new("test-agent");
        identity.update_checksum();
        identity.save(&file_path).unwrap();

        let loaded = IdentityFile::load(&file_path).unwrap();
        assert_eq!(loaded.agent_id, identity.agent_id);
        assert_eq!(loaded.checksum, identity.checksum);
        assert!(loaded.verify_checksum());
    }

    #[test]
    fn test_identity_file_save_invalid_checksum() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test-agent.json");

        let mut identity = IdentityFile::new("test-agent");
        identity.checksum = "invalid".to_string();

        let result = identity.save(&file_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_identity_manager_load_or_create() {
        let temp_dir = TempDir::new().unwrap();
        let manager = IdentityManager::new(temp_dir.path());

        let identity = manager.load_or_create("test-agent").unwrap();
        assert_eq!(identity.agent_id, "test-agent");

        let loaded = manager.load_or_create("test-agent").unwrap();
        assert_eq!(loaded.agent_id, identity.agent_id);
    }

    #[test]
    fn test_identity_file_update_state() {
        let mut identity = IdentityFile::new("test-agent");
        identity.update_checksum();

        identity.update_state("P2", "A-01", "in_progress");
        assert_eq!(identity.state.current_phase, "P2");
        assert_eq!(identity.state.current_task, "A-01");
        assert_eq!(identity.state.status, "in_progress");
    }
}
