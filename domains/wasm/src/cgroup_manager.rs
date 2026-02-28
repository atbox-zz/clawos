use crate::error::{BridgeError, BridgeResult, ErrorCode};
use crate::resource::Cgroup;
use std::path::Path;
use tracing::{info, debug, warn};

const CGROUP_ROOT: &str = "/sys/fs/cgroup/clawos";
const WASM_SLICE: &str = "/sys/fs/cgroup/clawos/wasm.slice";

#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub memory_max: u64,
    pub cpu_max: u64,
    pub cpu_period: u64,
    pub pids_max: u64,
    pub cpu_weight: u32,
    pub io_weight: u32,
    pub memory_swap_max: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        ResourceLimits {
            memory_max: 256 * 1024 * 1024,
            cpu_max: 50000,
            cpu_period: 1_000_000,
            pids_max: 32,
            cpu_weight: 5000,
            io_weight: 5000,
            memory_swap_max: 0,
        }
    }
}

impl ResourceLimits {
    pub fn wasm_sandbox() -> Self {
        ResourceLimits {
            memory_max: 256 * 1024 * 1024,
            cpu_max: 50000,
            cpu_period: 1_000_000,
            pids_max: 32,
            cpu_weight: 5000,
            io_weight: 5000,
            memory_swap_max: 0,
        }
    }

    pub fn daemon() -> Self {
        ResourceLimits {
            memory_max: 512 * 1024 * 1024,
            cpu_max: 100000,
            cpu_period: 1_000_000,
            pids_max: 64,
            cpu_weight: 8000,
            io_weight: 8000,
            memory_swap_max: 0,
        }
    }

    pub fn validate(&self) -> BridgeResult<()> {
        if self.memory_max == 0 {
            return Err(BridgeError::with_code(ErrorCode::InvalidConfig, "Memory limit cannot be zero"));
        }

        if self.cpu_max > self.cpu_period {
            return Err(BridgeError::with_code(ErrorCode::InvalidConfig, "CPU max cannot exceed CPU period"));
        }

        if self.cpu_weight == 0 || self.cpu_weight > 10000 {
            return Err(BridgeError::with_code(ErrorCode::InvalidConfig, "CPU weight must be 1-10000"));
        }

        if self.io_weight == 0 || self.io_weight > 10000 {
            return Err(BridgeError::with_code(ErrorCode::InvalidConfig, "IO weight must be 1-10000"));
        }

        Ok(())
    }
}

pub struct CgroupManager {
    base_path: String,
}

impl CgroupManager {
    pub fn new() -> BridgeResult<Self> {
        info!("Initializing CgroupManager");

        if !Path::new(CGROUP_ROOT).exists() {
            return Err(BridgeError::Cgroup(format!("Cgroup root {} does not exist", CGROUP_ROOT)));
        }

        info!("CgroupManager initialized successfully");
        Ok(CgroupManager {
            base_path: CGROUP_ROOT.to_string(),
        })
    }

    pub fn create_slice(&self, name: &str, parent: Option<&str>) -> BridgeResult<String> {
        let parent_path = parent.unwrap_or("");
        let slice_path = if parent_path.is_empty() {
            format!("{}/{}.slice", self.base_path, name)
        } else {
            format!("{}/{}.slice/{}.slice", self.base_path, parent_path, name)
        };

        std::fs::create_dir_all(&slice_path)
            .map_err(|e| BridgeError::Cgroup(format!("Failed to create slice {}: {}", slice_path, e)))?;

        info!("Created cgroup slice: {}", slice_path);
        Ok(slice_path)
    }

    pub fn create_instance(&self, slice_name: &str, instance_id: &str) -> BridgeResult<String> {
        let instance_path = format!("{}/{}.slice/{}", self.base_path, slice_name, instance_id);

        std::fs::create_dir_all(&instance_path)
            .map_err(|e| BridgeError::Cgroup(format!("Failed to create instance {}: {}", instance_path, e)))?;

        info!("Created cgroup instance: {}", instance_path);
        Ok(instance_path)
    }

    pub fn apply_limits(&self, path: &str, limits: &ResourceLimits) -> BridgeResult<()> {
        limits.validate()?;

        let memory_max_path = format!("{}/memory.max", path);
        let memory_max_str = if limits.memory_max == u64::MAX {
            "max".to_string()
        } else {
            limits.memory_max.to_string()
        };
        std::fs::write(&memory_max_path, memory_max_str)
            .map_err(|e| BridgeError::Cgroup(format!("Failed to set memory.max: {}", e)))?;

        let cpu_max_path = format!("{}/cpu.max", path);
        let cpu_max_str = format!("{} {}", limits.cpu_max, limits.cpu_period);
        std::fs::write(&cpu_max_path, cpu_max_str)
            .map_err(|e| BridgeError::Cgroup(format!("Failed to set cpu.max: {}", e)))?;

        let pids_max_path = format!("{}/pids.max", path);
        let pids_max_str = if limits.pids_max == u64::MAX {
            "max".to_string()
        } else {
            limits.pids_max.to_string()
        };
        std::fs::write(&pids_max_path, pids_max_str)
            .map_err(|e| BridgeError::Cgroup(format!("Failed to set pids.max: {}", e)))?;

        let cpu_weight_path = format!("{}/cpu.weight", path);
        std::fs::write(&cpu_weight_path, limits.cpu_weight.to_string())
            .map_err(|e| BridgeError::Cgroup(format!("Failed to set cpu.weight: {}", e)))?;

        let io_weight_path = format!("{}/io.weight", path);
        std::fs::write(&io_weight_path, limits.io_weight.to_string())
            .map_err(|e| BridgeError::Cgroup(format!("Failed to set io.weight: {}", e)))?;

        let memory_swap_max_path = format!("{}/memory.swap.max", path);
        let memory_swap_max_str = if limits.memory_swap_max == u64::MAX {
            "max".to_string()
        } else {
            limits.memory_swap_max.to_string()
        };
        std::fs::write(&memory_swap_max_path, memory_swap_max_str)
            .map_err(|e| BridgeError::Cgroup(format!("Failed to set memory.swap.max: {}", e)))?;

        let oom_group_path = format!("{}/memory.oom.group", path);
        std::fs::write(&oom_group_path, "1")
            .map_err(|e| BridgeError::Cgroup(format!("Failed to set memory.oom.group: {}", e)))?;

        info!("Applied resource limits to {}", path);
        Ok(())
    }

    pub fn add_process(&self, cgroup_path: &str, pid: u32) -> BridgeResult<()> {
        let procs_path = format!("{}/cgroup.procs", cgroup_path);

        std::fs::write(&procs_path, pid.to_string())
            .map_err(|e| BridgeError::Cgroup(format!("Failed to add process {} to {}: {}", pid, cgroup_path, e)))?;

        info!("Added process {} to {}", pid, cgroup_path);
        Ok(())
    }

    pub fn remove_process(&self, cgroup_path: &str, pid: u32) -> BridgeResult<()> {
        let procs_path = format!("{}/cgroup.procs", cgroup_path);

        let current_procs = std::fs::read_to_string(&procs_path)
            .map_err(|e| BridgeError::Cgroup(format!("Failed to read cgroup.procs: {}", e)))?;

        let new_procs: String = current_procs
            .lines()
            .filter(|line| line.trim() != pid.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        std::fs::write(&procs_path, new_procs)
            .map_err(|e| BridgeError::Cgroup(format!("Failed to remove process {} from {}: {}", pid, cgroup_path, e)))?;

        info!("Removed process {} from {}", pid, cgroup_path);
        Ok(())
    }

    pub fn get_cgroup(&self, path: &str) -> BridgeResult<Cgroup> {
        if !Path::new(path).exists() {
            return Err(BridgeError::Cgroup(format!("Cgroup {} does not exist", path)));
        }

        Ok(Cgroup::new(path.to_string()))
    }

    pub fn delete_cgroup(&self, path: &str) -> BridgeResult<()> {
        if !Path::new(path).exists() {
            return Err(BridgeError::Cgroup(format!("Cgroup {} does not exist", path)));
        }

        let procs_path = format!("{}/cgroup.procs", path);
        let procs = std::fs::read_to_string(&procs_path)
            .map_err(|e| BridgeError::Cgroup(format!("Failed to read cgroup.procs: {}", e)))?;

        if !procs.trim().is_empty() {
            return Err(BridgeError::Cgroup(format!("Cannot delete cgroup {} with active processes", path)));
        }

        std::fs::remove_dir(path)
            .map_err(|e| BridgeError::Cgroup(format!("Failed to delete cgroup {}: {}", path, e)))?;

        info!("Deleted cgroup: {}", path);
        Ok(())
    }

    pub fn get_memory_usage(&self, path: &str) -> BridgeResult<u64> {
        let memory_current_path = format!("{}/memory.current", path);
        let usage = std::fs::read_to_string(&memory_current_path)
            .map_err(|e| BridgeError::Cgroup(format!("Failed to read memory.current: {}", e)))?;

        usage.trim().parse::<u64>()
            .map_err(|_| BridgeError::Cgroup("Failed to parse memory usage".to_string()))
    }

    pub fn get_cpu_usage(&self, path: &str) -> BridgeResult<u64> {
        let cpu_stat_path = format!("{}/cpu.stat", path);
        let stat = std::fs::read_to_string(&cpu_stat_path)
            .map_err(|e| BridgeError::Cgroup(format!("Failed to read cpu.stat: {}", e)))?;

        for line in stat.lines() {
            if line.starts_with("usage_usec ") {
                let usage_usec = line.split_whitespace().nth(1)
                    .ok_or_else(|| BridgeError::Cgroup("Failed to parse CPU usage".to_string()))?;
                return Ok(usage_usec.parse::<u64>()
                    .map_err(|_| BridgeError::Cgroup("Failed to parse CPU usage".to_string()))? * 1000);
            }
        }

        Err(BridgeError::Cgroup("CPU usage not found in cgroup stat".to_string()))
    }

    pub fn get_pid_count(&self, path: &str) -> BridgeResult<u64> {
        let pids_current_path = format!("{}/pids.current", path);
        let count = std::fs::read_to_string(&pids_current_path)
            .map_err(|e| BridgeError::Cgroup(format!("Failed to read pids.current: {}", e)))?;

        count.trim().parse::<u64>()
            .map_err(|_| BridgeError::Cgroup("Failed to parse PID count".to_string()))
    }

    pub fn setup_wasm_slice(&self) -> BridgeResult<String> {
        info!("Setting up WASM slice");

        let wasm_slice_path = self.create_slice("wasm", None)?;
        let limits = ResourceLimits::wasm_sandbox();
        self.apply_limits(&wasm_slice_path, &limits)?;

        info!("WASM slice setup complete: {}", wasm_slice_path);
        Ok(wasm_slice_path)
    }

    pub fn setup_daemon_slice(&self) -> BridgeResult<String> {
        info!("Setting up daemon slice");

        let daemon_slice_path = self.create_slice("daemon", None)?;
        let limits = ResourceLimits::daemon();
        self.apply_limits(&daemon_slice_path, &limits)?;

        info!("Daemon slice setup complete: {}", daemon_slice_path);
        Ok(daemon_slice_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_limits_default() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.memory_max, 256 * 1024 * 1024);
        assert_eq!(limits.cpu_max, 50000);
        assert_eq!(limits.cpu_period, 1_000_000);
        assert_eq!(limits.pids_max, 32);
    }

    #[test]
    fn test_resource_limits_wasm_sandbox() {
        let limits = ResourceLimits::wasm_sandbox();
        assert_eq!(limits.memory_max, 256 * 1024 * 1024);
        assert_eq!(limits.cpu_max, 50000);
        assert_eq!(limits.pids_max, 32);
        assert_eq!(limits.memory_swap_max, 0);
    }

    #[test]
    fn test_resource_limits_daemon() {
        let limits = ResourceLimits::daemon();
        assert_eq!(limits.memory_max, 512 * 1024 * 1024);
        assert_eq!(limits.cpu_max, 100000);
        assert_eq!(limits.pids_max, 64);
    }

    #[test]
    fn test_resource_limits_validate() {
        let limits = ResourceLimits::default();
        assert!(limits.validate().is_ok());
    }

    #[test]
    fn test_resource_limits_validate_invalid() {
        let mut limits = ResourceLimits::default();
        limits.memory_max = 0;
        assert!(limits.validate().is_err());
    }
}
