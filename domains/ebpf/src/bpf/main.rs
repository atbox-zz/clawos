#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub enable_syscall_tracing: u8,
    pub enable_file_monitoring: u8,
    pub enable_network_monitoring: u8,
    pub enable_cgroup_monitoring: u8,
    pub syscall_anomaly_threshold: u32,
    pub file_access_violation_mode: u8,
    pub network_suspicious_threshold: u32,
    pub reserved: [u8; 7],
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enable_syscall_tracing: 1,
            enable_file_monitoring: 1,
            enable_network_monitoring: 1,
            enable_cgroup_monitoring: 1,
            syscall_anomaly_threshold: 1000,
            file_access_violation_mode: 1,
            network_suspicious_threshold: 100,
            reserved: [0; 7],
        }
    }
}
