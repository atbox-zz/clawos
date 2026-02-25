// ClawOS eBPF Event Structures
// Version: 1.0
// Specification: P1.3-ebpf-event-structs.md
//
// This module defines all eBPF event structures shared between kernel space
// (eBPF programs) and userspace (observability agent).
//
// CRITICAL: All structs must maintain binary compatibility with P1.3 spec.
// Any breaking change requires version bump and coordinated update.

#![allow(non_camel_case_types)]
#![allow(dead_code)]

// ============================================================================
// Event Type Enums
// ============================================================================

/// Event type classification for AnomalyEvent
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventType {
    Unknown = 0,
    SyscallAnomaly = 1,
    FileAccessViolation = 2,
    NetworkSuspicious = 3,
    CgroupThreshold = 4,
    ProcessAnomaly = 5,
    SecurityViolation = 6,
}

impl From<u8> for EventType {
    fn from(value: u8) -> Self {
        match value {
            1 => EventType::SyscallAnomaly,
            2 => EventType::FileAccessViolation,
            3 => EventType::NetworkSuspicious,
            4 => EventType::CgroupThreshold,
            5 => EventType::ProcessAnomaly,
            6 => EventType::SecurityViolation,
            _ => EventType::Unknown,
        }
    }
}

/// Severity level for anomaly events
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeverityCode {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl From<u8> for SeverityCode {
    fn from(value: u8) -> Self {
        match value {
            0 => SeverityCode::Info,
            1 => SeverityCode::Low,
            2 => SeverityCode::Medium,
            3 => SeverityCode::High,
            4 => SeverityCode::Critical,
            _ => SeverityCode::Info,
        }
    }
}

/// File access operation type
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileOperation {
    Read = 0,
    Write = 1,
    Execute = 2,
    Delete = 3,
    Create = 4,
    Rename = 5,
}

impl From<u8> for FileOperation {
    fn from(value: u8) -> Self {
        match value {
            0 => FileOperation::Read,
            1 => FileOperation::Write,
            2 => FileOperation::Execute,
            3 => FileOperation::Delete,
            4 => FileOperation::Create,
            5 => FileOperation::Rename,
            _ => FileOperation::Read,
        }
    }
}

/// Network protocol type
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkProtocol {
    Unknown = 0,
    Tcp = 1,
    Udp = 2,
    Icmp = 3,
    IcmpV6 = 4,
}

impl From<u8> for NetworkProtocol {
    fn from(value: u8) -> Self {
        match value {
            1 => NetworkProtocol::Tcp,
            2 => NetworkProtocol::Udp,
            3 => NetworkProtocol::Icmp,
            4 => NetworkProtocol::IcmpV6,
            _ => NetworkProtocol::Unknown,
        }
    }
}

/// Network connection direction
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkDirection {
    Unknown = 0,
    Inbound = 1,
    Outbound = 2,
}

impl From<u8> for NetworkDirection {
    fn from(value: u8) -> Self {
        match value {
            1 => NetworkDirection::Inbound,
            2 => NetworkDirection::Outbound,
            _ => NetworkDirection::Unknown,
        }
    }
}

/// Cgroup metric type for monitoring
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CgroupMetricType {
    Unknown = 0,
    MemoryUsage = 1,
    CpuUsage = 2,
    PidCount = 3,
    IoReadBytes = 4,
    IoWriteBytes = 5,
    NetworkRxBytes = 6,
    NetworkTxBytes = 7,
}

impl From<u8> for CgroupMetricType {
    fn from(value: u8) -> Self {
        match value {
            1 => CgroupMetricType::MemoryUsage,
            2 => CgroupMetricType::CpuUsage,
            3 => CgroupMetricType::PidCount,
            4 => CgroupMetricType::IoReadBytes,
            5 => CgroupMetricType::IoWriteBytes,
            6 => CgroupMetricType::NetworkRxBytes,
            7 => CgroupMetricType::NetworkTxBytes,
            _ => CgroupMetricType::Unknown,
        }
    }
}

// ============================================================================
// Event ID Mapping
// ============================================================================

/// Event ID discriminator for ring buffer events
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventId {
    Anomaly = 1,
    SyscallTrace = 2,
    FileAccess = 3,
    Network = 4,
    Cgroup = 5,
}

impl From<u8> for EventId {
    fn from(value: u8) -> Self {
        match value {
            1 => EventId::Anomaly,
            2 => EventId::SyscallTrace,
            3 => EventId::FileAccess,
            4 => EventId::Network,
            5 => EventId::Cgroup,
            _ => EventId::Anomaly,
        }
    }
}

// ============================================================================
// Event Header
// ============================================================================

/// Common header for all events
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct EventHeader {
    pub version: u8,
    pub event_id: u8,
    pub reserved: [u8; 2],
    pub timestamp_ns: u64,
}

impl Default for EventHeader {
    fn default() -> Self {
        Self {
            version: 1,
            event_id: 0,
            reserved: [0; 2],
            timestamp_ns: 0,
        }
    }
}

// ============================================================================
// Event Structures
// ============================================================================

/// General anomaly event structure for security and monitoring alerts
///
/// Total Size: 1056 bytes
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct AnomalyEvent {
    pub version: u8,
    pub event_type: u8,
    pub severity_code: u8,
    pub reserved: u8,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub gid: u32,
    pub description_len: u16,
    pub metadata_count: u16,
    pub description: [u8; 256],
    pub metadata_keys: [[u8; 32]; 8],
    pub metadata_values: [[u8; 64]; 8],
}

impl Default for AnomalyEvent {
    fn default() -> Self {
        Self {
            version: 1,
            event_type: 0,
            severity_code: 0,
            reserved: 0,
            timestamp_ns: 0,
            pid: 0,
            tid: 0,
            uid: 0,
            gid: 0,
            description_len: 0,
            metadata_count: 0,
            description: [0; 256],
            metadata_keys: [[0; 32]; 8],
            metadata_values: [[0; 64]; 8],
        }
    }
}

impl AnomalyEvent {
    pub fn get_event_type(&self) -> EventType {
        EventType::from(self.event_type)
    }

    pub fn get_severity(&self) -> SeverityCode {
        SeverityCode::from(self.severity_code)
    }

    pub fn description_str(&self) -> String {
        let len = self.description_len as usize;
        if len == 0 || len > 256 {
            return String::new();
        }
        String::from_utf8_lossy(&self.description[..len]).to_string()
    }
}

/// System call tracing event for monitoring process behavior
///
/// Total Size: 104 bytes
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct SyscallTraceEvent {
    pub version: u8,
    pub reserved: u8,
    pub sysnum: u16,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub return_value: i64,
    pub duration_ns: u64,
    pub arg_count: u8,
    pub args: [u64; 6],
    pub comm: [u8; 16],
}

impl Default for SyscallTraceEvent {
    fn default() -> Self {
        Self {
            version: 1,
            reserved: 0,
            sysnum: 0,
            timestamp_ns: 0,
            pid: 0,
            tid: 0,
            return_value: 0,
            duration_ns: 0,
            arg_count: 0,
            args: [0; 6],
            comm: [0; 16],
        }
    }
}

impl SyscallTraceEvent {
    pub fn comm_str(&self) -> String {
        String::from_utf8_lossy(&self.comm)
            .trim_end_matches('\0')
            .to_string()
    }
}

/// File access monitoring event for tracking file operations
///
/// Total Size: 304 bytes
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct FileAccessEvent {
    pub version: u8,
    pub operation: u8,
    pub permission_result: u8,
    pub reserved: u8,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub gid: u32,
    pub inode: u64,
    pub device_id: u32,
    pub mode: u32,
    pub path_len: u16,
    pub path: [u8; 256],
}

impl Default for FileAccessEvent {
    fn default() -> Self {
        Self {
            version: 1,
            operation: 0,
            permission_result: 0,
            reserved: 0,
            timestamp_ns: 0,
            pid: 0,
            tid: 0,
            uid: 0,
            gid: 0,
            inode: 0,
            device_id: 0,
            mode: 0,
            path_len: 0,
            path: [0; 256],
        }
    }
}

impl FileAccessEvent {
    pub fn get_operation(&self) -> FileOperation {
        FileOperation::from(self.operation)
    }

    pub fn is_granted(&self) -> bool {
        self.permission_result == 1
    }

    pub fn path_str(&self) -> String {
        let len = self.path_len as usize;
        if len == 0 || len > 256 {
            return String::new();
        }
        String::from_utf8_lossy(&self.path[..len]).to_string()
    }
}

/// Network activity monitoring event for tracking connections and traffic
///
/// Total Size: 72 bytes
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct NetworkEvent {
    pub version: u8,
    pub protocol: u8,
    pub direction: u8,
    pub reserved: u8,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub packet_size: u32,
    pub is_ipv4: u8,
    pub padding: [u8; 3],
}

impl Default for NetworkEvent {
    fn default() -> Self {
        Self {
            version: 1,
            protocol: 0,
            direction: 0,
            reserved: 0,
            timestamp_ns: 0,
            pid: 0,
            tid: 0,
            src_ip: [0; 16],
            dst_ip: [0; 16],
            src_port: 0,
            dst_port: 0,
            packet_size: 0,
            is_ipv4: 0,
            padding: [0; 3],
        }
    }
}

impl NetworkEvent {
    pub fn get_protocol(&self) -> NetworkProtocol {
        NetworkProtocol::from(self.protocol)
    }

    pub fn get_direction(&self) -> NetworkDirection {
        NetworkDirection::from(self.direction)
    }

    pub fn src_ip_str(&self) -> String {
        if self.is_ipv4 == 1 {
            format!("{}.{}.{}.{}",
                self.src_ip[0], self.src_ip[1], self.src_ip[2], self.src_ip[3])
        } else {
            // IPv6 representation
            let mut result = String::new();
            for i in 0..16 {
                if i > 0 && i % 2 == 0 {
                    result.push(':');
                }
                result.push_str(&format!("{:02x}", self.src_ip[i]));
            }
            result
        }
    }

    pub fn dst_ip_str(&self) -> String {
        if self.is_ipv4 == 1 {
            format!("{}.{}.{}.{}",
                self.dst_ip[0], self.dst_ip[1], self.dst_ip[2], self.dst_ip[3])
        } else {
            // IPv6 representation
            let mut result = String::new();
            for i in 0..16 {
                if i > 0 && i % 2 == 0 {
                    result.push(':');
                }
                result.push_str(&format!("{:02x}", self.dst_ip[i]));
            }
            result
        }
    }
}

/// Cgroup resource monitoring event for tracking resource usage and thresholds
///
/// Total Size: 304 bytes
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct CgroupEvent {
    pub version: u8,
    pub metric_type: u8,
    pub alert_flag: u8,
    pub reserved: u8,
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub value: u64,
    pub threshold: u64,
    pub pid_count: u32,
    pub cgroup_path_len: u16,
    pub cgroup_path: [u8; 256],
}

impl Default for CgroupEvent {
    fn default() -> Self {
        Self {
            version: 1,
            metric_type: 0,
            alert_flag: 0,
            reserved: 0,
            timestamp_ns: 0,
            cgroup_id: 0,
            value: 0,
            threshold: 0,
            pid_count: 0,
            cgroup_path_len: 0,
            cgroup_path: [0; 256],
        }
    }
}

impl CgroupEvent {
    pub fn get_metric_type(&self) -> CgroupMetricType {
        CgroupMetricType::from(self.metric_type)
    }

    pub fn is_alert(&self) -> bool {
        self.alert_flag == 1
    }

    pub fn cgroup_path_str(&self) -> String {
        let len = self.cgroup_path_len as usize;
        if len == 0 || len > 256 {
            return String::new();
        }
        String::from_utf8_lossy(&self.cgroup_path[..len]).to_string()
    }
}

// ============================================================================
// Size Verification Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anomaly_event_size() {
        assert_eq!(std::mem::size_of::<AnomalyEvent>(), 1056);
    }

    #[test]
    fn test_syscall_trace_event_size() {
        assert_eq!(std::mem::size_of::<SyscallTraceEvent>(), 104);
    }

    #[test]
    fn test_file_access_event_size() {
        assert_eq!(std::mem::size_of::<FileAccessEvent>(), 304);
    }

    #[test]
    fn test_network_event_size() {
        assert_eq!(std::mem::size_of::<NetworkEvent>(), 72);
    }

    #[test]
    fn test_cgroup_event_size() {
        assert_eq!(std::mem::size_of::<CgroupEvent>(), 304);
    }

    #[test]
    fn test_event_header_size() {
        assert_eq!(std::mem::size_of::<EventHeader>(), 12);
    }

    #[test]
    fn test_event_type_conversions() {
        assert_eq!(EventType::from(1), EventType::SyscallAnomaly);
        assert_eq!(EventType::from(255), EventType::Unknown);
    }

    #[test]
    fn test_severity_conversions() {
        assert_eq!(SeverityCode::from(3), SeverityCode::High);
        assert_eq!(SeverityCode::from(255), SeverityCode::Info);
    }

    #[test]
    fn test_file_operation_conversions() {
        assert_eq!(FileOperation::from(2), FileOperation::Execute);
        assert_eq!(FileOperation::from(255), FileOperation::Read);
    }

    #[test]
    fn test_network_protocol_conversions() {
        assert_eq!(NetworkProtocol::from(1), NetworkProtocol::Tcp);
        assert_eq!(NetworkProtocol::from(255), NetworkProtocol::Unknown);
    }

    #[test]
    fn test_cgroup_metric_conversions() {
        assert_eq!(CgroupMetricType::from(1), CgroupMetricType::MemoryUsage);
        assert_eq!(CgroupMetricType::from(255), CgroupMetricType::Unknown);
    }
}
