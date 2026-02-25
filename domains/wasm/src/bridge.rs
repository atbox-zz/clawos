use crate::error::{BridgeError, BridgeResult, ErrorCode};
use crate::resource::{FileDescriptor, DirectoryEntry, MemoryRegion, Socket, Cgroup, Device, FileStat, DeviceInfo};
use crate::security::{SeccompFilter, SecurityPolicy};
use crate::cgroup_manager::{CgroupManager, ResourceLimits};
use crate::WasmRuntime;
use wasmtime::{Engine, Linker, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use tracing::{info, debug, error, warn};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct WasmBridgeConfig {
    pub memory_limit: u64,
    pub cpu_limit: u64,
    pub cpu_period: u64,
    pub pid_limit: u64,
    pub security_policy: SecurityPolicy,
    pub enable_seccomp: bool,
    pub enable_cgroup: bool,
}

impl Default for WasmBridgeConfig {
    fn default() -> Self {
        WasmBridgeConfig {
            memory_limit: 256 * 1024 * 1024,
            cpu_limit: 50000,
            cpu_period: 1_000_000,
            pid_limit: 32,
            security_policy: SecurityPolicy::wasm_sandbox(),
            enable_seccomp: true,
            enable_cgroup: true,
        }
    }
}

pub struct WasmBridge {
    runtime: WasmRuntime,
    config: WasmBridgeConfig,
    cgroup_manager: Option<CgroupManager>,
    cgroup_path: Option<String>,
    file_descriptors: Arc<RwLock<HashMap<u64, FileDescriptor>>>,
    directory_entries: Arc<RwLock<HashMap<u64, DirectoryEntry>>>,
    memory_regions: Arc<RwLock<HashMap<u64, MemoryRegion>>>,
    sockets: Arc<RwLock<HashMap<u64, Socket>>>,
    cgroups: Arc<RwLock<HashMap<u64, Cgroup>>>,
    devices: Arc<RwLock<HashMap<u64, Device>>>,
    next_handle: Arc<Mutex<u64>>,
}

impl WasmBridge {
    pub fn new(runtime: WasmRuntime, config: WasmBridgeConfig) -> BridgeResult<Self> {
        info!("Initializing WASM Bridge");

        config.security_policy.validate()?;

        let cgroup_manager = if config.enable_cgroup {
            Some(CgroupManager::new()?)
        } else {
            None
        };

        let cgroup_path = if let Some(ref manager) = cgroup_manager {
            let path = manager.setup_wasm_slice()?;
            Some(path)
        } else {
            None
        };

        info!("WASM Bridge initialized successfully");
        Ok(WasmBridge {
            runtime,
            config,
            cgroup_manager,
            cgroup_path,
            file_descriptors: Arc::new(RwLock::new(HashMap::new())),
            directory_entries: Arc::new(RwLock::new(HashMap::new())),
            memory_regions: Arc::new(RwLock::new(HashMap::new())),
            sockets: Arc::new(RwLock::new(HashMap::new())),
            cgroups: Arc::new(RwLock::new(HashMap::new())),
            devices: Arc::new(RwLock::new(HashMap::new())),
            next_handle: Arc::new(Mutex::new(1)),
        })
    }

    fn next_handle(&self) -> u64 {
        let mut handle = self.next_handle.lock().unwrap();
        let h = *handle;
        *handle += 1;
        h
    }

    pub async fn apply_security(&self) -> BridgeResult<()> {
        info!("Applying security policy");

        if self.config.enable_seccomp {
            let mut seccomp = SeccompFilter::new(self.config.security_policy.strict_seccomp)?;
            seccomp.apply()?;
        }

        if let Some(ref cgroup_path) = self.cgroup_path {
            if let Some(ref manager) = self.cgroup_manager {
                let pid = std::process::id();
                manager.add_process(cgroup_path, pid)?;
            }
        }

        info!("Security policy applied successfully");
        Ok(())
    }

    pub async fn open(&self, path: &str, flags: u32, mode: u32) -> BridgeResult<u64> {
        debug!("Opening file: {} (flags: {}, mode: {})", path, flags, mode);

        let open_flags = match flags {
            0 => libc::O_RDONLY,
            1 => libc::O_WRONLY,
            2 => libc::O_RDWR,
            _ => return Err(BridgeError::with_code(ErrorCode::EINVAL, "Invalid open flags")),
        };

        let file = std::fs::File::open(path)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::ENOENT)), e.to_string()))?;

        let fd = FileDescriptor::new(file, path.to_string());
        let handle = self.next_handle();

        let mut fds = self.file_descriptors.write().await;
        fds.insert(handle, fd);

        debug!("File opened with handle: {}", handle);
        Ok(handle)
    }

    pub async fn mkdir(&self, path: &str, mode: u32) -> BridgeResult<()> {
        debug!("Creating directory: {} (mode: {})", path, mode);

        std::fs::create_dir_all(path)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

        debug!("Directory created: {}", path);
        Ok(())
    }

    pub async fn rmdir(&self, path: &str) -> BridgeResult<()> {
        debug!("Removing directory: {}", path);

        std::fs::remove_dir(path)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

        debug!("Directory removed: {}", path);
        Ok(())
    }

    pub async fn unlink(&self, path: &str) -> BridgeResult<()> {
        debug!("Unlinking file: {}", path);

        std::fs::remove_file(path)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

        debug!("File unlinked: {}", path);
        Ok(())
    }

    pub async fn rename(&self, old_path: &str, new_path: &str) -> BridgeResult<()> {
        debug!("Renaming {} to {}", old_path, new_path);

        std::fs::rename(old_path, new_path)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

        debug!("Renamed {} to {}", old_path, new_path);
        Ok(())
    }

    pub async fn stat(&self, path: &str) -> BridgeResult<FileStat> {
        debug!("Stating file: {}", path);

        let metadata = std::fs::metadata(path)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::ENOENT)), e.to_string()))?;

        Ok(FileStat {
            size: metadata.len(),
            mode: metadata.permissions().mode(),
            mtime: metadata.modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0),
            atime: metadata.accessed()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0),
            ctime: metadata.created()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0),
            ino: 0,
            dev: 0,
            nlink: metadata.nlink(),
            uid: 0,
            gid: 0,
            blksize: 4096,
            blocks: (metadata.len() + 511) / 512,
        })
    }

    pub async fn opendir(&self, path: &str) -> BridgeResult<u64> {
        debug!("Opening directory: {}", path);

        let dir_entry = DirectoryEntry::new(path.to_string())?;
        let handle = self.next_handle();

        let mut dirs = self.directory_entries.write().await;
        dirs.insert(handle, dir_entry);

        debug!("Directory opened with handle: {}", handle);
        Ok(handle)
    }

    pub async fn link(&self, old_path: &str, new_path: &str) -> BridgeResult<()> {
        debug!("Creating hard link: {} -> {}", old_path, new_path);

        std::os::unix::fs::link(old_path, new_path)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

        debug!("Hard link created: {} -> {}", old_path, new_path);
        Ok(())
    }

    pub async fn symlink(&self, target: &str, link_path: &str) -> BridgeResult<()> {
        debug!("Creating symlink: {} -> {}", link_path, target);

        std::os::unix::fs::symlink(target, link_path)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

        debug!("Symlink created: {} -> {}", link_path, target);
        Ok(())
    }

    pub async fn readlink(&self, path: &str) -> BridgeResult<String> {
        debug!("Reading symlink: {}", path);

        let target = std::fs::read_link(path)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

        debug!("Symlink target: {}", target.display());
        Ok(target.to_string_lossy().to_string())
    }

    pub async fn chmod(&self, path: &str, mode: u32) -> BridgeResult<()> {
        debug!("Changing permissions: {} to {}", path, mode);

        let mut perms = std::fs::metadata(path)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::ENOENT)), e.to_string()))?
            .permissions();

        perms.set_mode(mode);

        std::fs::set_permissions(path, perms)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

        debug!("Permissions changed: {} to {}", path, mode);
        Ok(())
    }

    pub async fn chown(&self, _path: &str, _uid: u32, _gid: u32) -> BridgeResult<()> {
        warn!("chown not implemented in userspace daemon");
        Err(BridgeError::with_code(ErrorCode::NotSupported, "chown not supported"))
    }

    pub async fn truncate(&self, path: &str, length: u64) -> BridgeResult<()> {
        debug!("Truncating file: {} to {} bytes", path, length);

        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::ENOENT)), e.to_string()))?;

        file.set_len(length)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

        debug!("File truncated: {} to {} bytes", path, length);
        Ok(())
    }

    pub async fn sync(&self, path: &str) -> BridgeResult<()> {
        debug!("Syncing file: {}", path);

        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::ENOENT)), e.to_string()))?;

        file.sync_all()
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

        debug!("File synced: {}", path);
        Ok(())
    }

    pub async fn socket(&self, _domain: u32, _type: u32, _protocol: u32) -> BridgeResult<u64> {
        debug!("Creating socket");

        let socket = Socket::new();
        let handle = self.next_handle();

        let mut sockets = self.sockets.write().await;
        sockets.insert(handle, socket);

        debug!("Socket created with handle: {}", handle);
        Ok(handle)
    }

    pub async fn resolve(&self, hostname: &str) -> BridgeResult<String> {
        debug!("Resolving hostname: {}", hostname);

        use std::net::ToSocketAddrs;
        let addr = format!("{}:80", hostname);
        let addrs = addr.to_socket_addrs()
            .map_err(|e| BridgeError::with_code(ErrorCode::EIO, e.to_string()))?;

        for addr in addrs {
            return Ok(addr.ip().to_string());
        }

        Err(BridgeError::with_code(ErrorCode::EIO, "Failed to resolve hostname"))
    }

    pub async fn gethostname(&self) -> BridgeResult<String> {
        debug!("Getting hostname");

        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("HOST"))
            .unwrap_or_else(|_| "localhost".to_string());

        debug!("Hostname: {}", hostname);
        Ok(hostname)
    }

    pub async fn cgroup_create(&self, name: &str, parent: &str) -> BridgeResult<u64> {
        debug!("Creating cgroup: {} (parent: {})", name, parent);

        let manager = self.cgroup_manager.as_ref()
            .ok_or_else(|| BridgeError::with_code(ErrorCode::NotSupported, "Cgroup manager not enabled"))?;

        let path = if parent.is_empty() {
            manager.create_slice(name, None)?
        } else {
            manager.create_slice(name, Some(parent))?
        };

        let cgroup = Cgroup::new(path);
        let handle = self.next_handle();

        let mut cgroups = self.cgroups.write().await;
        cgroups.insert(handle, cgroup);

        debug!("Cgroup created with handle: {}", handle);
        Ok(handle)
    }

    pub async fn cgroup_open(&self, path: &str) -> BridgeResult<u64> {
        debug!("Opening cgroup: {}", path);

        let manager = self.cgroup_manager.as_ref()
            .ok_or_else(|| BridgeError::with_code(ErrorCode::NotSupported, "Cgroup manager not enabled"))?;

        let cgroup = manager.get_cgroup(path)?;
        let handle = self.next_handle();

        let mut cgroups = self.cgroups.write().await;
        cgroups.insert(handle, cgroup);

        debug!("Cgroup opened with handle: {}", handle);
        Ok(handle)
    }

    pub async fn cgroup_delete(&self, path: &str) -> BridgeResult<()> {
        debug!("Deleting cgroup: {}", path);

        let manager = self.cgroup_manager.as_ref()
            .ok_or_else(|| BridgeError::with_code(ErrorCode::NotSupported, "Cgroup manager not enabled"))?;

        manager.delete_cgroup(path)?;

        debug!("Cgroup deleted: {}", path);
        Ok(())
    }

    pub async fn cgroup_add_process(&self, cgroup_path: &str, pid: u32) -> BridgeResult<()> {
        debug!("Adding process {} to cgroup: {}", pid, cgroup_path);

        let manager = self.cgroup_manager.as_ref()
            .ok_or_else(|| BridgeError::with_code(ErrorCode::NotSupported, "Cgroup manager not enabled"))?;

        manager.add_process(cgroup_path, pid)?;

        debug!("Process {} added to cgroup: {}", pid, cgroup_path);
        Ok(())
    }

    pub async fn cgroup_remove_process(&self, cgroup_path: &str, pid: u32) -> BridgeResult<()> {
        debug!("Removing process {} from cgroup: {}", pid, cgroup_path);

        let manager = self.cgroup_manager.as_ref()
            .ok_or_else(|| BridgeError::with_code(ErrorCode::NotSupported, "Cgroup manager not enabled"))?;

        manager.remove_process(cgroup_path, pid)?;

        debug!("Process {} removed from cgroup: {}", pid, cgroup_path);
        Ok(())
    }

    pub async fn memory_allocate(&self, size: u32, name: String) -> BridgeResult<u64> {
        debug!("Allocating memory region: {} bytes (name: {})", size, name);

        let mem_region = MemoryRegion::new(size, name)?;
        let handle = self.next_handle();

        let mut mem_regions = self.memory_regions.write().await;
        mem_regions.insert(handle, mem_region);

        debug!("Memory region allocated with handle: {}", handle);
        Ok(handle)
    }

    pub async fn memory_get_usage(&self) -> BridgeResult<u64> {
        debug!("Getting memory usage");

        if let Some(ref cgroup_path) = self.cgroup_path {
            if let Some(ref manager) = self.cgroup_manager {
                return manager.get_memory_usage(cgroup_path);
            }
        }

        Ok(0)
    }

    pub async fn memory_get_limit(&self) -> BridgeResult<u64> {
        debug!("Getting memory limit");
        Ok(self.config.memory_limit)
    }

    pub async fn device_open(&self, path: &str, flags: u32) -> BridgeResult<u64> {
        debug!("Opening device: {} (flags: {})", path, flags);

        let device = Device::new(path.to_string());
        device.open(flags).await?;

        let handle = self.next_handle();

        let mut devices = self.devices.write().await;
        devices.insert(handle, device);

        debug!("Device opened with handle: {}", handle);
        Ok(handle)
    }

    pub async fn device_get_info(&self, path: &str) -> BridgeResult<DeviceInfo> {
        debug!("Getting device info: {}", path);

        let metadata = std::fs::metadata(path)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::ENOENT)), e.to_string()))?;

        let device_type = if metadata.file_type().is_block_device() {
            1
        } else if metadata.file_type().is_char_device() {
            0
        } else {
            return Err(BridgeError::with_code(ErrorCode::EINVAL, "Not a device"));
        };

        Ok(DeviceInfo {
            major: 0,
            minor: 0,
            device_type,
        })
    }

    pub async fn system_get_info(&self) -> BridgeResult<SystemInfo> {
        debug!("Getting system info");

        let sysname = "Linux".to_string();
        let nodename = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("HOST"))
            .unwrap_or_else(|_| "localhost".to_string());
        let release = "6.6.0".to_string();
        let version = "".to_string();
        let machine = std::env::consts::ARCH.to_string();
        let cpus = num_cpus::get() as u32;
        let total_memory = self.config.memory_limit;
        let free_memory = total_memory / 2;

        Ok(SystemInfo {
            sysname,
            nodename,
            release,
            version,
            machine,
            cpus,
            total_memory,
            free_memory,
        })
    }

    pub async fn system_get_time(&self) -> BridgeResult<u64> {
        debug!("Getting system time");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| BridgeError::with_code(ErrorCode::EIO, e.to_string()))?;

        Ok(now.as_nanos() as u64)
    }

    pub async fn system_sleep(&self, duration_ns: u64) -> BridgeResult<()> {
        debug!("Sleeping for {} ns", duration_ns);

        let duration = std::time::Duration::from_nanos(duration_ns);
        tokio::time::sleep(duration).await;

        debug!("Sleep completed");
        Ok(())
    }

    pub async fn system_get_env(&self, name: &str) -> BridgeResult<String> {
        debug!("Getting environment variable: {}", name);

        let value = std::env::var(name)
            .map_err(|_| BridgeError::with_code(ErrorCode::ENOENT, "Environment variable not found"))?;

        debug!("Environment variable: {} = {}", name, value);
        Ok(value)
    }

    pub async fn system_set_env(&self, name: &str, value: &str) -> BridgeResult<()> {
        debug!("Setting environment variable: {} = {}", name, value);

        std::env::set_var(name, value);

        debug!("Environment variable set: {} = {}", name, value);
        Ok(())
    }

    pub async fn system_get_pid(&self) -> BridgeResult<u32> {
        debug!("Getting PID");
        Ok(std::process::id())
    }

    pub async fn system_get_ppid(&self) -> BridgeResult<u32> {
        debug!("Getting PPID");

        let ppid = unsafe { libc::getppid() };
        Ok(ppid as u32)
    }

    pub async fn system_exit(&self, exit_code: u32) -> ! {
        info!("Exiting with code: {}", exit_code);
        std::process::exit(exit_code as i32);
    }

    pub async fn logging_log(&self, level: u32, message: &str) {
        match level {
            0 => debug!("[WASM] {}", message),
            1 => info!("[WASM] {}", message),
            2 => warn!("[WASM] {}", message),
            3 => error!("[WASM] {}", message),
            _ => info!("[WASM] {}", message),
        }
    }

    pub async fn logging_debug(&self, message: &str) {
        debug!("[WASM] {}", message);
    }

    pub async fn logging_info(&self, message: &str) {
        info!("[WASM] {}", message);
    }

    pub async fn logging_warn(&self, message: &str) {
        warn!("[WASM] {}", message);
    }

    pub async fn logging_error(&self, message: &str) {
        error!("[WASM] {}", message);
    }
}

#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub sysname: String,
    pub nodename: String,
    pub release: String,
    pub version: String,
    pub machine: String,
    pub cpus: u32,
    pub total_memory: u64,
    pub free_memory: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_bridge_config_default() {
        let config = WasmBridgeConfig::default();
        assert_eq!(config.memory_limit, 256 * 1024 * 1024);
        assert_eq!(config.cpu_limit, 50000);
        assert_eq!(config.pid_limit, 32);
    }
}
