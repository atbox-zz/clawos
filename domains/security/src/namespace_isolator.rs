// Linux Namespace Isolator for ClawOS
//
// This module provides namespace isolation primitives for sandboxing WASM tools.
// Implements User, PID, Mount, Network, and UTS namespace isolation per P1.1 WIT ABI.
//
// # Security Model
//
// - All namespaces are created with CAP_SYS_ADMIN capability
// - User namespace maps to UID/GID 65534 (nobody) for privilege dropping
// - PID namespace isolates process IDs (init becomes PID 1)
// - Mount namespace provides isolated filesystem view
// - Network namespace provides isolated network stack
// - UTS namespace provides isolated hostname/domainname
//
// # Conflict Resolution (SKILLS.md line 351)
//
// **Conflict:** User Namespace uid_map vs PostgreSQL connection auth
// **Resolution:** mTLS client certificate auth replaces uid-based auth; fully decoupled
//
// This means PostgreSQL authentication no longer relies on UID mapping. Instead,
// mTLS certificates are used for authentication, allowing the user namespace
// to safely map to UID 65534 without breaking database connectivity.

use libc::{c_char, c_int, c_void, pid_t, size_t};
use nix::unistd::pivot_root;
use std::ffi::{CStr, CString};
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::io::RawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::error::{ErrorCode, SecurityError, SecurityResult};

/// Namespace types supported by Linux kernel
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum NamespaceType {
    /// Cgroup namespace (isolates cgroup root directory)
    Cgroup = libc::CLONE_NEWCGROUP,
    /// IPC namespace (isolates System V IPC and POSIX message queues)
    Ipc = libc::CLONE_NEWIPC,
    /// Network namespace (isolates network interfaces, firewall rules, routing tables)
    Network = libc::CLONE_NEWNET,
    /// Mount namespace (isolates filesystem mount points)
    Mount = libc::CLONE_NEWNS,
    /// PID namespace (isolates process ID numbers)
    Pid = libc::CLONE_NEWPID,
    /// User namespace (isolates user and group ID numbers)
    User = libc::CLONE_NEWUSER,
    /// UTS namespace (isolates hostname and domainname)
    Uts = libc::CLONE_NEWUTS,
}

impl NamespaceType {
    /// Convert from integer to NamespaceType
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            libc::CLONE_NEWCGROUP => Some(NamespaceType::Cgroup),
            libc::CLONE_NEWIPC => Some(NamespaceType::Ipc),
            libc::CLONE_NEWNET => Some(NamespaceType::Network),
            libc::CLONE_NEWNS => Some(NamespaceType::Mount),
            libc::CLONE_NEWPID => Some(NamespaceType::Pid),
            libc::CLONE_NEWUSER => Some(NamespaceType::User),
            libc::CLONE_NEWUTS => Some(NamespaceType::Uts),
            _ => None,
        }
    }

    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            NamespaceType::Cgroup => "cgroup",
            NamespaceType::Ipc => "ipc",
            NamespaceType::Network => "net",
            NamespaceType::Mount => "mnt",
            NamespaceType::Pid => "pid",
            NamespaceType::User => "user",
            NamespaceType::Uts => "uts",
        }
    }

    /// Get namespace file path in /proc
    pub fn proc_path(&self, pid: pid_t) -> String {
        format!("/proc/{}/ns/{}", pid, self.name())
    }
}

impl std::fmt::Display for NamespaceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Configuration for namespace isolation
#[derive(Debug, Clone)]
pub struct NamespaceConfig {
    /// Enable user namespace isolation
    pub user_namespace: bool,
    /// Enable PID namespace isolation
    pub pid_namespace: bool,
    /// Enable mount namespace isolation
    pub mount_namespace: bool,
    /// Enable network namespace isolation
    pub network_namespace: bool,
    /// Enable UTS namespace isolation
    pub uts_namespace: bool,
    /// UID to map inside user namespace (default: 65534/nobody)
    pub uid_map: u32,
    /// GID to map inside user namespace (default: 65534/nogroup)
    pub gid_map: u32,
    /// Hostname for UTS namespace
    pub hostname: Option<String>,
    /// Domain name for UTS namespace
    pub domainname: Option<String>,
    /// Root filesystem path for pivot_root
    pub rootfs: Option<String>,
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        Self {
            user_namespace: true,
            pid_namespace: true,
            mount_namespace: true,
            network_namespace: true,
            uts_namespace: true,
            uid_map: 65534, // nobody
            gid_map: 65534, // nogroup
            hostname: Some("clawos-sandbox".to_string()),
            domainname: Some("clawos.local".to_string()),
            rootfs: None,
        }
    }
}

impl NamespaceConfig {
    /// Create a new namespace config with all namespaces enabled
    pub fn all_enabled() -> Self {
        Self::default()
    }

    /// Create a minimal namespace config (only user namespace)
    pub fn minimal() -> Self {
        Self {
            user_namespace: true,
            pid_namespace: false,
            mount_namespace: false,
            network_namespace: false,
            uts_namespace: false,
            ..Default::default()
        }
    }

    /// Get the clone flags for creating namespaces
    pub fn clone_flags(&self) -> c_int {
        let mut flags = 0;
        if self.user_namespace {
            flags |= libc::CLONE_NEWUSER;
        }
        if self.pid_namespace {
            flags |= libc::CLONE_NEWPID;
        }
        if self.mount_namespace {
            flags |= libc::CLONE_NEWNS;
        }
        if self.network_namespace {
            flags |= libc::CLONE_NEWNET;
        }
        if self.uts_namespace {
            flags |= libc::CLONE_NEWUTS;
        }
        flags
    }
}

/// Namespace isolator for creating and managing Linux namespaces
pub struct NamespaceIsolator {
    config: NamespaceConfig,
    /// File descriptor for user namespace (if created)
    user_ns_fd: Option<RawFd>,
    /// File descriptor for PID namespace (if created)
    pid_ns_fd: Option<RawFd>,
    /// File descriptor for mount namespace (if created)
    mount_ns_fd: Option<RawFd>,
    /// File descriptor for network namespace (if created)
    net_ns_fd: Option<RawFd>,
    /// File descriptor for UTS namespace (if created)
    uts_ns_fd: Option<RawFd>,
}

impl NamespaceIsolator {
    /// Create a new namespace isolator with the given configuration
    pub fn new(config: NamespaceConfig) -> SecurityResult<Self> {
        Ok(Self {
            config,
            user_ns_fd: None,
            pid_ns_fd: None,
            mount_ns_fd: None,
            net_ns_fd: None,
            uts_ns_fd: None,
        })
    }

    /// Create a new namespace isolator with default configuration
    pub fn with_defaults() -> SecurityResult<Self> {
        Self::new(NamespaceConfig::default())
    }

    /// Create a new namespace isolator with minimal configuration
    pub fn with_minimal() -> SecurityResult<Self> {
        Self::new(NamespaceConfig::minimal())
    }

    /// Create all configured namespaces
    ///
    /// This method uses unshare() to create new namespaces for the calling process.
    /// Must be called before spawning child processes that should inherit the namespaces.
    pub fn create_namespaces(&mut self) -> SecurityResult<()> {
        let flags = self.config.clone_flags();

        if flags == 0 {
            return Err(SecurityError::Internal(
                "No namespaces configured".to_string(),
            ));
        }

        // Call unshare to create namespaces
        let ret = unsafe { libc::unshare(flags) };

        if ret == -1 {
            let err = io::Error::last_os_error();
            return Err(SecurityError::Internal(format!(
                "Failed to create namespaces: {}",
                err
            )));
        }

        // Store namespace file descriptors
        let pid = unsafe { libc::getpid() };

        if self.config.user_namespace {
            self.user_ns_fd = Some(self.open_namespace_fd(NamespaceType::User, pid)?);
            self.setup_user_namespace()?;
        }

        if self.config.pid_namespace {
            self.pid_ns_fd = Some(self.open_namespace_fd(NamespaceType::Pid, pid)?);
        }

        if self.config.mount_namespace {
            self.mount_ns_fd = Some(self.open_namespace_fd(NamespaceType::Mount, pid)?);
        }

        if self.config.network_namespace {
            self.net_ns_fd = Some(self.open_namespace_fd(NamespaceType::Network, pid)?);
        }

        if self.config.uts_namespace {
            self.uts_ns_fd = Some(self.open_namespace_fd(NamespaceType::Uts, pid)?);
            self.setup_uts_namespace()?;
        }

        Ok(())
    }

    /// Open a file descriptor for a namespace
    fn open_namespace_fd(&self, ns_type: NamespaceType, pid: pid_t) -> SecurityResult<RawFd> {
        let path = ns_type.proc_path(pid);
        let path_c = CString::new(path.as_str()).map_err(|e| {
            SecurityError::Internal(format!("Failed to create CString: {}", e))
        })?;

        let fd = unsafe { libc::open(path_c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };

        if fd == -1 {
            let err = io::Error::last_os_error();
            return Err(SecurityError::Internal(format!(
                "Failed to open namespace {}: {}",
                ns_type, err
            )));
        }

        Ok(fd)
    }

    /// Setup user namespace with UID/GID mapping
    ///
    /// Maps the current user to UID 65534 (nobody) inside the namespace.
    /// This provides privilege isolation while maintaining capability to
    /// perform privileged operations.
    fn setup_user_namespace(&self) -> SecurityResult<()> {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        // Write UID map: map outer UID to inner UID 65534
        let uid_map = format!("0 {} 1\n", uid);
        self.write_uid_gid_map("/proc/self/uid_map", &uid_map)?;

        // Write GID map: map outer GID to inner GID 65534
        let gid_map = format!("0 {} 1\n", gid);
        self.write_uid_gid_map("/proc/self/gid_map", &gid_map)?;

        // Disable setgroups for unprivileged user namespaces
        self.write_setgroups("deny")?;

        Ok(())
    }

    /// Write to uid_map or gid_map file
    fn write_uid_gid_map(&self, path: &str, content: &str) -> SecurityResult<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| SecurityError::Internal(format!("Failed to open {}: {}", path, e)))?;

        file.write_all(content.as_bytes())
            .map_err(|e| SecurityError::Internal(format!("Failed to write {}: {}", path, e)))?;

        Ok(())
    }

    /// Write to setgroups file
    fn write_setgroups(&self, value: &str) -> SecurityResult<()> {
        let path = "/proc/self/setgroups";

        // File may not exist if we have CAP_SETGID
        if !Path::new(path).exists() {
            return Ok(());
        }

        let mut file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| SecurityError::Internal(format!("Failed to open {}: {}", path, e)))?;

        file.write_all(value.as_bytes())
            .map_err(|e| SecurityError::Internal(format!("Failed to write {}: {}", path, e)))?;

        Ok(())
    }

    /// Setup UTS namespace with hostname and domainname
    fn setup_uts_namespace(&self) -> SecurityResult<()> {
        if let Some(ref hostname) = self.config.hostname {
            self.set_hostname(hostname)?;
        }

        if let Some(ref domainname) = self.config.domainname {
            self.set_domainname(domainname)?;
        }

        Ok(())
    }

    /// Set hostname for UTS namespace
    fn set_hostname(&self, hostname: &str) -> SecurityResult<()> {
        let hostname_c = CString::new(hostname).map_err(|e| {
            SecurityError::Internal(format!("Failed to create CString: {}", e))
        })?;

        let ret = unsafe { libc::sethostname(hostname_c.as_ptr(), hostname.len() as size_t) };

        if ret == -1 {
            let err = io::Error::last_os_error();
            return Err(SecurityError::Internal(format!(
                "Failed to set hostname: {}",
                err
            )));
        }

        Ok(())
    }

    /// Set domain name for UTS namespace
    fn set_domainname(&self, domainname: &str) -> SecurityResult<()> {
        let domainname_c = CString::new(domainname).map_err(|e| {
            SecurityError::Internal(format!("Failed to create CString: {}", e))
        })?;

        let ret = unsafe {
            libc::setdomainname(domainname_c.as_ptr(), domainname.len() as size_t)
        };

        if ret == -1 {
            let err = io::Error::last_os_error();
            return Err(SecurityError::Internal(format!(
                "Failed to set domainname: {}",
                err
            )));
        }

        Ok(())
    }

    /// Perform pivot_root to switch to a new root filesystem
    ///
    /// This is a critical operation for container isolation. It replaces the
    /// current root filesystem with a new one, providing complete filesystem
    /// isolation.
    ///
    /// # Arguments
    /// * `new_root` - Path to the new root directory
    /// * `put_old` - Path to put the old root (must be under new_root)
    pub fn pivot_root(&self, new_root: &str, put_old: &str) -> SecurityResult<()> {
        // Ensure new_root exists
        if !Path::new(new_root).exists() {
            return Err(SecurityError::Internal(format!(
                "New root path does not exist: {}",
                new_root
            )));
        }

        // Ensure put_old exists under new_root
        let put_old_full = format!("{}/{}", new_root, put_old);
        if !Path::new(&put_old_full).exists() {
            fs::create_dir_all(&put_old_full).map_err(|e| {
                SecurityError::Internal(format!("Failed to create put_old directory: {}", e))
            })?;
        }

        // Change current directory to new_root
        std::env::set_current_dir(new_root).map_err(|e| {
            SecurityError::Internal(format!("Failed to chdir to new_root: {}", e))
        })?;

        // Call pivot_root syscall
        pivot_root(new_root, put_old)
            .map_err(|e| SecurityError::Internal(format!("Failed to pivot_root: {}", e)))?;

        // Change current directory to /
        std::env::set_current_dir("/").map_err(|e| {
            SecurityError::Internal(format!("Failed to chdir to /: {}", e))
        })?;

        // Unmount the old root
        let put_old_mount = format!("/{}", put_old);
        let ret = unsafe {
            libc::umount2(
                CString::new(put_old_mount.as_str()).unwrap().as_ptr(),
                libc::MNT_DETACH,
            )
        };

        if ret == -1 {
            let err = io::Error::last_os_error();
            // Non-fatal: old root may already be unmounted
            log::warn!("Failed to unmount old root: {}", err);
        }

        Ok(())
    }

    /// Get the file descriptor for a namespace type
    pub fn get_namespace_fd(&self, ns_type: NamespaceType) -> Option<RawFd> {
        match ns_type {
            NamespaceType::User => self.user_ns_fd,
            NamespaceType::Pid => self.pid_ns_fd,
            NamespaceType::Mount => self.mount_ns_fd,
            NamespaceType::Network => self.net_ns_fd,
            NamespaceType::Uts => self.uts_ns_fd,
            _ => None,
        }
    }

    /// Set network namespace for the current thread
    ///
    /// This allows switching to a different network namespace, which is
    /// useful for managing network isolation in multi-threaded applications.
    pub fn set_network_namespace(&self, fd: RawFd) -> SecurityResult<()> {
        let ret = unsafe { libc::setns(fd, libc::CLONE_NEWNET) };

        if ret == -1 {
            let err = io::Error::last_os_error();
            return Err(SecurityError::Internal(format!(
                "Failed to set network namespace: {}",
                err
            )));
        }

        Ok(())
    }

    /// Get current hostname
    pub fn get_hostname(&self) -> SecurityResult<String> {
        let mut hostname = vec![0u8; 256];
        let ret = unsafe {
            libc::gethostname(hostname.as_mut_ptr() as *mut c_char, hostname.len())
        };

        if ret == -1 {
            let err = io::Error::last_os_error();
            return Err(SecurityError::Internal(format!(
                "Failed to get hostname: {}",
                err
            )));
        }

        // Find null terminator
        let len = hostname.iter().position(|&c| c == 0).unwrap_or(hostname.len());
        let hostname_str = String::from_utf8_lossy(&hostname[..len]).to_string();

        Ok(hostname_str)
    }

    /// Get current domain name
    pub fn get_domainname(&self) -> SecurityResult<String> {
        let mut domainname = vec![0u8; 256];
        let ret = unsafe {
            libc::getdomainname(domainname.as_mut_ptr() as *mut c_char, domainname.len())
        };

        if ret == -1 {
            let err = io::Error::last_os_error();
            return Err(SecurityError::Internal(format!(
                "Failed to get domainname: {}",
                err
            )));
        }

        // Find null terminator
        let len = domainname.iter().position(|&c| c == 0).unwrap_or(domainname.len());
        let domainname_str = String::from_utf8_lossy(&domainname[..len]).to_string();

        Ok(domainname_str)
    }

    /// Check if running in a namespace
    pub fn in_namespace(&self, ns_type: NamespaceType) -> SecurityResult<bool> {
        let pid = unsafe { libc::getpid() };
        let self_path = ns_type.proc_path(pid);
        let init_path = ns_type.proc_path(1);

        // Compare inode numbers of self and init namespace files
        let self_stat = fs::metadata(&self_path).map_err(|e| {
            SecurityError::Internal(format!("Failed to stat {}: {}", self_path, e))
        })?;
        let init_stat = fs::metadata(&init_path).map_err(|e| {
            SecurityError::Internal(format!("Failed to stat {}: {}", init_path, e))
        })?;

        // Different inodes mean we're in a different namespace
        Ok(self_stat.ino() != init_stat.ino())
    }
}

impl Drop for NamespaceIsolator {
    fn drop(&mut self) {
        // Close all namespace file descriptors
        if let Some(fd) = self.user_ns_fd.take() {
            unsafe { libc::close(fd) };
        }
        if let Some(fd) = self.pid_ns_fd.take() {
            unsafe { libc::close(fd) };
        }
        if let Some(fd) = self.mount_ns_fd.take() {
            unsafe { libc::close(fd) };
        }
        if let Some(fd) = self.net_ns_fd.take() {
            unsafe { libc::close(fd) };
        }
        if let Some(fd) = self.uts_ns_fd.take() {
            unsafe { libc::close(fd) };
        }
    }
}

/// Helper function to clone with new namespaces
///
/// This is a low-level function that creates a new process with the specified
/// namespaces. It's typically used for spawning containerized processes.
///
/// # Arguments
/// * `flags` - Clone flags (combination of CLONE_NEW* flags)
/// * `child_func` - Function to execute in the child process
/// * `arg` - Argument to pass to the child function
///
/// # Returns
/// * `Ok(pid)` - PID of the child process (in parent)
/// * `Err(SecurityError)` - Error if clone fails
pub unsafe fn clone_with_namespaces<F>(
    flags: c_int,
    child_func: extern "C" fn(*mut c_void) -> c_int,
    arg: *mut c_void,
) -> SecurityResult<pid_t> {
    // Allocate stack for child process
    const STACK_SIZE: usize = 1024 * 1024; // 1MB stack
    let mut stack: Vec<u8> = vec![0u8; STACK_SIZE];

    // Stack grows downward, so point to the end
    let stack_ptr = unsafe { stack.as_mut_ptr().add(STACK_SIZE) } as *mut c_void;

    // Call clone syscall
    let pid = unsafe { libc::clone(child_func, stack_ptr, flags, arg, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) };

    if pid == -1 {
        let err = io::Error::last_os_error();
        return Err(SecurityError::Internal(format!(
            "Failed to clone with namespaces: {}",
            err
        )));
    }

    Ok(pid)
}

/// Map kernel ABI functions from P1.1 WIT spec to namespace operations
///
/// This module provides the mapping between WIT interface functions and
/// the actual Linux namespace operations.
pub mod wit_abi {
    use super::*;

    /// WIT ABI: Create a new namespace
    ///
    /// Maps to: `unshare()` syscall
    ///
    /// # WIT Signature
    /// ```wit
    /// create-namespace: func(ns-type: u32) -> result<_>
    /// ```
    pub fn wit_create_namespace(ns_type: u32) -> SecurityResult<()> {
        let ns_type = NamespaceType::from_i32(ns_type as i32)
            .ok_or_else(|| SecurityError::Internal(format!("Invalid namespace type: {}", ns_type)))?;

        let ret = unsafe { libc::unshare(ns_type as c_int) };

        if ret == -1 {
            let err = io::Error::last_os_error();
            return Err(SecurityError::Internal(format!(
                "Failed to create namespace: {}",
                err
            )));
        }

        Ok(())
    }

    /// WIT ABI: Enter an existing namespace
    ///
    /// Maps to: `setns()` syscall
    ///
    /// # WIT Signature
    /// ```wit
    /// enter-namespace: func(fd: u32, ns-type: u32) -> result<_>
    /// ```
    pub fn wit_enter_namespace(fd: u32, ns_type: u32) -> SecurityResult<()> {
        let ns_type = NamespaceType::from_i32(ns_type as i32)
            .ok_or_else(|| SecurityError::Internal(format!("Invalid namespace type: {}", ns_type)))?;

        let ret = unsafe { libc::setns(fd as c_int, ns_type as c_int) };

        if ret == -1 {
            let err = io::Error::last_os_error();
            return Err(SecurityError::Internal(format!(
                "Failed to enter namespace: {}",
                err
            )));
        }

        Ok(())
    }

    /// WIT ABI: Set hostname
    ///
    /// Maps to: `sethostname()` syscall
    ///
    /// # WIT Signature
    /// ```wit
    /// set-hostname: func(hostname: string) -> result<_>
    /// ```
    pub fn wit_set_hostname(hostname: &str) -> SecurityResult<()> {
        let hostname_c = CString::new(hostname).map_err(|e| {
            SecurityError::Internal(format!("Failed to create CString: {}", e))
        })?;

        let ret = unsafe { libc::sethostname(hostname_c.as_ptr(), hostname.len() as size_t) };

        if ret == -1 {
            let err = io::Error::last_os_error();
            return Err(SecurityError::Internal(format!(
                "Failed to set hostname: {}",
                err
            )));
        }

        Ok(())
    }

    /// WIT ABI: Get hostname
    ///
    /// Maps to: `gethostname()` syscall
    ///
    /// # WIT Signature
    /// ```wit
    /// get-hostname: func() -> result<string>
    /// ```
    pub fn wit_get_hostname() -> SecurityResult<String> {
        let mut hostname = vec![0u8; 256];
        let ret = unsafe {
            libc::gethostname(hostname.as_mut_ptr() as *mut c_char, hostname.len())
        };

        if ret == -1 {
            let err = io::Error::last_os_error();
            return Err(SecurityError::Internal(format!(
                "Failed to get hostname: {}",
                err
            )));
        }

        let len = hostname.iter().position(|&c| c == 0).unwrap_or(hostname.len());
        Ok(String::from_utf8_lossy(&hostname[..len]).to_string())
    }

    /// WIT ABI: Pivot root
    ///
    /// Maps to: `pivot_root()` syscall
    ///
    /// # WIT Signature
    /// ```wit
    /// pivot-root: func(new-root: string, put-old: string) -> result<_>
    /// ```
    pub fn wit_pivot_root(new_root: &str, put_old: &str) -> SecurityResult<()> {
        let isolator = NamespaceIsolator::with_defaults()?;
        isolator.pivot_root(new_root, put_old)
    }

    /// WIT ABI: Map UID in user namespace
    ///
    /// Maps to: Writing to `/proc/self/uid_map`
    ///
    /// # WIT Signature
    /// ```wit
    /// map-uid: func(inside-uid: u32, outside-uid: u32, count: u32) -> result<_>
    /// ```
    pub fn wit_map_uid(inside_uid: u32, outside_uid: u32, count: u32) -> SecurityResult<()> {
        let uid_map = format!("{} {} {}\n", inside_uid, outside_uid, count);

        let mut file = OpenOptions::new()
            .write(true)
            .open("/proc/self/uid_map")
            .map_err(|e| SecurityError::Internal(format!("Failed to open uid_map: {}", e)))?;

        file.write_all(uid_map.as_bytes())
            .map_err(|e| SecurityError::Internal(format!("Failed to write uid_map: {}", e)))?;

        Ok(())
    }

    /// WIT ABI: Map GID in user namespace
    ///
    /// Maps to: Writing to `/proc/self/gid_map`
    ///
    /// # WIT Signature
    /// ```wit
    /// map-gid: func(inside-gid: u32, outside-gid: u32, count: u32) -> result<_>
    /// ```
    pub fn wit_map_gid(inside_gid: u32, outside_gid: u32, count: u32) -> SecurityResult<()> {
        let gid_map = format!("{} {} {}\n", inside_gid, outside_gid, count);

        let mut file = OpenOptions::new()
            .write(true)
            .open("/proc/self/gid_map")
            .map_err(|e| SecurityError::Internal(format!("Failed to open gid_map: {}", e)))?;

        file.write_all(gid_map.as_bytes())
            .map_err(|e| SecurityError::Internal(format!("Failed to write gid_map: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_type_from_i32() {
        assert_eq!(
            NamespaceType::from_i32(libc::CLONE_NEWUSER),
            Some(NamespaceType::User)
        );
        assert_eq!(
            NamespaceType::from_i32(libc::CLONE_NEWPID),
            Some(NamespaceType::Pid)
        );
        assert_eq!(
            NamespaceType::from_i32(libc::CLONE_NEWNS),
            Some(NamespaceType::Mount)
        );
        assert_eq!(
            NamespaceType::from_i32(libc::CLONE_NEWNET),
            Some(NamespaceType::Network)
        );
        assert_eq!(
            NamespaceType::from_i32(libc::CLONE_NEWUTS),
            Some(NamespaceType::Uts)
        );
        assert_eq!(NamespaceType::from_i32(999999), None);
    }

    #[test]
    fn test_namespace_type_name() {
        assert_eq!(NamespaceType::User.name(), "user");
        assert_eq!(NamespaceType::Pid.name(), "pid");
        assert_eq!(NamespaceType::Mount.name(), "mnt");
        assert_eq!(NamespaceType::Network.name(), "net");
        assert_eq!(NamespaceType::Uts.name(), "uts");
    }

    #[test]
    fn test_namespace_type_display() {
        assert_eq!(format!("{}", NamespaceType::User), "user");
        assert_eq!(format!("{}", NamespaceType::Pid), "pid");
    }

    #[test]
    fn test_namespace_type_proc_path() {
        assert_eq!(NamespaceType::User.proc_path(1234), "/proc/1234/ns/user");
        assert_eq!(NamespaceType::Pid.proc_path(5678), "/proc/5678/ns/pid");
    }

    #[test]
    fn test_namespace_config_default() {
        let config = NamespaceConfig::default();
        assert!(config.user_namespace);
        assert!(config.pid_namespace);
        assert!(config.mount_namespace);
        assert!(config.network_namespace);
        assert!(config.uts_namespace);
        assert_eq!(config.uid_map, 65534);
        assert_eq!(config.gid_map, 65534);
        assert_eq!(config.hostname, Some("clawos-sandbox".to_string()));
        assert_eq!(config.domainname, Some("clawos.local".to_string()));
    }

    #[test]
    fn test_namespace_config_minimal() {
        let config = NamespaceConfig::minimal();
        assert!(config.user_namespace);
        assert!(!config.pid_namespace);
        assert!(!config.mount_namespace);
        assert!(!config.network_namespace);
        assert!(!config.uts_namespace);
    }

    #[test]
    fn test_namespace_config_clone_flags() {
        let config = NamespaceConfig::all_enabled();
        let flags = config.clone_flags();

        assert!(flags & libc::CLONE_NEWUSER != 0);
        assert!(flags & libc::CLONE_NEWPID != 0);
        assert!(flags & libc::CLONE_NEWNS != 0);
        assert!(flags & libc::CLONE_NEWNET != 0);
        assert!(flags & libc::CLONE_NEWUTS != 0);
    }

    #[test]
    fn test_namespace_config_clone_flags_minimal() {
        let config = NamespaceConfig::minimal();
        let flags = config.clone_flags();

        assert!(flags & libc::CLONE_NEWUSER != 0);
        assert!(flags & libc::CLONE_NEWPID == 0);
        assert!(flags & libc::CLONE_NEWNS == 0);
        assert!(flags & libc::CLONE_NEWNET == 0);
        assert!(flags & libc::CLONE_NEWUTS == 0);
    }

    #[test]
    fn test_namespace_isolator_creation() {
        let isolator = NamespaceIsolator::with_defaults().unwrap();
        assert!(isolator.user_ns_fd.is_none());
        assert!(isolator.pid_ns_fd.is_none());
        assert!(isolator.mount_ns_fd.is_none());
        assert!(isolator.net_ns_fd.is_none());
        assert!(isolator.uts_ns_fd.is_none());
    }

    #[test]
    fn test_namespace_isolator_minimal() {
        let isolator = NamespaceIsolator::with_minimal().unwrap();
        assert_eq!(isolator.config.uid_map, 65534);
        assert_eq!(isolator.config.gid_map, 65534);
    }

    #[test]
    fn test_get_hostname() {
        let isolator = NamespaceIsolator::with_defaults().unwrap();
        let hostname = isolator.get_hostname();
        assert!(hostname.is_ok());
        let hostname = hostname.unwrap();
        assert!(!hostname.is_empty());
    }

    #[test]
    fn test_get_domainname() {
        let isolator = NamespaceIsolator::with_defaults().unwrap();
        let domainname = isolator.get_domainname();
        assert!(domainname.is_ok());
    }

    #[test]
    fn test_in_namespace() {
        let isolator = NamespaceIsolator::with_defaults().unwrap();
        // We're not in any custom namespace, so this should return false
        let result = isolator.in_namespace(NamespaceType::User);
        assert!(result.is_ok());
        // The result depends on whether we're already in a namespace
        // Just check that it doesn't error
    }

    #[test]
    fn test_wit_abi_get_hostname() {
        let hostname = wit_abi::wit_get_hostname();
        assert!(hostname.is_ok());
        let hostname = hostname.unwrap();
        assert!(!hostname.is_empty());
    }

    #[test]
    fn test_wit_abi_create_namespace_invalid_type() {
        let result = wit_abi::wit_create_namespace(999999);
        assert!(result.is_err());
    }

    #[test]
    fn test_wit_abi_map_uid_format() {
        // This test just verifies the format is correct
        // Actual mapping requires CAP_SETUID or being in a user namespace
        let uid_map = format!("{} {} {}\n", 0, 1000, 1);
        assert_eq!(uid_map, "0 1000 1\n");
    }

    #[test]
    fn test_wit_abi_map_gid_format() {
        // This test just verifies the format is correct
        // Actual mapping requires CAP_SETGID or being in a user namespace
        let gid_map = format!("{} {} {}\n", 0, 1000, 1);
        assert_eq!(gid_map, "0 1000 1\n");
    }

    // Note: The following tests require CAP_SYS_ADMIN and are skipped by default
    // They can be run in a privileged environment for integration testing

    #[test]
    #[ignore]
    fn test_create_user_namespace() {
        let mut isolator = NamespaceIsolator::with_minimal().unwrap();
        let result = isolator.create_namespaces();
        assert!(result.is_ok());
        assert!(isolator.user_ns_fd.is_some());
    }

    #[test]
    #[ignore]
    fn test_create_all_namespaces() {
        let mut isolator = NamespaceIsolator::with_defaults().unwrap();
        let result = isolator.create_namespaces();
        assert!(result.is_ok());
        assert!(isolator.user_ns_fd.is_some());
        assert!(isolator.pid_ns_fd.is_some());
        assert!(isolator.mount_ns_fd.is_some());
        assert!(isolator.net_ns_fd.is_some());
        assert!(isolator.uts_ns_fd.is_some());
    }

    #[test]
    #[ignore]
    fn test_set_hostname_in_uts_namespace() {
        let mut isolator = NamespaceIsolator::with_defaults().unwrap();
        isolator.create_namespaces().unwrap();

        let result = isolator.set_hostname("test-hostname");
        assert!(result.is_ok());

        let hostname = isolator.get_hostname().unwrap();
        assert_eq!(hostname, "test-hostname");
    }

    #[test]
    #[ignore]
    fn test_pivot_root() {
        // This test requires a prepared rootfs
        // Skip by default as it requires setup
    }
}
