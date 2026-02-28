use crate::error::{BridgeError, BridgeResult, ErrorCode};
use std::fs::File;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::fs::{PermissionsExt, MetadataExt};
use std::path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, warn};

#[derive(Debug, Clone)]
pub struct FileStat {
    pub size: u64,
    pub mode: u32,
    pub mtime: u64,
    pub atime: u64,
    pub ctime: u64,
    pub ino: u64,
    pub dev: u64,
    pub nlink: u64,
    pub uid: u32,
    pub gid: u32,
    pub blksize: u64,
    pub blocks: u64,
}

#[derive(Debug)]
pub struct FileDescriptor {
    file: Arc<Mutex<File>>,
    path: String,
    closed: Arc<Mutex<bool>>,
}

impl FileDescriptor {
    pub fn new(file: File, path: String) -> Self {
        FileDescriptor {
            file: Arc::new(Mutex::new(file)),
            path,
            closed: Arc::new(Mutex::new(false)),
        }
    }

    pub async fn read(&self, buffer: &mut [u8], max_bytes: u32) -> BridgeResult<u32> {
        let mut closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "File descriptor closed"));
        }
        drop(closed);

        let mut file = self.file.lock().await;
        use std::io::Read;
        let to_read = std::cmp::min(buffer.len() as u32, max_bytes) as usize;
        let bytes_read = file.read(&mut buffer[..to_read])
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;
        Ok(bytes_read as u32)
    }

    pub async fn write(&self, data: &[u8]) -> BridgeResult<u32> {
        let mut closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "File descriptor closed"));
        }
        drop(closed);

        let mut file = self.file.lock().await;
        use std::io::Write;
        let bytes_written = file.write(data)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;
        Ok(bytes_written as u32)
    }

    pub async fn seek(&self, offset: i64, whence: u8) -> BridgeResult<u64> {
        let mut closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "File descriptor closed"));
        }
        drop(closed);

        let mut file = self.file.lock().await;
        use std::io::Seek;
        use std::io::SeekFrom;

        let seek_from = match whence {
            0 => SeekFrom::Start(offset as u64),
            1 => SeekFrom::Current(offset),
            2 => SeekFrom::End(offset),
            _ => return Err(BridgeError::with_code(ErrorCode::EINVAL, "Invalid whence value")),
        };

        let pos = file.seek(seek_from)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;
        Ok(pos)
    }

    pub async fn stat(&self) -> BridgeResult<FileStat> {
        let mut closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "File descriptor closed"));
        }
        drop(closed);

        let file = self.file.lock().await;
        let metadata = file.metadata()
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

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

    pub async fn sync(&self) -> BridgeResult<()> {
        let mut closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "File descriptor closed"));
        }
        drop(closed);

        let file = self.file.lock().await;
        file.sync_all()
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;
        Ok(())
    }

    pub async fn close(&self) -> BridgeResult<()> {
        let mut closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "File descriptor already closed"));
        }
        *closed = true;
        debug!("File descriptor closed: {}", self.path);
        Ok(())
    }

    pub fn raw_fd(&self) -> RawFd {
        self.file.try_lock()
            .map(|f| f.as_raw_fd())
            .unwrap_or(-1)
    }
}

#[derive(Debug)]
pub struct DirectoryEntry {
    path: String,
    entries: Arc<Mutex<Vec<std::fs::DirEntry>>>,
    index: Arc<Mutex<usize>>,
    closed: Arc<Mutex<bool>>,
}

impl DirectoryEntry {
    pub fn new(path: String) -> BridgeResult<Self> {
        let entries = std::fs::read_dir(&path)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

        Ok(DirectoryEntry {
            path,
            entries: Arc::new(Mutex::new(entries)),
            index: Arc::new(Mutex::new(0)),
            closed: Arc::new(Mutex::new(false)),
        })
    }

    pub async fn read(&self) -> BridgeResult<String> {
        let mut closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "Directory entry closed"));
        }
        drop(closed);

        let mut entries = self.entries.lock().await;
        let mut index = self.index.lock().await;

        if *index >= entries.len() {
            return Ok(String::new());
        }

        let entry = entries[*index].file_name();
        *index += 1;

        Ok(entry.to_string_lossy().to_string())
    }

    pub async fn close(&self) -> BridgeResult<()> {
        let mut closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "Directory entry already closed"));
        }
        *closed = true;
        debug!("Directory entry closed: {}", self.path);
        Ok(())
    }
}

#[derive(Debug)]
pub struct MemoryRegion {
    data: Arc<Mutex<Vec<u8>>>,
    name: String,
    size: u32,
    closed: Arc<Mutex<bool>>,
}

impl MemoryRegion {
    pub fn new(size: u32, name: String) -> BridgeResult<Self> {
        if size == 0 {
            return Err(BridgeError::with_code(ErrorCode::EINVAL, "Memory region size cannot be zero"));
        }
        if size > 1024 * 1024 * 1024 {
            return Err(BridgeError::with_code(ErrorCode::QuotaExceeded, "Memory region size exceeds 1GB limit"));
        }

        Ok(MemoryRegion {
            data: Arc::new(Mutex::new(vec![0u8; size as usize])),
            name,
            size,
            closed: Arc::new(Mutex::new(false)),
        })
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    pub async fn read(&self, offset: u32, buffer: &mut [u8], length: u32) -> BridgeResult<()> {
        let mut closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "Memory region closed"));
        }
        drop(closed);

        let data = self.data.lock().await;
        let offset = offset as usize;
        let length = length as usize;

        if offset + length > self.size as usize {
            return Err(BridgeError::with_code(ErrorCode::EINVAL, "Read exceeds memory region bounds"));
        }

        buffer[..length].copy_from_slice(&data[offset..offset + length]);
        Ok(())
    }

    pub async fn write(&self, offset: u32, data: &[u8]) -> BridgeResult<()> {
        let mut closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "Memory region closed"));
        }
        drop(closed);

        let mut mem_data = self.data.lock().await;
        let offset = offset as usize;
        let length = data.len();

        if offset + length > self.size as usize {
            return Err(BridgeError::with_code(ErrorCode::EINVAL, "Write exceeds memory region bounds"));
        }

        mem_data[offset..offset + length].copy_from_slice(data);
        Ok(())
    }

    pub async fn sync(&self) -> BridgeResult<()> {
        let closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "Memory region closed"));
        }
        Ok(())
    }

    pub async fn close(&self) -> BridgeResult<()> {
        let mut closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "Memory region already closed"));
        }
        *closed = true;
        debug!("Memory region closed: {}", self.name);
        Ok(())
    }
}

#[derive(Debug)]
pub struct Socket {
    fd: Arc<Mutex<Option<std::net::TcpStream>>>,
    closed: Arc<Mutex<bool>>,
}

impl Socket {
    pub fn new() -> Self {
        Socket {
            fd: Arc::new(Mutex::new(None)),
            closed: Arc::new(Mutex::new(false)),
        }
    }

    pub async fn connect(&self, host: &str, port: u16) -> BridgeResult<()> {
        let mut closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "Socket closed"));
        }
        drop(closed);

        let address = format!("{}:{}", host, port);
        let stream = std::net::TcpStream::connect(&address)
            .map_err(|e| {
                let code = match e.kind() {
                    std::io::ErrorKind::ConnectionRefused => ErrorCode::ECONNREFUSED,
                    std::io::ErrorKind::TimedOut => ErrorCode::ETIMEDOUT,
                    std::io::ErrorKind::NotFound => ErrorCode::ENETUNREACH,
                    _ => ErrorCode::EIO,
                };
                BridgeError::with_code(code, e.to_string())
            })?;

        stream.set_nonblocking(true)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

        let mut fd = self.fd.lock().await;
        *fd = Some(stream);
        debug!("Socket connected to {}:{}", host, port);
        Ok(())
    }

    pub async fn send(&self, data: &[u8]) -> BridgeResult<u32> {
        let mut closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "Socket closed"));
        }
        drop(closed);

        let mut fd = self.fd.lock().await;
        let stream = fd.as_mut()
            .ok_or_else(|| BridgeError::with_code(ErrorCode::ENOTCONN, "Socket not connected"))?;

        use std::io::Write;
        let bytes_written = stream.write(data)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;
        Ok(bytes_written as u32)
    }

    pub async fn recv(&self, buffer: &mut [u8], max_bytes: u32) -> BridgeResult<u32> {
        let mut closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "Socket closed"));
        }
        drop(closed);

        let mut fd = self.fd.lock().await;
        let stream = fd.as_mut()
            .ok_or_else(|| BridgeError::with_code(ErrorCode::ENOTCONN, "Socket not connected"))?;

        use std::io::Read;
        let to_read = std::cmp::min(buffer.len() as u32, max_bytes) as usize;
        match stream.read(&mut buffer[..to_read]) {
            Ok(0) => Ok(0),
            Ok(n) => Ok(n as u32),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                Err(BridgeError::with_code(ErrorCode::EAgain, "Operation would block"))
            }
            Err(e) => Err(BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string())),
        }
    }

    pub async fn close(&self) -> BridgeResult<()> {
        let mut closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "Socket already closed"));
        }
        *closed = true;

        let mut fd = self.fd.lock().await;
        *fd = None;
        debug!("Socket closed");
        Ok(())
    }
}

#[derive(Debug)]
pub struct Cgroup {
    path: String,
    closed: Arc<Mutex<bool>>,
}

impl Cgroup {
    pub fn new(path: String) -> Self {
        Cgroup {
            path,
            closed: Arc::new(Mutex::new(false)),
        }
    }

    pub async fn set_memory_limit(&self, limit_bytes: u64) -> BridgeResult<()> {
        let closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "Cgroup closed"));
        }
        drop(closed);

        let memory_max_path = format!("{}/memory.max", self.path);
        let limit_str = if limit_bytes == 0 { "max".to_string() } else { limit_bytes.to_string() };

        std::fs::write(&memory_max_path, limit_str)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

        debug!("Cgroup memory limit set to {} bytes", limit_bytes);
        Ok(())
    }

    pub async fn set_cpu_limit(&self, cpu_max: u64, period_us: u64) -> BridgeResult<()> {
        let closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "Cgroup closed"));
        }
        drop(closed);

        let cpu_max_path = format!("{}/cpu.max", self.path);
        let cpu_max_str = format!("{} {}", cpu_max, period_us);

        std::fs::write(&cpu_max_path, cpu_max_str)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

        debug!("Cgroup CPU limit set to {} / {} us", cpu_max, period_us);
        Ok(())
    }

    pub async fn set_pid_limit(&self, max_pids: u64) -> BridgeResult<()> {
        let closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "Cgroup closed"));
        }
        drop(closed);

        let pids_max_path = format!("{}/pids.max", self.path);
        let pids_max_str = if max_pids == 0 { "max".to_string() } else { max_pids.to_string() };

        std::fs::write(&pids_max_path, pids_max_str)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

        debug!("Cgroup PID limit set to {}", max_pids);
        Ok(())
    }

    pub async fn get_memory_usage(&self) -> BridgeResult<u64> {
        let closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "Cgroup closed"));
        }
        drop(closed);

        let memory_current_path = format!("{}/memory.current", self.path);
        let usage = std::fs::read_to_string(&memory_current_path)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

        usage.trim().parse::<u64>()
            .map_err(|_| BridgeError::with_code(ErrorCode::EIO, "Failed to parse memory usage"))
    }

    pub async fn get_cpu_usage(&self) -> BridgeResult<u64> {
        let closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "Cgroup closed"));
        }
        drop(closed);

        let cpu_stat_path = format!("{}/cpu.stat", self.path);
        let stat = std::fs::read_to_string(&cpu_stat_path)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

        for line in stat.lines() {
            if line.starts_with("usage_usec ") {
                let usage_usec = line.split_whitespace().nth(1)
                    .ok_or_else(|| BridgeError::with_code(ErrorCode::EIO, "Failed to parse CPU usage"))?;
                return Ok(usage_usec.parse::<u64>()
                    .map_err(|_| BridgeError::with_code(ErrorCode::EIO, "Failed to parse CPU usage"))? * 1000);
            }
        }

        Err(BridgeError::with_code(ErrorCode::EIO, "CPU usage not found in cgroup stat"))
    }

    pub async fn get_pid_count(&self) -> BridgeResult<u64> {
        let closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "Cgroup closed"));
        }
        drop(closed);

        let pids_current_path = format!("{}/pids.current", self.path);
        let count = std::fs::read_to_string(&pids_current_path)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

        count.trim().parse::<u64>()
            .map_err(|_| BridgeError::with_code(ErrorCode::EIO, "Failed to parse PID count"))
    }

    pub async fn close(&self) -> BridgeResult<()> {
        let mut closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "Cgroup already closed"));
        }
        *closed = true;
        debug!("Cgroup closed: {}", self.path);
        Ok(())
    }
}

#[derive(Debug)]
pub struct DeviceInfo {
    pub major: u32,
    pub minor: u32,
    pub device_type: u32,
}

#[derive(Debug)]
pub struct Device {
    path: String,
    file: Arc<Mutex<Option<File>>>,
    closed: Arc<Mutex<bool>>,
}

impl Device {
    pub fn new(path: String) -> Self {
        Device {
            path,
            file: Arc::new(Mutex::new(None)),
            closed: Arc::new(Mutex::new(false)),
        }
    }

    pub async fn open(&self, flags: u32) -> BridgeResult<()> {
        let mut closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "Device closed"));
        }
        drop(closed);

        let _open_flags = match flags {
            0 => libc::O_RDONLY,
            1 => libc::O_WRONLY,
            2 => libc::O_RDWR,
            _ => return Err(BridgeError::with_code(ErrorCode::EINVAL, "Invalid open flags")),
        };

        let file = std::fs::File::open(&self.path)
                .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

        let mut fd = self.file.lock().await;
        *fd = Some(file);
        debug!("Device opened: {}", self.path);
        Ok(())
    }

    pub async fn read(&self, buffer: &mut [u8], offset: u64, length: u32) -> BridgeResult<()> {
        let mut closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "Device closed"));
        }
        drop(closed);

        let mut file = self.file.lock().await;
        let file = file.as_mut()
            .ok_or_else(|| BridgeError::with_code(ErrorCode::EBADF, "Device not opened"))?;

        use std::io::{Read, Seek, SeekFrom};
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

        let to_read = std::cmp::min(buffer.len() as u32, length) as usize;
        file.read_exact(&mut buffer[..to_read])
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

        Ok(())
    }

    pub async fn write(&self, data: &[u8], offset: u64) -> BridgeResult<()> {
        let mut closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "Device closed"));
        }
        drop(closed);

        let mut file = self.file.lock().await;
        let file = file.as_mut()
            .ok_or_else(|| BridgeError::with_code(ErrorCode::EBADF, "Device not opened"))?;

        use std::io::{Seek, SeekFrom, Write};
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

        file.write_all(data)
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

        Ok(())
    }

    pub async fn sync(&self) -> BridgeResult<()> {
        let closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "Device closed"));
        }
        drop(closed);

        let mut file = self.file.lock().await;
        let file = file.as_mut()
            .ok_or_else(|| BridgeError::with_code(ErrorCode::EBADF, "Device not opened"))?;

        file.sync_all()
            .map_err(|e| BridgeError::with_code(ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)), e.to_string()))?;

        Ok(())
    }

    pub async fn close(&self) -> BridgeResult<()> {
        let mut closed = self.closed.lock().await;
        if *closed {
            return Err(BridgeError::with_code(ErrorCode::ResourceClosed, "Device already closed"));
        }
        *closed = true;

        let mut file = self.file.lock().await;
        *file = None;
        debug!("Device closed: {}", self.path);
        Ok(())
    }
}
