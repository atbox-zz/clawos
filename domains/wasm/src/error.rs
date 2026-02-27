use thiserror::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    Success = 0,
    EAgain = 1,
    EIO = 2,
    ENOENT = 3,
    EPERM = 4,
    EProto = 5,
    ETimeout = 6,
    EInternal = 7,
    EPanic = 8,
    ENOMEM = 12,
    EACCES = 13,
    EEXIST = 17,
    EBUSY = 16,
    ENOTDIR = 20,
    EISDIR = 21,
    EINVAL = 22,
    ENFILE = 23,
    EMFILE = 24,
    ENOSPC = 28,
    EROFS = 30,
    ENOTEMPTY = 39,
    EBADF = 9,
    ECONNREFUSED = 111,
    ETIMEDOUT = 110,
    ENETUNREACH = 101,
    ENOTCONN = 107,
    EMSGSIZE = 90,
    EADDRINUSE = 98,
    EADDRNOTAVAIL = 99,
    WasmAllocFailed = 100,
    WasmStackOverflow = 113,
    WasmTrap = 102,
    WasmInvalidModule = 103,
    WasmFunctionNotFound = 104,
    WasmResourceLimit = 105,
    InvalidHandle = 200,
    ResourceClosed = 201,
    SecurityDenied = 202,
    QuotaExceeded = 203,
    NotSupported = 204,
    InvalidConfig = 205,
    Timeout = 207,
    Canceled = 208,
    TooManyPending = 209,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl ErrorCode {
    pub fn from_errno(errno: i32) -> Self {
        match errno {
            0 => ErrorCode::Success,
            libc::EAGAIN => ErrorCode::EAgain,
            libc::EWOULDBLOCK => ErrorCode::EAgain,
            libc::EIO => ErrorCode::EIO,
            libc::ENOENT => ErrorCode::ENOENT,
            libc::EPERM => ErrorCode::EPERM,
            libc::ENOMEM => ErrorCode::ENOMEM,
            libc::EACCES => ErrorCode::EACCES,
            libc::EEXIST => ErrorCode::EEXIST,
            libc::EBUSY => ErrorCode::EBUSY,
            libc::ENOTDIR => ErrorCode::ENOTDIR,
            libc::EISDIR => ErrorCode::EISDIR,
            libc::EINVAL => ErrorCode::EINVAL,
            libc::ENFILE => ErrorCode::ENFILE,
            libc::EMFILE => ErrorCode::EMFILE,
            libc::ENOSPC => ErrorCode::ENOSPC,
            libc::EROFS => ErrorCode::EROFS,
            libc::ENOTEMPTY => ErrorCode::ENOTEMPTY,
            libc::ECONNREFUSED => ErrorCode::ECONNREFUSED,
            libc::ETIMEDOUT => ErrorCode::ETIMEDOUT,
            libc::ENETUNREACH => ErrorCode::ENETUNREACH,
            libc::ENOTCONN => ErrorCode::ENOTCONN,
            libc::EMSGSIZE => ErrorCode::EMSGSIZE,
            libc::EADDRINUSE => ErrorCode::EADDRINUSE,
            libc::EADDRNOTAVAIL => ErrorCode::EADDRNOTAVAIL,
            _ => ErrorCode::EInternal,
        }
    }

    pub fn as_errno(&self) -> i32 {
        match self {
            ErrorCode::Success => 0,
            ErrorCode::EAgain => libc::EAGAIN,
            ErrorCode::EIO => libc::EIO,
            ErrorCode::ENOENT => libc::ENOENT,
            ErrorCode::EPERM => libc::EPERM,
            ErrorCode::EProto => libc::EPROTO,
            ErrorCode::ETimeout => libc::ETIMEDOUT,
            ErrorCode::EInternal => libc::EIO,
            ErrorCode::EPanic => libc::EIO,
            ErrorCode::ENOMEM => libc::ENOMEM,
            ErrorCode::EACCES => libc::EACCES,
            ErrorCode::EEXIST => libc::EEXIST,
            ErrorCode::EBUSY => libc::EBUSY,
            ErrorCode::ENOTDIR => libc::ENOTDIR,
            ErrorCode::EISDIR => libc::EISDIR,
            ErrorCode::EINVAL => libc::EINVAL,
            ErrorCode::ENFILE => libc::ENFILE,
            ErrorCode::EMFILE => libc::EMFILE,
            ErrorCode::ENOSPC => libc::ENOSPC,
            ErrorCode::EROFS => libc::EROFS,
            ErrorCode::ENOTEMPTY => libc::ENOTEMPTY,
            ErrorCode::ECONNREFUSED => libc::ECONNREFUSED,
            ErrorCode::ETIMEDOUT => libc::ETIMEDOUT,
            ErrorCode::ENETUNREACH => libc::ENETUNREACH,
            ErrorCode::ENOTCONN => libc::ENOTCONN,
            ErrorCode::EMSGSIZE => libc::EMSGSIZE,
            ErrorCode::EADDRINUSE => libc::EADDRINUSE,
            ErrorCode::EADDRNOTAVAIL => libc::EADDRNOTAVAIL,
            ErrorCode::WasmAllocFailed => libc::ENOMEM,
            ErrorCode::WasmStackOverflow => libc::ENOMEM,
            ErrorCode::WasmTrap => libc::EFAULT,
            ErrorCode::WasmInvalidModule => libc::ENOEXEC,
            ErrorCode::WasmFunctionNotFound => libc::ENOENT,
            ErrorCode::WasmResourceLimit => libc::EDQUOT,
            ErrorCode::InvalidHandle => libc::EBADF,
            ErrorCode::ResourceClosed => libc::EBADF,
            ErrorCode::SecurityDenied => libc::EPERM,
            ErrorCode::QuotaExceeded => libc::EDQUOT,
            ErrorCode::NotSupported => libc::ENOSYS,
            ErrorCode::InvalidConfig => libc::EINVAL,
            ErrorCode::Timeout => libc::ETIMEDOUT,
            ErrorCode::Canceled => libc::ECANCELED,
            ErrorCode::TooManyPending => libc::EAGAIN,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ErrorCode::Success => "SUCCESS",
            ErrorCode::EAgain => "EAGAIN",
            ErrorCode::EIO => "EIO",
            ErrorCode::ENOENT => "ENOENT",
            ErrorCode::EPERM => "EPERM",
            ErrorCode::EProto => "EPROTO",
            ErrorCode::ETimeout => "ETIMEOUT",
            ErrorCode::EInternal => "EINTERNAL",
            ErrorCode::EPanic => "EPANIC",
            ErrorCode::ENOMEM => "ENOMEM",
            ErrorCode::EACCES => "EACCES",
            ErrorCode::EEXIST => "EEXIST",
            ErrorCode::EBUSY => "EBUSY",
            ErrorCode::ENOTDIR => "ENOTDIR",
            ErrorCode::EISDIR => "EISDIR",
            ErrorCode::EINVAL => "EINVAL",
            ErrorCode::ENFILE => "ENFILE",
            ErrorCode::EMFILE => "EMFILE",
            ErrorCode::ENOSPC => "ENOSPC",
            ErrorCode::EROFS => "EROFS",
            ErrorCode::ENOTEMPTY => "ENOTEMPTY",
            ErrorCode::ECONNREFUSED => "ECONNREFUSED",
            ErrorCode::ETIMEDOUT => "ETIMEDOUT",
            ErrorCode::ENETUNREACH => "ENETUNREACH",
            ErrorCode::ENOTCONN => "ENOTCONN",
            ErrorCode::EMSGSIZE => "EMSGSIZE",
            ErrorCode::EADDRINUSE => "EADDRINUSE",
            ErrorCode::EADDRNOTAVAIL => "EADDRNOTAVAIL",
            ErrorCode::WasmAllocFailed => "WASM_ALLOC_FAILED",
            ErrorCode::WasmStackOverflow => "WASM_STACK_OVERFLOW",
            ErrorCode::WasmTrap => "WASM_TRAP",
            ErrorCode::WasmInvalidModule => "WASM_INVALID_MODULE",
            ErrorCode::WasmFunctionNotFound => "WASM_FUNCTION_NOT_FOUND",
            ErrorCode::WasmResourceLimit => "WASM_RESOURCE_LIMIT",
            ErrorCode::InvalidHandle => "INVALID_HANDLE",
            ErrorCode::ResourceClosed => "RESOURCE_CLOSED",
            ErrorCode::SecurityDenied => "SECURITY_DENIED",
            ErrorCode::QuotaExceeded => "QUOTA_EXCEEDED",
            ErrorCode::NotSupported => "NOT_SUPPORTED",
            ErrorCode::InvalidConfig => "INVALID_CONFIG",
            ErrorCode::Timeout => "TIMEOUT",
            ErrorCode::Canceled => "CANCELED",
            ErrorCode::TooManyPending => "TOO_MANY_PENDING",
        }
    }
}

#[derive(Error, Debug)]
pub enum BridgeError {
    #[error("Engine initialization failed: {0}")]
    EngineInit(String),

    #[error("Module loading failed: {0}")]
    ModuleLoad(String),

    #[error("Instantiation failed: {0}")]
    Instantiation(String),

    #[error("Function call failed: {0}")]
    FunctionCall(String),

    #[error("Resource error: {0}")]
    Resource(String),

    #[error("Security error: {0}")]
    Security(String),

    #[error("Cgroup error: {0}")]
    Cgroup(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("WASM trap: {0}")]
    WasmTrap(String),

    #[error("Error code {code:?}: {message}")]
    ErrorCode { code: ErrorCode, message: String },
}

impl BridgeError {
    pub fn with_code(code: ErrorCode, message: impl Into<String>) -> Self {
        BridgeError::ErrorCode {
            code,
            message: message.into(),
        }
    }

    pub fn error_code(&self) -> ErrorCode {
        match self {
            BridgeError::EngineInit(_) => ErrorCode::EInternal,
            BridgeError::ModuleLoad(_) => ErrorCode::WasmInvalidModule,
            BridgeError::Instantiation(_) => ErrorCode::WasmInvalidModule,
            BridgeError::FunctionCall(_) => ErrorCode::WasmTrap,
            BridgeError::Resource(_) => ErrorCode::InvalidHandle,
            BridgeError::Security(_) => ErrorCode::SecurityDenied,
            BridgeError::Cgroup(_) => ErrorCode::QuotaExceeded,
            BridgeError::Io(e) => ErrorCode::from_errno(e.raw_os_error().unwrap_or(libc::EIO)),
            BridgeError::WasmTrap(_) => ErrorCode::WasmTrap,
            BridgeError::ErrorCode { code, .. } => *code,
        }
    }
}

pub type BridgeResult<T> = Result<T, BridgeError>;
