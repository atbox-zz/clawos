use std::fmt;
use thiserror::Error;

/// Error codes mapping to P1.7 IPC protocol specification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// Operation completed successfully
    Success = 0,
    /// Operation would block (resource temporarily unavailable)
    EAgain = 1,
    /// I/O error (filesystem, network, or device failure)
    EIO = 2,
    /// Entity not found (file, resource, or component missing)
    ENOENT = 3,
    /// Permission denied (security policy violation)
    EPerm = 4,
    /// Protocol error (invalid message format, version mismatch)
    EProto = 5,
    /// Operation timeout (no response within timeout period)
    ETimeout = 6,
    /// Internal error (unexpected condition, should be logged)
    EInternal = 7,
    /// Unrecoverable error (system state corrupted, trigger rollback)
    EPanic = 8,
}

impl ErrorCode {
    /// Convert from integer to ErrorCode
    pub fn from_i32(code: i32) -> Option<Self> {
        match code {
            0 => Some(ErrorCode::Success),
            1 => Some(ErrorCode::EAgain),
            2 => Some(ErrorCode::EIO),
            3 => Some(ErrorCode::ENOENT),
            4 => Some(ErrorCode::EPerm),
            5 => Some(ErrorCode::EProto),
            6 => Some(ErrorCode::ETimeout),
            7 => Some(ErrorCode::EInternal),
            8 => Some(ErrorCode::EPanic),
            _ => None,
        }
    }

    /// Convert to integer
    pub fn as_i32(self) -> i32 {
        self as i32
    }

    /// Get human-readable description
    pub fn description(self) -> &'static str {
        match self {
            ErrorCode::Success => "Operation completed successfully",
            ErrorCode::EAgain => "Operation would block (resource temporarily unavailable)",
            ErrorCode::EIO => "I/O error (filesystem, network, or device failure)",
            ErrorCode::ENOENT => "Entity not found (file, resource, or component missing)",
            ErrorCode::EPerm => "Permission denied (security policy violation)",
            ErrorCode::EProto => "Protocol error (invalid message format, version mismatch)",
            ErrorCode::ETimeout => "Operation timeout (no response within timeout period)",
            ErrorCode::EInternal => "Internal error (unexpected condition, should be logged)",
            ErrorCode::EPanic => "Unrecoverable error (system state corrupted, trigger rollback)",
        }
    }

    /// Map to seccomp errno if applicable
    pub fn to_seccomp_errno(self) -> Option<u32> {
        match self {
            ErrorCode::Success => None,
            ErrorCode::EAgain => Some(libseccomp::scmp_errno::EAGAIN),
            ErrorCode::EIO => Some(libseccomp::scmp_errno::EIO),
            ErrorCode::ENOENT => Some(libseccomp::scmp_errno::ENOENT),
            ErrorCode::EPerm => Some(libseccomp::scmp_errno::EPERM),
            ErrorCode::EProto => None,
            ErrorCode::ETimeout => None,
            ErrorCode::EInternal => None,
            ErrorCode::EPanic => None,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.as_i32(), self.description())
    }
}

/// Security error type with P1.7 error code mapping
#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Whitelist validation failed: {0}")]
    WhitelistValidation(String),

    #[error("Invalid syscall name: {0}")]
    InvalidSyscall(String),

    #[error("Invalid permission level: {0}")]
    InvalidPermission(String),

    #[error("Invalid condition: {0}")]
    InvalidCondition(String),

    #[error("JSON parsing error: {0}")]
    JsonParse(#[from] serde_json::Error),

    #[error("seccomp filter error: {0}")]
    SeccompFilter(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl SecurityError {
    /// Get the corresponding P1.7 error code
    pub fn error_code(&self) -> ErrorCode {
        match self {
            SecurityError::WhitelistValidation(_) => ErrorCode::EPerm,
            SecurityError::InvalidSyscall(_) => ErrorCode::EPerm,
            SecurityError::InvalidPermission(_) => ErrorCode::EPerm,
            SecurityError::InvalidCondition(_) => ErrorCode::EPerm,
            SecurityError::JsonParse(_) => ErrorCode::EProto,
            SecurityError::SeccompFilter(_) => ErrorCode::EInternal,
            SecurityError::Io(_) => ErrorCode::EIO,
            SecurityError::Internal(_) => ErrorCode::EInternal,
        }
    }
}

/// Result type with SecurityError
pub type SecurityResult<T> = Result<T, SecurityError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_roundtrip() {
        for code in [
            ErrorCode::Success,
            ErrorCode::EAgain,
            ErrorCode::EIO,
            ErrorCode::ENOENT,
            ErrorCode::EPerm,
            ErrorCode::EProto,
            ErrorCode::ETimeout,
            ErrorCode::EInternal,
            ErrorCode::EPanic,
        ] {
            let i32_val = code.as_i32();
            let converted = ErrorCode::from_i32(i32_val);
            assert_eq!(Some(code), converted);
        }
    }

    #[test]
    fn test_error_code_invalid() {
        assert_eq!(None, ErrorCode::from_i32(999));
    }

    #[test]
    fn test_error_code_display() {
        let code = ErrorCode::EPerm;
        let display = format!("{}", code);
        assert!(display.contains("4"));
        assert!(display.contains("Permission denied"));
    }

    #[test]
    fn test_security_error_code_mapping() {
        let err = SecurityError::WhitelistValidation("test".to_string());
        assert_eq!(err.error_code(), ErrorCode::EPerm);

        let err = SecurityError::JsonParse(serde_json::Error::syntax(
            serde_json::error::ErrorCode::ExpectedColon,
            0,
            0,
        ));
        assert_eq!(err.error_code(), ErrorCode::EProto);

        let err = SecurityError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "test",
        ));
        assert_eq!(err.error_code(), ErrorCode::EIO);
    }

    #[test]
    fn test_seccomp_errno_mapping() {
        assert_eq!(Some(libseccomp::scmp_errno::EAGAIN), ErrorCode::EAgain.to_seccomp_errno());
        assert_eq!(Some(libseccomp::scmp_errno::EIO), ErrorCode::EIO.to_seccomp_errno());
        assert_eq!(Some(libseccomp::scmp_errno::ENOENT), ErrorCode::ENOENT.to_seccomp_errno());
        assert_eq!(Some(libseccomp::scmp_errno::EPERM), ErrorCode::EPerm.to_seccomp_errno());
        assert_eq!(None, ErrorCode::Success.to_seccomp_errno());
        assert_eq!(None, ErrorCode::EProto.to_seccomp_errno());
    }
}
