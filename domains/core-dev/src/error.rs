// ClawOS Core Development Library Error Types

use thiserror::Error;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PROTOCOL_VERSION: &str = "1.0";

/// Result type alias
pub type Result<T> = std::result::Result<T, Error>;

/// ClawOS Core Development Library errors
#[derive(Debug, Error)]
pub enum Error {
    #[error("IPC error: {0}")]
    Ipc(#[from] IpcError),

    #[error("Security error: {0}")]
    Security(String),

    #[error("ClawFS error: {0}")]
    ClawFS(String),

    #[error("Public API error: {0}")]
    PublicApi(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Service error: {0}")]
    Service(String),
}

/// IPC-specific errors
#[derive(Debug, Error)]
pub enum IpcError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Message error: {0}")]
    Message(String),

    #[error("Timeout error")]
    Timeout,

    #[error("Protocol error: {0}")]
    Protocol(String),
}

impl From<IpcError> for Error {
    fn from(err: IpcError) -> Self {
        Error::Ipc(err)
    }
}
