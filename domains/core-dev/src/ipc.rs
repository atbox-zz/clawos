// IPC Protocol Implementation (P1.7)

use crate::error::{Error, Result, IpcError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use uuid::Uuid;
use chrono::Utc;

/// Message type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    Request,
    Response,
    Event,
    Error,
}

/// Error code enumeration (P1.7)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    Success = 0,
    EAgain = 1,
    EIo = 2,
    ENoent = 3,
    EPerm = 4,
    EProto = 5,
    ETimeout = 6,
    EInternal = 7,
    EPanic = 8,
}

/// IPC message envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub version: String,
    pub timestamp_ns: u64,
    pub sender: String,
    pub recipient: String,
    pub message_id: String,
    pub correlation_id: Option<String>,
    pub message_type: MessageType,
    pub payload: Value,
}

impl Message {
    pub fn new(sender: &str, recipient: &str, message_type: MessageType, payload: Value) -> Self {
        Self {
            version: "1.0".to_string(),
            timestamp_ns: Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64,
            sender: sender.to_string(),
            recipient: recipient.to_string(),
            message_id: Uuid::new_v4().to_string(),
            correlation_id: None,
            message_type,
            payload,
        }
    }

    pub fn with_correlation_id(mut self, correlation_id: String) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }
}

/// IPC client for sending messages
pub struct IpcClient {
    socket_path: String,
}

impl IpcClient {
    pub fn new(socket_path: &str) -> Result<Self> {
        Ok(Self {
            socket_path: socket_path.to_string(),
        })
    }

    pub async fn send(&self, message: &Message) -> Result<Message> {
        let mut stream = UnixStream::connect(&self.socket_path).await
            .map_err(|e| IpcError::Connection(e.to_string()))?;

        let json = serde_json::to_vec(message)?;
        let len = json.len() as u32;

        stream.write_all(&len.to_be_bytes()).await
            .map_err(|e| IpcError::Connection(e.to_string()))?;
        stream.write_all(&json).await
            .map_err(|e| IpcError::Connection(e.to_string()))?;

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await
            .map_err(|e| IpcError::Connection(e.to_string()))?;
        let response_len = u32::from_be_bytes(len_buf) as usize;

        let mut response_buf = vec![0u8; response_len];
        stream.read_exact(&mut response_buf).await
            .map_err(|e| IpcError::Connection(e.to_string()))?;

        let response: Message = serde_json::from_slice(&response_buf)?;
        Ok(response)
    }
}

/// IPC server for receiving messages
pub struct IpcServer {
    socket_path: String,
}

impl IpcServer {
    pub fn new(socket_path: &str) -> Result<Self> {
        Ok(Self {
            socket_path: socket_path.to_string(),
        })
    }

    pub async fn accept(&mut self) -> Result<Message> {
        let listener = tokio::net::UnixListener::bind(&self.socket_path)
            .map_err(|e| IpcError::Connection(e.to_string()))?;

        let (mut stream, _) = listener.accept().await
            .map_err(|e| IpcError::Connection(e.to_string()))?;

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await
            .map_err(|e| IpcError::Connection(e.to_string()))?;
        let message_len = u32::from_be_bytes(len_buf) as usize;

        let mut message_buf = vec![0u8; message_len];
        stream.read_exact(&mut message_buf).await
            .map_err(|e| IpcError::Connection(e.to_string()))?;

        let message: Message = serde_json::from_slice(&message_buf)?;
        Ok(message)
    }
}

impl Clone for IpcServer {
    fn clone(&self) -> Self {
        Self {
            socket_path: self.socket_path.clone(),
        }
    }
}
