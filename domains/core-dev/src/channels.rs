// Channel Repackaging for ClawOS (P3.2)
//
// This module implements SSE/WebSocket interface definitions for channels.
// It provides:
// - SSE (Server-Sent Events) interface for unidirectional push
// - WebSocket interface for bidirectional communication
// - Channel configuration for Telegram/Slack/other platforms

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Channel type enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelType {
    Telegram,
    Slack,
    Discord,
    Matrix,
    Email,
    Custom { name: String },
}

/// Channel interface type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceType {
    Sse,
    WebSocket,
    Webhook,
    Polling,
}

/// Channel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelConfig {
    pub channel_type: ChannelType,
    pub interface_type: InterfaceType,
    pub endpoint: String,
    pub credentials: HashMap<String, String>,
    pub preferences: ChannelPreferences,
}

/// Channel transmission preferences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelPreferences {
    pub retry_count: u32,
    pub timeout_secs: u32,
    pub batch_size: u32,
    pub compression: bool,
}

/// SSE event format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SseEvent {
    pub id: String,
    pub event: String,
    pub data: String,
    pub retry: Option<u32>,
}

/// WebSocket message format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsMessage {
    pub message_id: String,
    pub msg_type: String,
    pub payload: String,
    pub correlation_id: Option<String>,
}

/// Channel message direction
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageDirection {
    Inbound,
    Outbound,
    Bidirectional,
}

impl Default for ChannelPreferences {
    fn default() -> Self {
        Self {
            retry_count: 3,
            timeout_secs: 30,
            batch_size: 10,
            compression: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sse_event_serialization() {
        let event = SseEvent {
            id: "123".to_string(),
            event: "message".to_string(),
            data: "Hello, World!".to_string(),
            retry: Some(5000),
        };

        let json = serde_json::to_string(&event);
        assert!(json.is_ok());
    }

    #[test]
    fn test_ws_message_serialization() {
        let msg = WsMessage {
            message_id: "msg-001".to_string(),
            msg_type: "text".to_string(),
            payload: "Test payload".to_string(),
            correlation_id: Some("corr-123".to_string()),
        };

        let json = serde_json::to_string(&msg);
        assert!(json.is_ok());
    }

    #[test]
    fn test_channel_preferences_default() {
        let prefs = ChannelPreferences::default();
        assert_eq!(prefs.retry_count, 3);
        assert_eq!(prefs.timeout_secs, 30);
        assert!(prefs.compression, true);
    }
}
