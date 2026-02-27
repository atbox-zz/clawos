// crates/clawos-agent/src/router/mod.rs
//
// Router: classifies incoming messages into Intent variants,
// then hands off to the Scheduler for job execution.
// Ported from IronClaw src/router/ — PostgreSQL references removed.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

// ── Intent Classification ─────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Intent {
    /// Run a named tool with JSON arguments
    ToolCall { tool: String, args: serde_json::Value },
    /// Natural language query → LLM + memory search
    Query    { text: String },
    /// Background task (cron, event, webhook)
    Routine  { routine_id: String, trigger: Trigger },
    /// Administrative: inspect state, cancel jobs, etc.
    Admin    { command: AdminCommand },
    /// Unknown / needs clarification
    Ambiguous { raw: String, candidates: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Trigger {
    Cron    { schedule: String },
    Event   { event_type: String },
    Webhook { path: String },
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AdminCommand {
    ListJobs,
    CancelJob { job_id: String },
    ShowMemory { query: Option<String> },
    AgentStatus,
    GateCheck  { phase: String },
}

// ── Router ────────────────────────────────────────────────────

pub struct Router {
    /// Registered tool names (from ClawFS tool registry)
    known_tools: Vec<String>,
}

impl Router {
    pub fn new(known_tools: Vec<String>) -> Self {
        Self { known_tools }
    }

    /// Classify a raw message string into an Intent.
    /// Order: exact tool match → slash command → admin → fallback to Query
    pub fn classify(&self, raw: &str) -> Intent {
        let trimmed = raw.trim();
        debug!(raw = trimmed, "Router classifying message");

        // ── Slash commands ───────────────────────────────────
        if let Some(intent) = self.try_slash_command(trimmed) {
            return intent;
        }

        // ── JSON tool call ───────────────────────────────────
        if let Some(intent) = self.try_json_tool_call(trimmed) {
            return intent;
        }

        // ── Natural language keyword heuristics ──────────────
        if let Some(intent) = self.try_keyword_match(trimmed) {
            return intent;
        }

        // ── Fallback: LLM query ──────────────────────────────
        Intent::Query { text: trimmed.to_string() }
    }

    fn try_slash_command(&self, s: &str) -> Option<Intent> {
        if !s.starts_with('/') { return None; }

        let parts: Vec<&str> = s.splitn(3, ' ').collect();
        match parts[0] {
            "/jobs"   => Some(Intent::Admin { command: AdminCommand::ListJobs }),
            "/cancel" => parts.get(1).map(|id| Intent::Admin {
                command: AdminCommand::CancelJob { job_id: id.to_string() }
            }),
            "/memory" => Some(Intent::Admin {
                command: AdminCommand::ShowMemory { query: parts.get(1).map(|s| s.to_string()) }
            }),
            "/status" => Some(Intent::Admin { command: AdminCommand::AgentStatus }),
            "/gate"   => parts.get(1).map(|phase| Intent::Admin {
                command: AdminCommand::GateCheck { phase: phase.to_string() }
            }),
            other => {
                // /toolname {args}
                let tool_name = other.trim_start_matches('/');
                if self.known_tools.iter().any(|t| t == tool_name) {
                    let args_str = parts.get(1).copied().unwrap_or("{}");
                    let args = serde_json::from_str(args_str)
                        .unwrap_or(serde_json::Value::String(args_str.to_string()));
                    Some(Intent::ToolCall { tool: tool_name.to_string(), args })
                } else {
                    None
                }
            }
        }
    }

    fn try_json_tool_call(&self, s: &str) -> Option<Intent> {
        // Detect: { "tool": "name", "args": {...} }
        if !s.starts_with('{') { return None; }
        let v: serde_json::Value = serde_json::from_str(s).ok()?;
        let tool = v.get("tool")?.as_str()?.to_string();
        let args = v.get("args").cloned().unwrap_or(serde_json::Value::Null);
        Some(Intent::ToolCall { tool, args })
    }

    fn try_keyword_match(&self, s: &str) -> Option<Intent> {
        let lower = s.to_lowercase();

        // Check if any known tool name appears prominently
        for tool in &self.known_tools {
            if lower.contains(tool.as_str()) {
                warn!(tool = tool, "Fuzzy tool match — may need confirmation");
                // Don't auto-dispatch fuzzy matches; let LLM decide
                return None;
            }
        }
        None
    }
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn router() -> Router {
        Router::new(vec!["web-search".into(), "file-read".into(), "summarise".into()])
    }

    #[test]
    fn classifies_slash_jobs() {
        let r = router();
        assert_eq!(r.classify("/jobs"), Intent::Admin { command: AdminCommand::ListJobs });
    }

    #[test]
    fn classifies_json_tool_call() {
        let r = router();
        let raw = r#"{"tool":"web-search","args":{"query":"rust eBPF"}}"#;
        let intent = r.classify(raw);
        assert!(matches!(intent, Intent::ToolCall { tool, .. } if tool == "web-search"));
    }

    #[test]
    fn falls_back_to_query() {
        let r = router();
        let intent = r.classify("What is the capital of France?");
        assert!(matches!(intent, Intent::Query { .. }));
    }

    #[test]
    fn classifies_slash_tool() {
        let r = router();
        let intent = r.classify("/web-search {\"query\":\"eBPF\"}");
        assert!(matches!(intent, Intent::ToolCall { tool, .. } if tool == "web-search"));
    }
}
