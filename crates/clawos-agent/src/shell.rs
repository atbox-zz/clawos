// crates/clawos-agent/src/shell.rs
//
// clawsh — ClawOS AI Shell (Layer 7)
// A readline-style REPL that forwards input to the agent loop
// and streams responses. Supports:
//   - Natural language → agent dispatch
//   - Slash commands (/tools, /status, /gate P2→P3, /memory)
//   - Structured output (JSON, table, markdown)
//   - Voice mode toggle (/voice on|off)

use crate::agent::{AgentMessage, AgentReply};
use anyhow::Result;
use std::io::{self, BufRead, Write};
use tokio::sync::{mpsc, oneshot};
//use tracing::{debug, info};

const PROMPT: &str = "clawsh ▶ ";
const VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct Shell {
    agent_tx: mpsc::Sender<AgentMessage>,
    session_id: String,
    voice: bool,
}

impl Shell {
    pub fn new(agent_tx: mpsc::Sender<AgentMessage>) -> Self {
        Self {
            agent_tx,
            session_id: uuid::Uuid::new_v4().to_string(),
            voice: false,
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        println!("╔══════════════════════════════════════════╗");
        println!("║  clawsh v{VERSION:<32}║");
        println!("║  ClawAgent AI Shell — Layer 7            ║");
        println!("║  Type /help for commands, Ctrl-D to exit ║");
        println!("║  Type /status                            ║");
        println!("║  Type /tools                             ║");
        println!("║  Type /memory                            ║");
        println!("║  Type /cancel                            ║");
        println!("║  Type /session                           ║");
        println!("║  Type /clear                             ║");
        println!("║  Type /exit                              ║");
        println!("║  Type /gate p1-P2                        ║");
        println!("║  Type /voice on | off                    ║");
        println!("╚══════════════════════════════════════════╝");
        println!();

        let stdin = io::stdin();
        let mut stdout = io::stdout();

        for line in stdin.lock().lines() {
            let input = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            let input = input.trim().to_string();
            if input.is_empty() {
                print!("{PROMPT}");
                stdout.flush().ok();
                continue;
            }

            // Built-in shell commands (don't go to agent)
            if let Some(output) = self.handle_shell_builtin(&input) {
                println!("{output}");
                print!("{PROMPT}");
                stdout.flush().ok();
                continue;
            }

            // Send to agent
            match self.send_to_agent(input).await {
                Ok(reply) => {
                    self.render_reply(&reply);
                }
                Err(e) => {
                    eprintln!("  ✗ Agent error: {e}");
                }
            }

            print!("{PROMPT}");
            stdout.flush().ok();
        }

        println!("\n  Bye.");
        Ok(())
    }

    fn handle_shell_builtin(&mut self, input: &str) -> Option<String> {
        match input {
            "/help" | "/?" => Some(HELP_TEXT.to_string()),
            "/exit" | "/quit" => {
                std::process::exit(0);
            }
            "/clear" => {
                print!("\x1B[2J\x1B[1;1H");
                None
            }
            s if s == "/voice on" => {
                self.voice = true;
                Some("  Voice mode enabled".into())
            }
            s if s == "/voice off" => {
                self.voice = false;
                Some("  Voice mode disabled".into())
            }
            s if s.starts_with("/session") => Some(format!("  Session: {}", self.session_id)),
            _ => None,
        }
    }

    async fn send_to_agent(&self, content: String) -> Result<AgentReply> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let msg = AgentMessage {
            id: uuid::Uuid::new_v4().to_string(),
            content,
            reply_tx,
        };
        self.agent_tx
            .send(msg)
            .await
            .map_err(|_| anyhow::anyhow!("Agent channel closed"))?;

        tokio::time::timeout(std::time::Duration::from_secs(60), reply_rx)
            .await
            .map_err(|_| anyhow::anyhow!("Agent reply timed out"))?
            .map_err(|_| anyhow::anyhow!("Agent reply channel dropped"))
    }

    fn render_reply(&self, reply: &AgentReply) {
        println!();

        // Tool call summary
        if !reply.tool_calls.is_empty() {
            for tc in &reply.tool_calls {
                let icon = if tc.ok { "✓" } else { "✗" };
                println!("  [{icon}] {} → {} chars", tc.tool, tc.output.len());
            }
            println!();
        }

        // Main content
        for line in reply.content.lines() {
            println!("  {line}");
        }

        // Token count (dim)
        if reply.tokens > 0 {
            println!("\n  \x1B[2m({} tokens)\x1B[0m", reply.tokens);
        }
        println!();
    }
}

const HELP_TEXT: &str = r#"  clawsh commands:
  /help           Show this help
  /status         Agent status (queue depth, tools loaded)
  /tools          List registered tools
  /memory         Show conversation memory
  /gate P1→P2     Run phase gate validation
  /cancel <id>    Cancel a queued job
  /voice on|off   Toggle TTS voice output
  /session        Show current session ID
  /clear          Clear screen
  /exit           Exit shell

  Everything else is forwarded to the agent loop.
  Natural language, JSON tool calls, and /tool-name {args} all work."#;
