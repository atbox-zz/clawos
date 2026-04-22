// tools/shell-exec/src/lib.rs
// Disabled by default — manifest.enabled=false.
// Only runs pre-approved commands via execvp (never sh -c).

use serde::{Deserialize, Serialize};

const WHITELIST: &[(&str, &[&str])] = &[
    ("cargo", &["test"]),
    ("cargo", &["clippy", "--", "-D", "warnings"]),
    ("cargo", &["build", "--release"]),
    ("git",   &["status"]),
    ("git",   &["log", "--oneline", "-10"]),
];

#[derive(Deserialize)]
struct Input {
    command: String,
    cwd:     Option<String>,
}

#[derive(Serialize)]
struct Output {
    stdout:    String,
    stderr:    String,
    exit_code: i32,
    command:   String,
}

pub fn run(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json)
        .map_err(|e| format!("Invalid input: {e}"))?;

    // Parse command into tokens (no shell interpretation)
    let tokens: Vec<&str> = input.command.split_whitespace().collect();
    if tokens.is_empty() {
        return Err("Empty command".into());
    }

    let binary = tokens[0];
    let args   = &tokens[1..];

    // Check against whitelist (binary + args must match exactly)
    let allowed = WHITELIST.iter().any(|(wb, wa)| {
        *wb == binary && wa.len() == args.len() &&
        wa.iter().zip(args.iter()).all(|(w, a)| w == a)
    });

    if !allowed {
        return Err(format!(
            "Command not in whitelist: '{}'. Allowed: {}",
            input.command,
            WHITELIST.iter()
                .map(|(b, a)| format!("{} {}", b, a.join(" ")))
                .collect::<Vec<_>>().join("; ")
        ));
    }

    // Validate working directory
    let cwd = input.cwd.as_deref().unwrap_or("/var/lib/clawos/workspace");
    if !cwd.starts_with("/var/lib/clawos/workspace") {
        return Err("cwd must be under /var/lib/clawos/workspace".into());
    }

    let (stdout, stderr, exit_code) = host_exec(binary, args, cwd)?;

    let out = Output { stdout, stderr, exit_code, command: input.command };
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
fn host_exec(binary: &str, args: &[&str], cwd: &str) -> Result<(String, String, i32), String> {
    let result = std::process::Command::new(binary)
        .args(args)
        .current_dir(cwd)
        .output()
        .map_err(|e| format!("exec failed: {e}"))?;
    Ok((
        String::from_utf8_lossy(&result.stdout).into(),
        String::from_utf8_lossy(&result.stderr).into(),
        result.status.code().unwrap_or(-1),
    ))
}

#[cfg(target_arch = "wasm32")]
fn host_exec(_b: &str, _a: &[&str], _cwd: &str) -> Result<(String, String, i32), String> {
    Err("host_exec not available in WASM — use host function bridge".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn whitelist_blocks_arbitrary_commands() {
        assert!(run(r#"{"command":"rm -rf /"}"#).is_err());
        assert!(run(r#"{"command":"sh -c 'cat /etc/passwd'"}"#).is_err());
        assert!(run(r#"{"command":"curl https://evil.com"}"#).is_err());
    }
    #[test]
    fn path_traversal_in_cwd_blocked() {
        assert!(run(r#"{"command":"git status","cwd":"/etc"}"#).is_err());
    }
}
