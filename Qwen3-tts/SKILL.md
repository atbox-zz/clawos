---
name: rust
description: Use this skill whenever the user wants to write, compile, debug, or optimize Rust code. Triggers include: creating Rust projects, writing Rust functions/structs/traits/modules, working with Cargo, async Rust, error handling with Result/Option, lifetimes, ownership issues, FFI, WebAssembly targets, CLI tools, or performance-critical systems code. Also use when converting code from another language to Rust, or when asked to explain Rust-specific concepts like borrowing, lifetimes, or the type system.
license: Apache-2.0
---

# Rust Development Guide

## Overview

This guide covers Rust project structure, idiomatic patterns, common crates, and best practices for writing safe and performant Rust code. Claude should always prefer idiomatic Rust over literal translations from other languages.

---

## Quick Start

```bash
# Create a new project
cargo new my_project
cd my_project

# Build and run
cargo run

# Run tests
cargo test

# Build release (optimized)
cargo build --release

# Check without building
cargo check
```

---

## Project Structure

```
my_project/
├── Cargo.toml          # Manifest: dependencies, metadata
├── Cargo.lock          # Locked dependency versions (commit for binaries)
├── src/
│   ├── main.rs         # Binary entry point
│   ├── lib.rs          # Library root (if dual crate)
│   └── modules/
│       ├── mod.rs      # Module declaration
│       └── feature.rs
├── tests/
│   └── integration.rs  # Integration tests
├── benches/
│   └── bench.rs        # Benchmarks (criterion)
└── examples/
    └── demo.rs         # runnable with `cargo run --example demo`
```

---

## Cargo.toml Essentials

```toml
[package]
name = "my_project"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { version = "1", features = ["derive"] }
tokio = { version = "1", features = ["full"] }
anyhow = "1"
thiserror = "2"
clap = { version = "4", features = ["derive"] }
tracing = "0.1"
tracing-subscriber = "0.3"

[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
strip = true
```

---

## Error Handling

### Using `anyhow` (applications)

```rust
use anyhow::{Context, Result};

fn read_config(path: &str) -> Result<String> {
    std::fs::read_to_string(path)
|  |
}

fn main() -> Result<()> {
    let config = read_config("config.toml")?;
    println!("{config}");
    Ok(())
}
```

### Using `thiserror` (libraries)

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error at line {line}: {msg}")]
    Parse { line: usize, msg: String },
    #[error("Not found: {0}")]
    NotFound(String),
}

pub fn find_user(id: u64) -> Result<User, AppError> {
    Err(AppError::NotFound(format!("User {id}")))
}
```

### The `?` Operator

```rust
// ? propagates errors automatically
fn process() -> Result<(), AppError> {
    let data = std::fs::read_to_string("data.txt")?;  // auto-converts io::Error
    let parsed: u32 = data.trim().parse()
| e |
    println!("Parsed: {parsed}");
    Ok(())
}
```

---

## Ownership & Borrowing Patterns

```rust
// Pass by reference when you don't need ownership
fn print_len(s: &str) {
    println!("Length: {}", s.len());
}

// Clone only when necessary
let s1 = String::from("hello");
let s2 = s1.clone();  // explicit clone

// Use Cow<str> for flexible string ownership
use std::borrow::Cow;
fn normalize(s: &str) -> Cow<str> {
    if s.contains(' ') {
        Cow::Owned(s.replace(' ', "_"))
    } else {
        Cow::Borrowed(s)
    }
}
```

---

## Structs, Enums & Traits

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: u64,
    pub name: String,
    pub email: Option<String>,
}

impl User {
    pub fn new(id: u64, name: impl Into<String>) -> Self {
        Self { id, name: name.into(), email: None }
    }

    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }
}

// Implement Display
use std::fmt;
impl fmt::Display for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "User({}: {})", self.id, self.name)
    }
}

// Trait definition
pub trait Summarize {
    fn summary(&self) -> String;
    fn preview(&self) -> &str { "..." }  // default impl
}

impl Summarize for User {
    fn summary(&self) -> String {
        format!("{} <{}>", self.name, self.email.as_deref().unwrap_or("no email"))
    }
}
```

---

## Async Rust (Tokio)

```rust
use tokio::time::{sleep, Duration};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let result = fetch_data("https://example.com").await?;
    println!("{result}");
    Ok(())
}

async fn fetch_data(url: &str) -> Result<String> {
    let response = reqwest::get(url).await?.text().await?;
    Ok(response)
}

// Concurrent tasks
async fn run_parallel() -> Result<()> {
    let (a, b) = tokio::join!(
        fetch_data("https://api1.example.com"),
        fetch_data("https://api2.example.com"),
    );
    println!("{} {}", a?, b?);
    Ok(())
}

// Spawning tasks
async fn spawn_tasks() {
    let handles: Vec<_> = (0..4)
| i |
            sleep(Duration::from_millis(100 * i)).await;
            i * i
        }))
        .collect();

    for handle in handles {
        println!("{}", handle.await.unwrap());
    }
}
```

---

## Common Collections & Iterators

```rust
// Idiomatic iterator chains
let numbers = vec![1, 2, 3, 4, 5];

let result: Vec<i32> = numbers.iter()
| &&x |
| &x  |
    .collect();

// HashMap
use std::collections::HashMap;
let mut scores: HashMap<String, u32> = HashMap::new();
scores.entry("Alice".to_string()).or_insert(0) += 1;

// flatten / flat_map
let words = vec![vec!["hello", "world"], vec!["foo", "bar"]];
let flat: Vec<&str> = words.into_iter().flatten().collect();

// zip, enumerate
let names = vec!["Alice", "Bob"];
let ages = vec![30, 25];
let pairs: Vec<_> = names.iter().zip(ages.iter()).collect();
```

---

## Lifetimes

```rust
// Explicit lifetimes when returning references
fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > y.len() { x } else { y }
}

// Struct holding references
struct Excerpt<'a> {
    text: &'a str,
}

impl<'a> Excerpt<'a> {
    fn announce(&self, msg: &str) -> &str {
        println!("Attention: {msg}");
        self.text
    }
}
```

---

## CLI with Clap

```rust
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "mytool", about = "A CLI tool")]
struct Cli {
    /// Input file path
    #[arg(short, long)]
    input: std::path::PathBuf,

    /// Verbose mode
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Number of workers
    #[arg(short, long, default_value_t = 4)]
    workers: usize,
}

fn main() {
    let cli = Cli::parse();
    println!("Input: {:?}, workers: {}", cli.input, cli.workers);
}
```

---

## Logging with Tracing

```rust
use tracing::{info, warn, error, instrument};
use tracing_subscriber::EnvFilter;

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
}

#[instrument]
async fn process_request(id: u64) {
    info!("Processing request");
    warn!(id, "This might be slow");
    error!("Something went wrong");
}
```

---

## Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn test_panic() {
        let v: Vec<i32> = vec![];
        let _ = v[0];
    }

    #[tokio::test]
    async fn test_async() {
        let result = some_async_fn().await;
        assert!(result.is_ok());
    }
}

// Integration tests in tests/integration.rs
// They can only access public API
```

---

## Common Crates Reference

| Category       | Crate                  | Use Case           |
| ---------------| -----------------------| -------------------|
| Error handling | `anyhow`               | Applications       |
| Error handling | `thiserror`            | Libraries          |
| Serialization  | `serde` + `serde_json` | JSON/TOML/etc      |
| Async runtime  | `tokio`                | Async I/O          |
| HTTP client    | `reqwest`              | REST APIs          |
| HTTP server    | `axum`                 | Web APIs           |
| CLI            | `clap`                 | Argument parsing   |
| Logging        | `tracing`              | Structured logging |
| Database       | `sqlx`                 | Async SQL          |
| Regex          | `regex`                | Pattern matching   |
| Parallelism    | `rayon`                | Data parallelism   |
| Random         | `rand`                 | RNG                |
| Time           | `chrono`               | Date/time          |
| UUID           | `uuid`                 | UUID generation    |

---

## Best Practices

**Do:**
- Prefer `&str` over `String` in function parameters when you don't need ownership
- Use `impl Trait` in function signatures for flexibility
- Use `#[derive(Debug)]` on all public types
- Prefer `unwrap_or_else` over `unwrap` in production code
- Use `cargo clippy` and fix all warnings before shipping

**Avoid:**
- `unwrap()` and `expect()` in library code (only OK in tests/examples)
- `clone()` on large data structures without good reason
- `unsafe` blocks unless absolutely necessary and well-documented
- Nested `match` when `if let` or `?` is cleaner
- Premature optimization—profile first with `cargo flamegraph` or `perf`

---

## Running the Code

```bash
# Development
cargo run
cargo run -- --input file.txt --verbose

# Tests
cargo test
cargo test -- --nocapture        # show println output
cargo test specific_test_name    # run one test

# Linting
cargo clippy -- -D warnings

# Format
cargo fmt

# Documentation
cargo doc --open

# Benchmarks
cargo bench
```
