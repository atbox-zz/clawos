// crates/clawos-tools/src/main.rs
// CLI for building and managing ClawOS WASM tools.
//
// Usage:
//   clawos-tools status              — list all tools and their state
//   clawos-tools build <tool>        — build a specific tool
//   clawos-tools build-all           — build all tools
//   clawos-tools install <tool>      — build + install to tools_dir
//   clawos-tools install-all         — install all tools
//   clawos-tools validate            — validate all manifests

#![allow(dead_code)]
use anyhow::Result;
use clawos_tools::ToolManager;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("CLAWOS_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("status");

    let tools_dir =
        std::env::var("CLAWOS_TOOLS_DIR").unwrap_or_else(|_| "/var/lib/clawos/tools".into());
    let source_dir = std::env::var("CLAWOS_SOURCE_DIR").unwrap_or_else(|_| "tools".into());

    let mgr = ToolManager::new(&tools_dir, &source_dir);

    match cmd {
        "status" => {
            println!("ClawOS Tool Registry");
            println!("  tools_dir:  {tools_dir}");
            println!("  source_dir: {source_dir}");
            println!();
            mgr.status_table()?;
        }

        "build" => {
            let tool = args
                .get(2)
                .ok_or_else(|| anyhow::anyhow!("Usage: clawos-tools build <tool>"))?;
            let wasm = mgr.build_tool(tool)?;
            println!("Built: {}", wasm.display());
        }

        "install" => {
            let tool = args
                .get(2)
                .ok_or_else(|| anyhow::anyhow!("Usage: clawos-tools install <tool>"))?;
            let wasm = mgr.build_tool(tool)?;
            let installed = mgr.install_tool(tool, &wasm)?;
            println!(
                "Installed: {} ({} bytes)",
                installed.manifest.name, installed.wasm_size
            );
        }

        "install-all" => {
            let installed = mgr.install_all()?;
            println!("Installed {} tools:", installed.len());
            for t in &installed {
                println!(
                    "  ✓ {} v{} ({} bytes)",
                    t.manifest.name, t.manifest.version, t.wasm_size
                );
            }
        }

        "validate" => {
            let tools = mgr.scan_installed()?;
            let mut errors = 0;
            for t in &tools {
                let errs = t.manifest.validate();
                if errs.is_empty() {
                    println!("  ✓ {}", t.manifest.name);
                } else {
                    println!("  ✗ {}: {:?}", t.manifest.name, errs);
                    errors += 1;
                }
            }
            if errors > 0 {
                anyhow::bail!("{errors} tool(s) failed validation");
            }
            println!("All {} tools valid", tools.len());
        }

        other => {
            anyhow::bail!(
                "Unknown command: {other}. Try: status, build, install, install-all, validate"
            );
        }
    }

    Ok(())
}
