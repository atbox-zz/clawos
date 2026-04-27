pub mod bridge;
pub mod error;
pub mod resource;
pub mod security;
pub mod cgroup_manager;
pub mod tools;

pub use bridge::{WasmBridge, WasmBridgeConfig};
pub use error::{BridgeError, BridgeResult, ErrorCode};
pub use resource::{FileDescriptor, DirectoryEntry, MemoryRegion, Socket, Cgroup, Device};
pub use security::{SeccompFilter, SecurityPolicy};
pub use cgroup_manager::{CgroupManager, ResourceLimits};
pub use tools::{ToolRegistry, ToolDefinition, ToolPackage};

use wasmtime::{Engine, Module, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder};
use tracing::{info, error, debug};

const CLAWOS_WIT_VERSION: &str = "2.0.0";
const WASMTIME_MIN_VERSION: &str = "27.0.0";

pub struct WasmRuntime {
    engine: Engine,
    config: WasmBridgeConfig,
}

impl WasmRuntime {
    pub fn new(config: WasmBridgeConfig) -> BridgeResult<Self> {
        info!("Initializing ClawOS WASM Runtime v{}", CLAWOS_WIT_VERSION);
        debug!("WIT version: {}, wasmtime version: {}", CLAWOS_WIT_VERSION, WASMTIME_MIN_VERSION);

        let mut engine_config = wasmtime::Config::new();
        engine_config.wasm_component_model(true);
        engine_config.async_support(true);
        engine_config.cranelift_opt_level(wasmtime::OptLevel::Speed);

        let engine = Engine::new(&engine_config)
            .map_err(|e| BridgeError::EngineInit(e.to_string()))?;

        info!("WASM Runtime initialized successfully");

        Ok(WasmRuntime { engine, config })
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    pub fn config(&self) -> &WasmBridgeConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_initialization() {
        let config = WasmBridgeConfig::default();
        let runtime = WasmRuntime::new(config);
        assert!(runtime.is_ok());
    }
}
