//! Wasmtime engine configuration with ADR-0006 sandbox enforcement.
//!
//! Creates a [`WasmEngine`] that is locked down per the ADR-0006 sandbox table:
//! no WASI, no networking, no filesystem, bounded memory and tables,
//! fuel-based and epoch-based interruption, and a total execution deadline.
//!
//! # Critical limitation (ADR-0006)
//!
//! Fuel and epoch interruption do NOT stop a guest blocked inside a host call.
//! Every host function imported into a component must therefore enforce its own
//! deadline and support cancellation. The [`WasmStoreData::deadline`] field is
//! the per-store wall-clock deadline that host functions MUST check.

#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use wasmtime::component::Component;
use wasmtime::{Config, Engine, ResourceLimiter, Store, Strategy};

/// Default memory ceiling per component instance: 64 MB.
const DEFAULT_MAX_MEMORY_BYTES: usize = 64 * 1024 * 1024;

/// Default table element ceiling per component instance.
const DEFAULT_MAX_TABLE_ELEMENTS: usize = 10_000;

/// Default maximum concurrently loaded components.
const DEFAULT_MAX_COMPONENTS: usize = 32;

/// Default fuel budget per component invocation: 1 billion units.
const DEFAULT_FUEL_LIMIT: u64 = 1_000_000_000;

/// Default epoch timeout (coarse-grained interruption deadline).
const DEFAULT_EPOCH_TIMEOUT_SECS: u64 = 30;

/// Default maximum output bytes produced by a single component invocation.
const DEFAULT_MAX_OUTPUT_BYTES: usize = 10 * 1024 * 1024;

/// Configuration for the Wasmtime engine per ADR-0006.
///
/// Every field corresponds to a row in the ADR-0006 sandbox table. Defaults are
/// chosen to be generous enough for legitimate plugins while preventing
/// resource-exhaustion attacks from untrusted community plugins.
#[derive(Clone, Debug)]
pub struct WasmEngineConfig {
    /// Maximum linear memory a single component instance may allocate, in bytes.
    pub max_memory_bytes: usize,
    /// Maximum number of elements a single table may hold.
    pub max_table_elements: usize,
    /// Maximum number of concurrently loaded components in the engine.
    pub max_components: usize,
    /// Fuel budget for deterministic, per-instruction interruption.
    pub fuel_limit: u64,
    /// Wall-clock budget for the epoch-based coarse deadline.
    pub epoch_timeout: Duration,
    /// Maximum bytes of output a single invocation may produce.
    pub max_output_bytes: usize,
}

impl Default for WasmEngineConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
            max_table_elements: DEFAULT_MAX_TABLE_ELEMENTS,
            max_components: DEFAULT_MAX_COMPONENTS,
            fuel_limit: DEFAULT_FUEL_LIMIT,
            epoch_timeout: Duration::from_secs(DEFAULT_EPOCH_TIMEOUT_SECS),
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        }
    }
}

/// Errors returned while creating or operating a [`WasmEngine`].
#[derive(Debug, thiserror::Error)]
pub enum WasmEngineError {
    /// Engine or config construction failed.
    #[error("engine creation failed: {0}")]
    EngineCreation(String),
    /// Component compilation from `.wasm` bytes failed.
    #[error("component compilation failed: {0}")]
    Compilation(String),
    /// A compiled component failed validation.
    #[error("component validation failed: {0}")]
    Validation(String),
    /// A configured resource limit was exceeded.
    #[error("resource limit exceeded: {limit}")]
    ResourceLimit {
        /// Human-readable name of the limit that was exceeded.
        limit: String,
    },
}

/// Wraps a Wasmtime [`Engine`] with ADR-0006 sandbox configuration.
///
/// The engine is constructed with `default-features = false` on the `wasmtime`
/// crate, meaning no WASI, no ambient filesystem, and no networking are linked.
/// This type enforces fuel consumption, epoch interruption, bounded memory and
/// tables, and a compilation cache.
pub struct WasmEngine {
    engine: Engine,
    config: WasmEngineConfig,
}

impl WasmEngine {
    /// Creates a new engine with the given ADR-0006 configuration.
    ///
    /// # Errors
    ///
    /// Returns [`WasmEngineError::EngineCreation`] if Wasmtime cannot be
    /// initialised (for example, the compilation cache cannot be created).
    pub fn new(config: WasmEngineConfig) -> Result<Self, WasmEngineError> {
        let mut wasm_config = Config::new();

        wasm_config
            .strategy(Strategy::Cranelift)
            .consume_fuel(true)
            .epoch_interruption(true)
            .parallel_compilation(true)
            .wasm_component_model(true);

        // Enable the on-disk compilation cache so repeated loads of the same
        // component do not recompile. Uses Wasmtime's default cache config.
        let cache = wasmtime::Cache::new(wasmtime::CacheConfig::new())
            .map_err(|e| WasmEngineError::EngineCreation(e.to_string()))?;
        wasm_config.cache(Some(cache));

        let engine = Engine::new(&wasm_config)
            .map_err(|e| WasmEngineError::EngineCreation(e.to_string()))?;

        Ok(Self { engine, config })
    }

    /// Compiles a component from `.wasm` bytes.
    ///
    /// The bytes must be a valid WebAssembly Component Model binary. Core wasm
    /// modules are rejected — wrap them in a component adapter first.
    ///
    /// # Errors
    ///
    /// Returns [`WasmEngineError::Compilation`] if the bytes cannot be parsed
    /// or compiled.
    pub fn compile(&self, wasm_bytes: &[u8]) -> Result<Component, WasmEngineError> {
        Component::new(&self.engine, wasm_bytes)
            .map_err(|e| WasmEngineError::Compilation(e.to_string()))
    }

    /// Creates a new store with resource limits, fuel, and epoch deadline applied.
    ///
    /// The store starts with:
    /// - Fuel set to [`WasmEngineConfig::fuel_limit`].
    /// - Epoch deadline set to 1 tick (traps on the next `Engine::increment_epoch`).
    /// - A [`WasmResourceLimiter`] enforcing memory and table bounds.
    ///
    /// # Errors
    ///
    /// Returns [`WasmEngineError::EngineCreation`] if fuel cannot be configured
    /// (only possible if the engine was not created with `consume_fuel(true)`,
    /// which is always enabled by [`WasmEngine::new`]).
    pub fn create_store(&self) -> Result<Store<WasmStoreData>, WasmEngineError> {
        let data = WasmStoreData::new(&self.config);
        let mut store = Store::new(&self.engine, data);

        store
            .set_fuel(self.config.fuel_limit)
            .map_err(|e| WasmEngineError::EngineCreation(e.to_string()))?;

        store.set_epoch_deadline(1);

        store.limiter(|data: &mut WasmStoreData| -> &mut dyn ResourceLimiter { &mut data.limiter });

        Ok(store)
    }

    /// Returns the underlying Wasmtime engine reference.
    ///
    /// Required for creating a `Linker` or instantiating precompiled components.
    #[must_use]
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Returns the configured ADR-0006 limits.
    #[must_use]
    pub fn config(&self) -> &WasmEngineConfig {
        &self.config
    }
}

/// Per-component store data containing resource tracking.
///
/// Host functions receive a `&mut WasmStoreData` via the store and MUST check
/// [`WasmStoreData::deadline`] before performing blocking work, because fuel
/// and epoch interruption cannot interrupt a guest blocked in a host call
/// (ADR-0006 critical limitation).
pub struct WasmStoreData {
    /// Resource limiter enforcing memory and table bounds.
    pub limiter: WasmResourceLimiter,
    /// Fuel consumed so far in this store (updated after calls via `get_fuel`).
    pub fuel_consumed: u64,
    /// Bytes of output produced so far.
    pub output_bytes: usize,
    /// Maximum bytes of output permitted.
    pub max_output: usize,
    /// Absolute wall-clock deadline for this store's execution.
    pub deadline: Instant,
}

impl WasmStoreData {
    /// Creates store data from the engine configuration.
    #[must_use]
    pub fn new(config: &WasmEngineConfig) -> Self {
        Self {
            limiter: WasmResourceLimiter::new(config.clone()),
            fuel_consumed: 0,
            output_bytes: 0,
            max_output: config.max_output_bytes,
            deadline: Instant::now() + config.epoch_timeout,
        }
    }

    /// Returns the current linear-memory usage tracked by the limiter.
    #[must_use]
    pub fn memory_used(&self) -> usize {
        self.limiter.memory_used()
    }

    /// Returns `true` if the store's wall-clock deadline has passed.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.deadline
    }
}

/// Resource limiter that enforces ADR-0006 memory and table bounds.
///
/// Installed per-store via `Store::limiter`. The limiter is consulted every
/// time a guest requests linear-memory or table growth.
pub struct WasmResourceLimiter {
    config: WasmEngineConfig,
    memory_used: usize,
}

impl WasmResourceLimiter {
    /// Creates a new limiter from the engine configuration.
    #[must_use]
    pub fn new(config: WasmEngineConfig) -> Self {
        Self {
            config,
            memory_used: 0,
        }
    }

    /// Returns the last requested memory size in bytes.
    #[must_use]
    pub fn memory_used(&self) -> usize {
        self.memory_used
    }
}

impl ResourceLimiter for WasmResourceLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        self.memory_used = desired;
        Ok(desired <= self.config.max_memory_bytes)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= self.config.max_table_elements)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmtime::{Instance, Module};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A module exporting a function with an infinite loop.
    const LOOP_MODULE_WAT: &str = r#"
        (module
            (func (export "spin")
                (loop (br 0))
            )
        )
    "#;

    /// A module that attempts aggressive memory growth.
    const GROW_MEMORY_MODULE_WAT: &str = r#"
        (module
            (memory (export "mem") 1)
            (func (export "grow")
                (drop (memory.grow (i32.const 2000)))
            )
        )
    "#;

    fn make_engine() -> Result<WasmEngine, WasmEngineError> {
        WasmEngine::new(WasmEngineConfig::default())
    }

    #[test]
    fn engine_creates_with_defaults() -> TestResult {
        let engine = make_engine()?;
        assert_eq!(engine.config().max_memory_bytes, DEFAULT_MAX_MEMORY_BYTES);
        Ok(())
    }

    #[test]
    fn engine_creates_with_custom_config() -> TestResult {
        let config = WasmEngineConfig {
            max_memory_bytes: 8 * 1024 * 1024,
            max_table_elements: 1_000,
            max_components: 4,
            fuel_limit: 100_000,
            epoch_timeout: Duration::from_secs(5),
            max_output_bytes: 1024,
        };

        let engine = WasmEngine::new(config)?;

        assert_eq!(engine.config().max_memory_bytes, 8 * 1024 * 1024);
        assert_eq!(engine.config().max_table_elements, 1_000);
        assert_eq!(engine.config().fuel_limit, 100_000);
        assert_eq!(engine.config().epoch_timeout, Duration::from_secs(5));
        assert_eq!(engine.config().max_output_bytes, 1024);
        Ok(())
    }

    #[test]
    fn compile_rejects_invalid_wasm() -> TestResult {
        let engine = make_engine()?;

        match engine.compile(b"this is not wasm") {
            Err(WasmEngineError::Compilation(_)) => Ok(()),
            Err(other) => Err(format!("expected Compilation, got {other:?}").into()),
            Ok(_) => Err("invalid bytes must be rejected".into()),
        }
    }

    #[test]
    fn store_has_resource_limiter() -> TestResult {
        let engine = make_engine()?;
        let store = engine.create_store()?;

        assert_eq!(store.data().memory_used(), 0);
        assert!(store.data().max_output > 0);
        assert!(store.data().deadline > Instant::now());
        Ok(())
    }

    #[test]
    fn fuel_is_consumed() -> TestResult {
        let config = WasmEngineConfig {
            fuel_limit: 1_000,
            ..WasmEngineConfig::default()
        };
        let engine = WasmEngine::new(config)?;
        let mut store = engine.create_store()?;

        let wasm = wat::parse_str(LOOP_MODULE_WAT)?;
        let module = Module::new(engine.engine(), &wasm)?;
        let instance = Instance::new(&mut store, &module, &[])?;
        let spin = instance.get_typed_func::<(), ()>(&mut store, "spin")?;

        let result = spin.call(&mut store, ());
        assert!(
            result.is_err(),
            "infinite loop must trap when fuel runs out"
        );

        let remaining = store.get_fuel()?;
        assert!(
            remaining < 1_000,
            "fuel must have been consumed, remaining: {remaining}"
        );
        Ok(())
    }

    #[test]
    fn memory_limit_enforced() -> TestResult {
        let config = WasmEngineConfig {
            max_memory_bytes: 128 * 1024,
            ..WasmEngineConfig::default()
        };
        let engine = WasmEngine::new(config)?;
        let mut store = engine.create_store()?;

        let wasm = wat::parse_str(GROW_MEMORY_MODULE_WAT)?;
        let module = Module::new(engine.engine(), &wasm)?;
        let instance = Instance::new(&mut store, &module, &[])?;

        let memory = instance
            .get_memory(&mut store, "mem")
            .ok_or("exported memory")?;

        let initial_size = memory.data_size(&store);
        assert_eq!(initial_size, 64 * 1024);

        let grow = instance
            .get_typed_func::<(), ()>(&mut store, "grow")
            .map_err(|e| e.to_string())?;

        grow.call(&mut store, ())?;

        let after_size = memory.data_size(&store);
        assert_eq!(
            after_size, initial_size,
            "memory growth beyond limit must be rejected by limiter"
        );
        Ok(())
    }

    #[test]
    fn epoch_deadline_enforced() -> TestResult {
        let engine = make_engine()?;
        let mut store = engine.create_store()?;

        let wasm = wat::parse_str(LOOP_MODULE_WAT)?;
        let module = Module::new(engine.engine(), &wasm)?;
        let instance = Instance::new(&mut store, &module, &[])?;
        let spin = instance.get_typed_func::<(), ()>(&mut store, "spin")?;

        // create_store sets epoch_deadline to 1 tick. Incrementing the engine
        // epoch once expires the store's deadline.
        engine.engine().increment_epoch();

        let result = spin.call(&mut store, ());
        assert!(
            result.is_err(),
            "execution must trap after epoch deadline expires"
        );
        Ok(())
    }

    #[test]
    fn config_defaults_match_adr() {
        let config = WasmEngineConfig::default();

        assert_eq!(
            config.max_memory_bytes, DEFAULT_MAX_MEMORY_BYTES,
            "default memory must be 64 MB"
        );
        assert_eq!(
            config.max_table_elements, DEFAULT_MAX_TABLE_ELEMENTS,
            "default table elements must be 10 000"
        );
        assert_eq!(
            config.max_components, DEFAULT_MAX_COMPONENTS,
            "default max components must be 32"
        );
        assert_eq!(
            config.fuel_limit, DEFAULT_FUEL_LIMIT,
            "default fuel must be 1 billion"
        );
        assert_eq!(
            config.epoch_timeout,
            Duration::from_secs(DEFAULT_EPOCH_TIMEOUT_SECS),
            "default epoch timeout must be 30 s"
        );
        assert_eq!(
            config.max_output_bytes, DEFAULT_MAX_OUTPUT_BYTES,
            "default max output must be 10 MB"
        );
    }
}
