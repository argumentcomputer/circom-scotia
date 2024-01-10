use thiserror::Error;

/// Enum related to witness generatiuon problems.
#[derive(Error, Debug)]
pub enum WitnessCalculatorError {
    /// Error thrown when we fail to initialize a new WASM memory.
    #[error("Failed to initialize a new WASM memory, got: {0}")]
    MemoryInitError(String),
    /// Error thrown when aligning over 64-bits fails on a target architecture of 64-bit.
    #[error("Unaligned parts after aligning over 64-bit pointer.")]
    UnalignedParts,
}
