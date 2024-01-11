use thiserror::Error;

/// Enum related to witness generatiuon problems.
#[derive(Error, Debug)]
pub enum WitnessCalculatorError {
    /// Error thrown when aligning over 64-bits fails on a target architecture of 64-bit.
    #[error("Unaligned parts after aligning over 64-bit pointer.")]
    UnalignedParts,
}
