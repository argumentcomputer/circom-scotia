use thiserror::Error;

/// Enum related to error happening while reading data from source.
#[derive(Error, Debug)]
pub enum ReaderError {
    /// Error if we could not find the specified gadget either locally or on Github.
    #[error("Failed to open file \"{filename}\", got: {err}")]
    OpenFileError { filename: String, err: String },
    #[error("Failed to read witness from file \"{filename}\", got: {err}")]
    ReadWitnessError { filename: String, err: String },
    #[error("Could not read provided file path. It most likely contains non-Unicode data.")]
    FilenameError,
    #[error("'witns' header not found.")]
    WitnessHeaderError,
    #[error("'r1cs' header not found.")]
    R1CSHeaderError,
    #[error("Error while seeking in buffer, got: {0}")]
    SeekError(String),
    #[error("Witness version not supported. Version supported are 1 or 2, found {0}")]
    WitnessVersionNotSupported(String),
    #[error("R1CS version not supported. Version supported is 1, found {0}")]
    R1CSVersionNotSupported(String),
    #[error("Failed to find section {0}")]
    SectionNotFound(String),
    #[error("Invalid number of sections found in witness data. Expected 2 got {0}")]
    SectionCountError(String),
    #[error("Invalid section type. Expected {0}, got {1}")]
    SectionTypeError(String, String),
    #[error("Invalid section length. Expected {0}, got {1}")]
    SectionLengthError(String, String),
    #[error("Invalid field byte size. Expected {0}, got {1}")]
    FieldByteSizeError(String, String),
    #[error("Failed to read integer from bytes, got: {0}")]
    ReadIntegerError(String),
    #[error("Failed to read bytes, got: {0}")]
    ReadBytesError(String),
    #[error("Failed to read field from bytes, got: {0}")]
    ReadFieldError(String),
    #[error("Mismatched prime field. Expected {expected}, read {value} in the header instead.")]
    NonMatchingPrime { expected: String, value: String },
    #[error("Wire 0 should always be mapped to 0")]
    WireError,
}

/// Enum related to witness generatiuon problems.
#[derive(Error, Debug)]
pub enum WitnessError {
    /// Error if we could not execute the node command to generate our witness.
    #[error("Failed to execute the witness generation, got: {0}")]
    FailedExecutionError(String),
    /// Error if we could not read the witness from the generated file.
    #[error("Could not load witness from its generated file, got: {0}")]
    LoadWitnessError(String),
    /// Error generated while trying to access or alter the file system.
    #[error("Could not interact with the file system, got: {0}")]
    FileSystemError(String),
}
