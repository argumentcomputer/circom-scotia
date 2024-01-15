use thiserror::Error;

/// Enum related to error happening while reading data from source.
#[derive(Error, Debug)]
pub enum ReaderError {
    /// Error if we failed to open the file we want to read.
    #[error("Failed to open file \"{filename}\": {source}")]
    OpenFileError {
        filename: String,
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    /// High level error returned if we could not read our .bin or .json file.
    #[error("Failed to read witness from file \"{filename}\": {source}")]
    ReadWitnessError {
        filename: String,
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    /// Error thrown if the specified filename contains non-unicode characters.
    #[error("Could not read provided file path. It most likely contains non-Unicode data.")]
    FilenameError,
    /// Error if we could not find the magic header 'wtns' in the witness file.
    #[error("'witns' header not found.")]
    WitnessHeaderError,
    /// Error if we could not find the magic header 'r1cs' in the r1cs file.
    #[error("'r1cs' header not found.")]
    R1CSHeaderError,
    /// Error thrown while failing to seek a new position in our buffer.
    #[error("Error while seeking in buffer: {source}")]
    SeekError {
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    /// Error thrown when we try to read a witness file with a non-supported version.
    #[error("Witness version not supported. Version supported is 2.*, found {0}")]
    WitnessVersionNotSupported(String),
    /// Error thrown when we try to read a r1cs file with a non-supported version.
    #[error("R1CS version not supported. Version supported is 1, found {0}")]
    R1CSVersionNotSupported(String),
    /// Error thrown when we try to read a section from our file and it does not exist.
    #[error("Failed to find section {0}")]
    SectionNotFound(String),
    /// Error if the number of sections in the witness file is not two.
    #[error("Invalid number of sections found in witness data. Expected 2 got {0}")]
    SectionCountError(String),
    /// Error thrown if the section we are reading is not of the type we expected.
    #[error("Invalid section type. Expected {0}, got {1}")]
    SectionTypeError(String, String),
    /// Error thrown if the section we are reading is not of the length we expected.
    #[error("Invalid section length. Expected {0}, got {1}")]
    SectionLengthError(String, String),
    /// Error thrown if the field we are reading is not of the size we expected.
    #[error("Invalid field byte size. Expected {0}, got {1}")]
    FieldByteSizeError(String, String),
    /// Error if we tried to read an integer from the bytes and it failed.
    #[error("Failed to read integer from bytes: {source}")]
    ReadIntegerError {
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    /// Error if we tried to read a specified amount of bytes and it failed.
    #[error("Failed to read bytes: {source}")]
    ReadBytesError {
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    /// Error if we tried to read a field element from the bytes and it failed.
    #[error("Failed to read field from bytes: {source}")]
    ReadFieldError {
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    /// Error thrown if the specified modulus in the r1cs header is not the one we were expecting.
    #[error("Mismatched prime field. Expected {expected}, read {value} in the header instead.")]
    NonMatchingPrime { expected: String, value: String },
    /// Error thrown when parsing wires in an R1CS file. We expect the first wire to always be mapped to 0.
    #[error("Wire 0 should always be mapped to 0")]
    WireError,
}

/// Enum related to witness generatiuon problems.
#[derive(Error, Debug)]
pub enum WitnessError {
    /// Error if we could not execute the node command to generate our witness.
    #[error("Failed to execute the witness generation: {source}")]
    FailedExecutionError {
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    /// Error if we could not read the witness from the generated file.
    #[error("Could not load witness from its generated file: {source}")]
    LoadWitnessError {
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    /// Error generated while trying to access or alter the file system.
    #[error("Could not interact with the file system: {source}")]
    FileSystemError {
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    /// Error generated if a panic occurs when trying to access the content of our Mutex.
    #[error("Could not acquire the witness calculator mutex lock.")]
    MutexError,
    /// Error if we could not calculate the witness.
    #[error("Failed to calculate the witness: {source}")]
    WitnessCalculationError {
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
}

/// Error related to the Circom configuration
#[derive(Error, Debug)]
pub enum CircomConfigError {
    /// Error if we could not instantiate our Witness Calculator.
    #[error(
        "Could instantiate a witness calculator based on the witness file \"{path}\": {source}"
    )]
    WitnessCalculatorInstantiationError {
        path: String,
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    /// Error if we could not load data from our R1CS file.
    #[error("Could load r1cs data from the given file \"{path}\": {source}")]
    LoadR1CSError {
        path: String,
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
}
