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
    #[error("Witness version not supported. Version supported are 1 or 2, found {0}")]
    VersionNotSupported(String),
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
    #[error("Failed to read field from bytes, got: {0}")]
    ReadFieldError(String),
}
