// Copyright (c) 2022 Nalin
// Copyright (c) Lurk Lab
// SPDX-License-Identifier: MIT
//! # R1CS File Loader
//!
//! This module provides functionality for loading and parsing R1CS (Rank-1 Constraint Systems)
//! files, either in binary or JSON format. It supports handling witness data and circuit
//! constraints.

use anyhow::{anyhow, Context, Error, Result};
use ff::PrimeField;
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::ReaderError::{
    self, FieldByteSizeError, FilenameError, NonMatchingPrime, OpenFileError, R1CSHeaderError,
    R1CSVersionNotSupported, ReadBytesError, ReadFieldError, ReadIntegerError, ReadWitnessError,
    SectionCountError, SectionLengthError, SectionNotFound, SectionTypeError, SeekError, WireError,
    WitnessHeaderError, WitnessVersionNotSupported,
};
use byteorder::{LittleEndian, ReadBytesExt};

use crate::r1cs::Constraint;
use crate::r1cs::R1CS;

/// Represents R1CS (Rank-1 Constraint System) data extracted from a JSON file.
///
/// This struct includes the constraints as vectors of [`BTreeMap`], along with the number of
/// inputs, outputs, and variables in the circuit.
#[derive(Serialize, Deserialize)]
pub(crate) struct CircuitJson {
    constraints: Vec<Vec<BTreeMap<String, String>>>,
    #[serde(rename = "nPubInputs")]
    num_inputs: usize,
    #[serde(rename = "nOutputs")]
    num_outputs: usize,
    #[serde(rename = "nVars")]
    num_variables: usize,
}

/// Header of an [`R1CSFile`], containing metadata about the constraint system.
#[allow(dead_code)]
#[derive(Debug, Default)]
struct Header {
    field_size: u32,
    prime_size: Vec<u8>,
    n_wires: u32,
    n_pub_out: u32,
    n_pub_in: u32,
    n_prv_in: u32,
    n_labels: u64,
    n_constraints: u32,
}

/// Represents an R1CS (Rank-1 Constraint System) file, including version, header, constraints, and wire mapping.
#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct R1CSFile<F: PrimeField> {
    version: u32,
    header: Header,
    constraints: Vec<Constraint<F>>,
    wire_mapping: Vec<u64>,
}

/// Loads witness data from a file, detecting whether it's in binary or JSON format.
///
/// The function supports both `.bin` and `.json` file extensions and loads the witness data
/// accordingly.
pub(crate) fn load_witness_from_file<F: PrimeField>(
    filename: impl AsRef<Path>,
) -> std::result::Result<Vec<F>, ReaderError> {
    if filename.as_ref().ends_with("json") {
        load_witness_from_json_file::<F>(filename)
    } else {
        load_witness_from_bin_file::<F>(filename)
    }
}

/// Loads witness data from a binary file.
///
/// This function reads the witness data from a binary file specified by the `filename`.
/// It leverages a [`BufReader`] for efficient reading and returns a vector of field elements.
fn load_witness_from_bin_file<F: PrimeField>(
    filename: impl AsRef<Path>,
) -> std::result::Result<Vec<F>, ReaderError> {
    let path_string = filename.as_ref().to_str().ok_or(FilenameError)?.to_string();
    let reader = OpenOptions::new()
        .read(true)
        .open(&filename)
        .map_err(|err| OpenFileError {
            filename: path_string.clone(),
            source: err.into(),
        })?;
    load_witness_from_bin_reader::<F, BufReader<File>>(BufReader::new(reader)).map_err(|err| {
        ReadWitnessError {
            filename: path_string,
            source: err.into(),
        }
    })
}

/// Loads witness data from a binary reader.
///
/// This function reads the witness data from a binary reader and returns a vector of
/// field elements. It handles the binary format of the witness data, ensuring correct
/// parsing and conversion into field elements.
fn load_witness_from_bin_reader<F: PrimeField, R: Read>(
    mut reader: R,
) -> std::result::Result<Vec<F>, ReaderError> {
    let mut wtns_header = [0u8; 4];
    reader
        .read_exact(&mut wtns_header)
        .map_err(|err| ReadBytesError { source: err.into() })?;
    if wtns_header != [119, 116, 110, 115] {
        return Err(WitnessHeaderError);
    }
    let version = reader
        .read_u32::<LittleEndian>()
        .map_err(|err| ReadIntegerError { source: err.into() })?;

    if version > 2 {
        return Err(WitnessVersionNotSupported(version.to_string()));
    }
    let num_sections = reader
        .read_u32::<LittleEndian>()
        .map_err(|err| ReadIntegerError { source: err.into() })?;
    if num_sections != 2 {
        return Err(SectionCountError(num_sections.to_string()));
    }
    // Read the first section.
    let sec_type = reader
        .read_u32::<LittleEndian>()
        .map_err(|err| ReadIntegerError { source: err.into() })?;
    if sec_type != 1 {
        return Err(SectionTypeError(1.to_string(), sec_type.to_string()));
    }
    let sec_size = reader
        .read_u64::<LittleEndian>()
        .map_err(|err| ReadIntegerError { source: err.into() })?;
    if sec_size != 4 + 32 + 4 {
        return Err(SectionLengthError(
            (4 + 32 + 4).to_string(),
            sec_size.to_string(),
        ));
    }
    let field_size = reader
        .read_u32::<LittleEndian>()
        .map_err(|err| ReadIntegerError { source: err.into() })?;
    if field_size != 32 {
        return Err(FieldByteSizeError(32.to_string(), field_size.to_string()));
    }
    let mut prime = vec![0u8; field_size as usize];
    reader
        .read_exact(&mut prime)
        .map_err(|err| ReadBytesError { source: err.into() })?;

    // Read the second section.
    let witness_len = reader
        .read_u32::<LittleEndian>()
        .map_err(|err| ReadIntegerError { source: err.into() })?;
    let sec_type = reader
        .read_u32::<LittleEndian>()
        .map_err(|err| ReadIntegerError { source: err.into() })?;
    if sec_type != 2 {
        return Err(SectionTypeError(2.to_string(), sec_type.to_string()));
    }
    let sec_size = reader
        .read_u64::<LittleEndian>()
        .map_err(|err| ReadIntegerError { source: err.into() })?;
    if sec_size != u64::from(witness_len * field_size) {
        return Err(SectionLengthError(
            (witness_len * field_size).to_string(),
            sec_size.to_string(),
        ));
    }
    let mut result = Vec::with_capacity(witness_len as usize);
    for _ in 0..witness_len {
        result.push(
            read_field::<&mut R, F>(&mut reader)
                .map_err(|err| ReadFieldError { source: err.into() })?,
        );
    }
    Ok(result)
}

/// Loads witness data from a JSON file.
///
/// Reads witness data from a JSON formatted file. This function is particularly useful
/// for handling human-readable witness data, converting it into a vector of field elements.
fn load_witness_from_json_file<F: PrimeField>(
    filename: impl AsRef<Path>,
) -> std::result::Result<Vec<F>, ReaderError> {
    let path_string = filename.as_ref().to_str().ok_or(FilenameError)?.to_string();
    let reader = OpenOptions::new()
        .read(true)
        .open(&filename)
        .map_err(|err| OpenFileError {
            filename: path_string.clone(),
            source: err.into(),
        })?;
    load_witness_from_json::<F, BufReader<File>>(BufReader::new(reader)).map_err(|err| {
        ReadWitnessError {
            filename: path_string,
            source: err.into(),
        }
    })
}

/// Loads witness data from a JSON reader.
///
/// Parses witness data from a JSON reader and returns a vector of field elements.
/// Useful for cases where witness data is stored in JSON format.
fn load_witness_from_json<F: PrimeField, R: Read>(reader: R) -> Result<Vec<F>> {
    let witness: Vec<String> = serde_json::from_reader(reader).context("Failed to parse JSON")?;
    witness
        .into_iter()
        .map(|x| {
            F::from_str_vartime(&x)
                .with_context(|| format!("Failed to parse field element: '{}'", x))
        })
        .collect()
}

/// Loads an R1CS (Rank-1 Constraint System) from a binary file.
///
/// Reads an R1CS file in binary format, returning an `R1CS` structure that represents
/// the constraint system. This is key for zk-SNARK applications where the R1CS format
/// is used for defining constraints.
fn load_r1cs_from_bin_file<F: PrimeField>(
    filename: impl AsRef<Path>,
) -> Result<R1CS<F>, ReaderError> {
    let path_string = filename.as_ref().to_str().ok_or(FilenameError)?.to_string();
    let reader = OpenOptions::new()
        .read(true)
        .open(filename.as_ref())
        .map_err(|err| OpenFileError {
            filename: path_string.clone(),
            source: err.into(),
        })?;
    load_r1cs_from_bin(BufReader::new(reader)).map_err(|err| ReadWitnessError {
        filename: path_string,
        source: err.into(),
    })
}

/// Attempts to extract a field element from a byte reader.
///
/// Given a byte reader, this function attempts to read and convert the bytes into
/// a field element, returning an error if the process fails.
fn read_field<R: Read, F: PrimeField>(mut reader: R) -> Result<F, Error> {
    let mut repr = F::ZERO.to_repr();
    for digit in repr.as_mut().iter_mut() {
        // TODO: may need to reverse order?
        *digit = reader.read_u8().map_err(|err| anyhow!(err.to_string()))?;
    }

    let fr = F::from_repr(repr);

    if fr.is_some().into() {
        #[allow(clippy::unwrap_used)]
        Ok(fr.unwrap())
    } else {
        Err(anyhow!(
            "Failed to convert a byte representation into a field element."
        ))
    }
}

/// Attempts to extract an R1CS [`Header`] from a byte reader.
///
/// Reads and parses the header of an R1CS file, returning a [`Header`] struct. This includes
/// information such as field size, prime size, number of wires, public inputs, and constraints.
fn read_header<R: Read>(
    mut reader: R,
    size: u64,
    expected_prime: &str,
) -> Result<Header, ReaderError> {
    let field_size = reader
        .read_u32::<LittleEndian>()
        .map_err(|err| ReadIntegerError { source: err.into() })?;

    if size != 32 + u64::from(field_size) {
        return Err(SectionLengthError(
            size.to_string(),
            (32 + u64::from(field_size)).to_string(),
        ));
    }

    let mut prime_size = vec![0u8; field_size as usize];
    reader
        .read_exact(&mut prime_size)
        .map_err(|err| ReadBytesError { source: err.into() })?;
    let prime = U256::from_le_slice(&prime_size);
    let prime = &prime.to_string().to_ascii_lowercase();

    if prime != &expected_prime[2..] {
        // get rid of '0x' in the front
        return Err(NonMatchingPrime {
            expected: expected_prime.to_string(),
            value: prime.to_string(),
        });
    }

    Ok(Header {
        field_size,
        prime_size,
        n_wires: reader
            .read_u32::<LittleEndian>()
            .map_err(|err| ReadIntegerError { source: err.into() })?,
        n_pub_out: reader
            .read_u32::<LittleEndian>()
            .map_err(|err| ReadIntegerError { source: err.into() })?,
        n_pub_in: reader
            .read_u32::<LittleEndian>()
            .map_err(|err| ReadIntegerError { source: err.into() })?,
        n_prv_in: reader
            .read_u32::<LittleEndian>()
            .map_err(|err| ReadIntegerError { source: err.into() })?,
        n_labels: reader
            .read_u64::<LittleEndian>()
            .map_err(|err| ReadIntegerError { source: err.into() })?,
        n_constraints: reader
            .read_u32::<LittleEndian>()
            .map_err(|err| ReadIntegerError { source: err.into() })?,
    })
}

/// Reads and converts a vector of constraints from a byte reader.
///
/// This function parses a sequence of constraints from a byte reader, returning a vector
/// of constraints for use in an [`R1CS`].
fn read_constraint_vec<R: Read, F: PrimeField>(
    mut reader: R,
    _header: &Header,
) -> Result<Vec<(usize, F)>, ReaderError> {
    let n_vec = reader
        .read_u32::<LittleEndian>()
        .map_err(|err| ReadIntegerError { source: err.into() })? as usize;
    let mut vec = Vec::with_capacity(n_vec);
    for _ in 0..n_vec {
        vec.push((
            reader
                .read_u32::<LittleEndian>()
                .map_err(|err| ReadIntegerError { source: err.into() })? as usize,
            read_field::<&mut R, F>(&mut reader)
                .map_err(|err| ReadFieldError { source: err.into() })?,
        ));
    }
    Ok(vec)
}

/// Reads and constructs constraints for an R1CS from a byte reader.
///
/// Parses the constraints section of an R1CS file, constructing a vector of [`Constraint`]
/// objects that represent the constraints in the R1CS.
fn read_constraints<R: Read, F: PrimeField>(
    mut reader: R,
    _size: u64,
    header: &Header,
) -> Result<Vec<Constraint<F>>, ReaderError> {
    // todo check section size
    let mut vec = Vec::with_capacity(header.n_constraints as usize);
    for _ in 0..header.n_constraints {
        vec.push((
            read_constraint_vec::<&mut R, F>(&mut reader, header)?,
            read_constraint_vec::<&mut R, F>(&mut reader, header)?,
            read_constraint_vec::<&mut R, F>(&mut reader, header)?,
        ));
    }
    Ok(vec)
}

/// Reads and creates a mapping from wires to labels from a byte reader.
///
/// This function is responsible for parsing the wire-to-label mapping in an [`R1CS`] file,
/// critical for correctly interpreting the constraint system.
fn read_map<R: Read>(mut reader: R, size: u64, header: &Header) -> Result<Vec<u64>, ReaderError> {
    if size != u64::from(header.n_wires) * 8 {
        return Err(SectionLengthError(
            size.to_string(),
            (u64::from(header.n_wires) * 8).to_string(),
        ));
    }
    let mut vec = Vec::with_capacity(header.n_wires as usize);
    for _ in 0..header.n_wires {
        vec.push(
            reader
                .read_u64::<LittleEndian>()
                .map_err(|err| ReadIntegerError { source: err.into() })?,
        );
    }
    if vec[0] != 0 {
        return Err(WireError);
    }
    Ok(vec)
}

/// Constructs an `R1CSFile` from a byte reader.
///
/// Given a byte reader, this function constructs an [`R1CSFile`] structure, which includes
/// the version, header, constraints, and wire mapping of an [`R1CS`].
fn from_reader<F: PrimeField, R: Read + Seek>(mut reader: R) -> Result<R1CSFile<F>, ReaderError> {
    let mut magic = [0u8; 4];
    reader
        .read_exact(&mut magic)
        .map_err(|err| ReadBytesError { source: err.into() })?;
    if magic != [0x72, 0x31, 0x63, 0x73] {
        // magic = "r1cs"
        return Err(R1CSHeaderError);
    }

    let version = reader
        .read_u32::<LittleEndian>()
        .map_err(|err| ReadIntegerError { source: err.into() })?;
    if version != 1 {
        return Err(R1CSVersionNotSupported(version.to_string()));
    }

    let num_sections = reader
        .read_u32::<LittleEndian>()
        .map_err(|err| ReadIntegerError { source: err.into() })?;

    // section type -> file offset
    let mut section_offsets = HashMap::<u32, u64>::new();
    let mut section_sizes = HashMap::<u32, u64>::new();

    // get file offset of each section
    for _ in 0..num_sections {
        let section_type = reader
            .read_u32::<LittleEndian>()
            .map_err(|err| ReadIntegerError { source: err.into() })?;
        let section_size = reader
            .read_u64::<LittleEndian>()
            .map_err(|err| ReadIntegerError { source: err.into() })?;
        let offset = reader
            .stream_position()
            .map_err(|err| SeekError { source: err.into() })?;
        section_offsets.insert(section_type, offset);
        section_sizes.insert(section_type, section_size);
        reader
            .seek(SeekFrom::Current(section_size as i64))
            .map_err(|err| SeekError { source: err.into() })?;
    }

    let header_type = 1;
    let constraint_type = 2;
    let wire2label_type = 3;

    reader
        .seek(SeekFrom::Start(
            *section_offsets
                .get(&header_type)
                .ok_or_else(|| SectionNotFound(constraint_type.to_string()))?,
        ))
        .map_err(|err| SeekError { source: err.into() })?;
    let header = read_header(
        &mut reader,
        *section_sizes
            .get(&header_type)
            .ok_or_else(|| SectionNotFound(header_type.to_string()))?,
        F::MODULUS,
    )?;
    if header.field_size != 32 {
        return Err(FieldByteSizeError(
            32.to_string(),
            header.field_size.to_string(),
        ));
    }

    reader
        .seek(SeekFrom::Start(
            *section_offsets
                .get(&constraint_type)
                .ok_or_else(|| SectionNotFound(constraint_type.to_string()))?,
        ))
        .map_err(|err| SeekError { source: err.into() })?;
    let constraints = read_constraints::<&mut R, F>(
        &mut reader,
        *section_sizes
            .get(&constraint_type)
            .ok_or_else(|| SectionNotFound(constraint_type.to_string()))?,
        &header,
    )?;

    reader
        .seek(SeekFrom::Start(
            *section_offsets
                .get(&wire2label_type)
                .ok_or_else(|| SectionNotFound(constraint_type.to_string()))?,
        ))
        .map_err(|err| SeekError { source: err.into() })?;

    let wire_mapping = read_map(
        &mut reader,
        *section_sizes
            .get(&wire2label_type)
            .ok_or_else(|| SectionNotFound(constraint_type.to_string()))?,
        &header,
    )?;

    Ok(R1CSFile {
        version,
        header,
        constraints,
        wire_mapping,
    })
}

/// Loads R1CS data from a binary reader.
///
/// Reads and constructs an [`R1CS`] structure from a binary reader, which represents
/// the Rank-1 Constraint System.
fn load_r1cs_from_bin<F: PrimeField, R: Read + Seek>(reader: R) -> Result<R1CS<F>> {
    let file = from_reader(reader)?;
    let num_pub_in = file.header.n_pub_in as usize;
    let num_pub_out = file.header.n_pub_out as usize;
    let num_inputs = (1 + file.header.n_pub_in + file.header.n_pub_out) as usize;
    let num_variables = file.header.n_wires as usize;
    let num_aux = num_variables - num_inputs;

    Ok(R1CS {
        num_aux,
        num_pub_in,
        num_pub_out,
        num_inputs,
        num_variables,
        constraints: file.constraints,
    })
}

/// Loads [`R1CS`] data from a file, automatically detecting the format (binary or JSON).
///
/// This function provides a convenient way to load [`R1CS`] data, supporting both binary
/// and JSON file formats.
pub fn load_r1cs<F: PrimeField>(filename: impl AsRef<Path>) -> Result<R1CS<F>, ReaderError> {
    if filename.as_ref().ends_with("json") {
        load_r1cs_from_json_file(filename)
    } else {
        load_r1cs_from_bin_file(filename)
    }
}

/// Loads R1CS data from a JSON file.
///
/// This function reads and parses R1CS data from a JSON formatted file, converting it
/// into an [`R1CS`] structure.
fn load_r1cs_from_json_file<F: PrimeField>(
    filename: impl AsRef<Path>,
) -> Result<R1CS<F>, ReaderError> {
    let path_string = filename.as_ref().to_str().ok_or(FilenameError)?.to_string();
    let reader = OpenOptions::new()
        .read(true)
        .open(&filename)
        .map_err(|err| OpenFileError {
            filename: path_string.clone(),
            source: err.into(),
        })?;
    load_r1cs_from_json(BufReader::new(reader)).map_err(|err| ReadWitnessError {
        filename: path_string,
        source: err.into(),
    })
}

/// Loads R1CS data from a JSON reader.
///
/// Parses R1CS data from a JSON reader, creating an [`R1CS`] structure that represents
/// the constraint system in a human-readable format.
fn load_r1cs_from_json<F: PrimeField, R: Read>(reader: R) -> Result<R1CS<F>> {
    let circuit_json: CircuitJson = serde_json::from_reader(reader)?;

    let num_pub_in = circuit_json.num_inputs;
    let num_pub_out = circuit_json.num_outputs;
    let num_inputs = circuit_json.num_inputs + circuit_json.num_outputs + 1;
    let num_aux = circuit_json.num_variables - num_inputs;

    let convert_constraint = |lc: &BTreeMap<String, String>| -> Result<Vec<(usize, F)>> {
        lc.iter()
            .map(|(index, coeff)| {
                let parsed_index = index
                    .parse()
                    .map_err(|_| anyhow!("Failed to parse index: {}", index))?;
                let parsed_coeff = F::from_str_vartime(coeff)
                    .ok_or_else(|| anyhow!("Failed to parse coefficient: {}", coeff))?;
                Ok((parsed_index, parsed_coeff))
            })
            .collect()
    };

    let constraints = circuit_json
        .constraints
        .iter()
        .map(|c| {
            Ok((
                convert_constraint(&c[0])?,
                convert_constraint(&c[1])?,
                convert_constraint(&c[2])?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(R1CS {
        num_pub_in,
        num_pub_out,
        num_inputs,
        num_aux,
        num_variables: circuit_json.num_variables,
        constraints,
    })
}
