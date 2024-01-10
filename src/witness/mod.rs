// Copyright (c) 2021 Georgios Konstantopoulos
// Copyright (c) Lurk Lab
// SPDX-License-Identifier: MIT
//! # Witness module
//!
//! The `witness` module of the Circom Scotia library provides core functionality to interface with Circom-generated
//! WebAssembly (WASM) code. It handles the instantiation and execution of WASM modules, enabling the calculation of
//! circuit witnesses based on given inputs.
//!
//! This module is comprised of several submodules, each responsible for different aspects of the WASM interaction:
//! - `witness_calculator`: Manages the WASM instance and performs witness calculation. It abstracts the interaction
//!   with the WASM module, providing a high-level interface for witness generation.
//! - `memory`: Handles memory operations and safety within the WASM environment, ensuring proper allocation, read, and
//!   write operations on the WASM memory.
//! - `circom`: Provides traits and implementations specific to Circom, supporting both Circom versions 1 and 2. It
//!   includes functionalities such as initialization, memory access, and version-specific operations.
//!
//! Additionally, this module defines utility functions for hashing and other common operations used across the Circom
//! Scotia library.
//!
//! Features:
//! - Initialization and management of Circom WASM instances.
//! - Safe and efficient memory operations within the WASM context.
//! - Support for both Circom 1 and Circom 2.
//! - Utility functions for hashing and other operations.
mod witness_calculator;
pub use witness_calculator::WitnessCalculator;

mod memory;
pub(super) use memory::SafeMemory;

mod circom;
mod error;

pub(super) use circom::{CircomBase, Wasm};

#[cfg(feature = "circom-2")]
pub(super) use circom::Circom2;

pub(super) use circom::Circom;

use fnv::FnvHasher;
use std::hash::Hasher;

pub(crate) fn fnv(inp: &str) -> (u32, u32) {
    let mut hasher = FnvHasher::default();
    hasher.write(inp.as_bytes());
    let h = hasher.finish();

    ((h >> 32) as u32, h as u32)
}
