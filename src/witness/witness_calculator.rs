// Copyright (c) 2021 Georgios Konstantopoulos
// Copyright (c) Lurk Lab
// SPDX-License-Identifier: MIT
//! # Witness calculator module
//!
//! The `witness_calculator` module provides functionality for initializing and interacting
//! with Circom-generated WebAssembly instances. It facilitates the calculation of circuit
//! witnesses (solutions) based on provided inputs.
//!
//! This module abstracts the complexities of setting up a WebAssembly environment and
//! executing Circom-generated code within it. It includes the definition of [`WitnessCalculator`],
//! which is responsible for initializing the WebAssembly instance, allocating memory, and
//! performing computations to generate the witness.
//!
//! The [`WitnessCalculator`] struct interacts with the WebAssembly instance using the
//! WebAssembly [`Store`], and manages memory through a [`SafeMemory`] object. It supports both
//! Circom version 1 and version 2, providing the necessary interface to handle differences
//! in their execution environments.
//!
//! Additionally, this module contains utility functions for converting between field elements
//! and their byte representations, as well as the `runtime` submodule, which provides callback
//! hooks for debugging and error handling within the WebAssembly environment.
use anyhow::Result;
use crypto_bigint::U256;
use ff::PrimeField;
use wasmer::{
    imports, AsStoreMut, Function, Instance, Memory, MemoryType, Module, RuntimeError, Store,
};
#[cfg(feature = "llvm")]
use wasmer_compiler_llvm::LLVM;

use super::{fnv, Circom, SafeMemory, Wasm};
use crate::error::ReaderError::WitnessVersionNotSupported;
use crate::{r1cs::CircomInput, witness::error::WitnessCalculatorError::UnalignedParts};

/// A struct for managing and calculating witnesses in Circom circuits.
/// It utilizes a WebAssembly instance to run computations and manage state.
#[derive(Debug)]
pub struct WitnessCalculator {
    pub instance: Wasm,
    pub store: Store,
    pub memory: SafeMemory,
    pub n64: u32,
    pub circom_version: u32,
}

// Error type to signal end of execution.
// From https://docs.wasmer.io/integrations/examples/exit-early
#[derive(thiserror::Error, Debug, Clone, Copy)]
#[error("{0}")]
struct ExitCode(u32);

/// Helper function to convert a vector of [`u32`] values to a [`PrimeField`] element. Assumes little endian representation.
/// Compatible with Circom version 1.
pub fn from_vec_u32<F: PrimeField>(arr: Vec<u32>) -> F {
    let mut res = F::ZERO;
    let radix = F::from(0x0001_0000_0000_u64);
    for &val in &arr {
        res = res * radix + F::from(u64::from(val));
    }
    res
}

/// Helper function to convert a vector of [`u32`] values to a [`PrimeField`] element. Assumes little endian representation.
/// Compatible with Circom version 2.
pub fn to_vec_u32<F: PrimeField>(f: F) -> Result<Vec<u32>> {
    let repr = F::to_repr(&f);
    let repr = repr.as_ref();

    let (pre, res, suf) = unsafe { repr.align_to::<u32>() };

    if !pre.is_empty() || !suf.is_empty() {
        return Err(UnalignedParts.into());
    }

    Ok(res.into())
}

/// Little endian
pub fn u256_from_vec_u32(data: &[u32]) -> Result<U256> {
    let mut limbs = [0u32; 8];
    limbs.copy_from_slice(data);

    cfg_if::cfg_if! {
        if #[cfg(target_pointer_width = "64")] {
            let (pre, limbs, suf) = unsafe { limbs.align_to::<u64>() };

            if !pre.is_empty()  || !suf.is_empty() {
                return Err(UnalignedParts.into())
            }

            Ok(U256::from_words(limbs.try_into()?))
        } else {
            Ok(U256::from_words(limbs.as_ref().try_into()?))
        }
    }
}

/// Little endian
pub fn u256_to_vec_u32(s: U256) -> Vec<u32> {
    let words = s.to_words();
    let (pre, res, suf) = unsafe { words.align_to::<u32>() };
    assert_eq!(pre.len(), 0);
    assert_eq!(suf.len(), 0);

    res.into()
}

impl WitnessCalculator {
    /// Constructs a new [`WitnessCalculator`] from a given file path.
    ///
    /// # Arguments
    ///
    /// * `path` - The file path to the WebAssembly module representing the circuit.
    ///
    /// # Errors
    ///
    /// Returns an error if the WebAssembly module cannot be loaded or instantiated.
    pub fn new(path: impl AsRef<std::path::Path>) -> Result<Self> {
        Self::from_file(path)
    }

    /// Constructs a [`WitnessCalculator`] from a file containing a WebAssembly module.
    ///
    /// # Arguments
    ///
    /// * `path` - The file path to the WebAssembly module representing the circuit.
    ///
    /// # Errors
    ///
    /// Returns an error if the WebAssembly module cannot be loaded or instantiated.
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "llvm")] {
                let compiler = LLVM::new();
                let store = Store::new(compiler);
            } else {
                let store = Store::default();
            }
        }
        let module = Module::from_file(&store, path)?;
        Self::from_module(module, store)
    }

    /// Constructs a [`WitnessCalculator`] from a WebAssembly module.
    ///
    /// # Arguments
    ///
    /// * `module` - The WebAssembly module representing the circuit.
    /// * `store` - The WebAssembly store for managing state and execution.
    ///
    /// # Errors
    ///
    /// Returns an error if the WebAssembly instance cannot be created.
    pub fn from_module(module: Module, mut store: Store) -> Result<Self> {
        // Set up the memory
        let memory = Memory::new(&mut store, MemoryType::new(2000, None, false))?;
        let import_object = imports! {
            "env" => {
                "memory" => memory.clone(),
            },
            // Host function callbacks from the WASM
            "runtime" => {
                "error" => runtime::error(&mut store),
                "logSetSignal" => runtime::log_signal(&mut store),
                "logGetSignal" => runtime::log_signal(&mut store),
                "logFinishComponent" => runtime::log_component(&mut store),
                "logStartComponent" => runtime::log_component(&mut store),
                "log" => runtime::log_component(&mut store),
                "exceptionHandler" => runtime::exception_handler(&mut store),
                "showSharedRWMemory" => runtime::show_memory(&mut store),
                "printErrorMessage" => runtime::print_error_message(&mut store),
                "writeBufferMessage" => runtime::write_buffer_message(&mut store),
            }
        };
        let instance = Wasm::new(Instance::new(&mut store, &module, &import_object)?);

        let version = instance.get_version(&mut store).unwrap_or(1);

        if version != 2 {
            return Err(WitnessVersionNotSupported(version.to_string()).into());
        }

        let n32 = instance.get_field_num_len32(&mut store)?;
        let mut safe_memory = SafeMemory::new(memory, n32 as usize, U256::ZERO);
        instance.get_raw_prime(&mut store)?;
        let mut arr = vec![0; n32 as usize];
        for i in 0..n32 {
            let res = instance.read_shared_rw_memory(&mut store, i)?;
            arr[i as usize] = res;
        }
        let prime = u256_from_vec_u32(&arr)?;

        let n64 = ((prime.bits() - 1) / 64 + 1) as u32;
        safe_memory.prime = prime;

        Ok(WitnessCalculator {
            instance,
            store,
            memory: safe_memory,
            n64,
            circom_version: version,
        })
    }

    /// Calculates the witness for a given set of Circom inputs, specific to Circom version 2.
    ///
    /// # Arguments
    ///
    /// * `inputs` - A vector of Circom inputs for the computation.
    /// * `sanity_check` - A flag to enable sanity checks during computation.
    ///
    /// # Errors
    ///
    /// Returns an error if the witness calculation fails.
    pub fn calculate_witness<F: PrimeField>(
        &mut self,
        inputs: Vec<CircomInput<F>>,
        sanity_check: bool,
    ) -> Result<Vec<F>> {
        self.instance.init(&mut self.store, sanity_check)?;

        if self.circom_version != 2 {
            return Err(WitnessVersionNotSupported(self.circom_version.to_string()).into());
        }

        let n32 = self.instance.get_field_num_len32(&mut self.store)?;

        // allocate the inputs
        for input in inputs {
            let (msb, lsb) = fnv(&input.name);

            for (i, value) in input.value.into_iter().enumerate() {
                let f_arr = to_vec_u32(value)?;
                for j in 0..n32 {
                    self.instance
                        .write_shared_rw_memory(&mut self.store, j, f_arr[j as usize])?;
                }
                self.instance
                    .set_input_signal(&mut self.store, msb, lsb, i as u32)?;
            }
        }

        let mut w = Vec::new();

        let witness_size = self.instance.get_witness_size(&mut self.store)?;
        for i in 0..witness_size {
            self.instance.get_witness(&mut self.store, i)?;
            let mut arr = vec![0; n32 as usize];
            for j in 0..n32 {
                arr[(n32 as usize) - 1 - (j as usize)] =
                    self.instance.read_shared_rw_memory(&mut self.store, j)?;
            }
            w.push(from_vec_u32(arr));
        }

        Ok(w)
    }

    /// Retrieves the witness buffer as a byte vector.
    ///
    /// # Arguments
    ///
    /// * `store` - A mutable reference to the WebAssembly store used in computation.
    ///
    /// # Errors
    ///
    /// Returns an error if the witness buffer cannot be retrieved.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` representing the witness buffer if successful.
    pub fn get_witness_buffer(&self, store: &mut impl AsStoreMut) -> Result<Vec<u8>> {
        let ptr = self.instance.get_ptr_witness_buffer(store)? as usize;
        let len = self.instance.get_n_vars(store)? * self.n64 * 8;
        let view = self.memory.view(store);
        let bytes = unsafe { view.data_unchecked() };

        let arr = bytes[ptr..ptr + len as usize].to_vec();

        Ok(arr)
    }
}

mod runtime {
    //! Module `runtime` provides callback hooks for debugging and interacting with the Circom execution environment in
    //! WebAssembly.
    //!
    //! These functions are typically registered as imports into the WebAssembly instance and called by the
    //! Circom-generated WebAssembly code.
    use super::{AsStoreMut, ExitCode, Function, Result, RuntimeError};
    use log::error;

    /// Creates a function to handle runtime errors occurring within the WebAssembly instance.
    ///
    /// This function is invoked when the Circom-generated code encounters a runtime error.
    /// It logs the error details and terminates the execution with a custom [`ExitCode`].
    ///
    /// # Arguments
    ///
    /// * `store` - A mutable reference to the WebAssembly store.
    ///
    /// # Returns
    ///
    /// A [`Function`] that can be called from within the WebAssembly instance.
    pub fn error(store: &mut impl AsStoreMut) -> Function {
        #[allow(unused)]
        #[allow(clippy::many_single_char_names)]
        fn func(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32) -> Result<(), RuntimeError> {
            // NOTE: We can also get more information why it is failing, see p2str etc here:
            // https://github.com/iden3/circom_runtime/blob/master/js/witness_calculator.js#L52-L64
            error!("runtime error, exiting early: {a} {b} {c} {d} {e} {f}",);
            Err(RuntimeError::user(Box::new(ExitCode(1))))
        }
        Function::new_typed(store, func)
    }

    // Function definitions for Circom 2.0

    /// Handles exceptions thrown within the WebAssembly instance for Circom 2.0.
    ///
    /// This function is a stub and currently does nothing.
    pub fn exception_handler(store: &mut impl AsStoreMut) -> Function {
        #[allow(unused)]
        fn func(a: i32) {}
        Function::new_typed(store, func)
    }

    /// Debugging function to display the shared read-write memory in Circom 2.0.
    ///
    /// This function is a stub and currently does nothing.
    pub fn show_memory(store: &mut impl AsStoreMut) -> Function {
        #[allow(unused)]
        fn func() {}
        Function::new_typed(store, func)
    }

    /// Logs error messages for Circom 2.0.
    ///
    /// This function is a stub and currently does nothing.
    pub fn print_error_message(store: &mut impl AsStoreMut) -> Function {
        #[allow(unused)]
        fn func() {}
        Function::new_typed(store, func)
    }

    /// Writes buffer messages for Circom 2.0.
    ///
    /// This function is a stub and currently does nothing.
    pub fn write_buffer_message(store: &mut impl AsStoreMut) -> Function {
        #[allow(unused)]
        fn func() {}
        Function::new_typed(store, func)
    }

    // Common utility functions for Circom 1 and Circom 2.0

    /// Logs signals during Circom computation.
    ///
    /// This function is a stub and currently does nothing.
    pub fn log_signal(store: &mut impl AsStoreMut) -> Function {
        #[allow(unused)]
        fn func(a: i32, b: i32) {}
        Function::new_typed(store, func)
    }

    /// Logs component-related messages during Circom computation.
    ///
    /// This function is a stub and currently does nothing.
    pub fn log_component(store: &mut impl AsStoreMut) -> Function {
        #[allow(unused)]
        fn func(a: i32) {}
        Function::new_typed(store, func)
    }
}
