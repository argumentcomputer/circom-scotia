// Copyright (c) 2021 Georgios Konstantopoulos
// Copyright (c) Lurk Lab
// SPDX-License-Identifier: MIT
//! # Circom module
//!
//! The `circom` module provides an interface for working with WebAssembly (WASM) instances, specifically tailored for
//! Circom-based cryptographic computations. It includes functionality to interact with Circom-compiled WASM functions and
//! manage the Circom computation environment.

use anyhow::Result;
use wasmer::{AsStoreMut, Function, Instance, Value};

/// Represents a WebAssembly instance for Circom computations.
#[derive(Clone, Debug)]
pub struct Wasm(Instance);

/// Base trait for interacting with Circom WASM instances.
pub trait CircomBase {
    fn init(&self, store: &mut impl AsStoreMut, sanity_check: bool) -> Result<()>;
    fn func(&self, name: &str) -> &Function;
    fn get_ptr_witness_buffer(&self, store: &mut impl AsStoreMut) -> Result<u32>;
    fn get_ptr_witness(&self, store: &mut impl AsStoreMut, w: u32) -> Result<u32>;
    fn get_n_vars(&self, store: &mut impl AsStoreMut) -> Result<u32>;
    fn get_signal_offset32(
        &self,
        store: &mut impl AsStoreMut,
        p_sig_offset: u32,
        component: u32,
        hash_msb: u32,
        hash_lsb: u32,
    ) -> Result<()>;
    fn set_signal(
        &self,
        store: &mut impl AsStoreMut,
        c_idx: u32,
        component: u32,
        signal: u32,
        p_val: u32,
    ) -> Result<()>;
    fn get_u32(&self, store: &mut impl AsStoreMut, name: &str) -> Result<u32>;
    // Only exists natively in Circom2, hardcoded for Circom
    fn get_version(&self, store: &mut impl AsStoreMut) -> Result<u32>;
}

/// Extended trait for working with Circom-specific features.
pub trait Circom {
    fn get_fr_len(&self, store: &mut impl AsStoreMut) -> Result<u32>;
    fn get_ptr_raw_prime(&self, store: &mut impl AsStoreMut) -> Result<u32>;
}

/// Extended trait for Circom version 2 specific functionalities.
#[cfg(feature = "circom-2")]
pub trait Circom2 {
    fn get_field_num_len32(&self, store: &mut impl AsStoreMut) -> Result<u32>;
    fn get_raw_prime(&self, store: &mut impl AsStoreMut) -> Result<()>;
    fn read_shared_rw_memory(&self, store: &mut impl AsStoreMut, i: u32) -> Result<u32>;
    fn write_shared_rw_memory(&self, store: &mut impl AsStoreMut, i: u32, v: u32) -> Result<()>;
    fn set_input_signal(
        &self,
        store: &mut impl AsStoreMut,
        hmsb: u32,
        hlsb: u32,
        pos: u32,
    ) -> Result<()>;
    fn get_witness(&self, store: &mut impl AsStoreMut, i: u32) -> Result<()>;
    fn get_witness_size(&self, store: &mut impl AsStoreMut) -> Result<u32>;
}

impl Circom for Wasm {
    fn get_fr_len(&self, store: &mut impl AsStoreMut) -> Result<u32> {
        self.get_u32(store, "getFrLen")
    }

    fn get_ptr_raw_prime(&self, store: &mut impl AsStoreMut) -> Result<u32> {
        self.get_u32(store, "getPRawPrime")
    }
}

#[cfg(feature = "circom-2")]
impl Circom2 for Wasm {
    fn get_field_num_len32(&self, store: &mut impl AsStoreMut) -> Result<u32> {
        self.get_u32(store, "getFieldNumLen32")
    }

    fn get_raw_prime(&self, store: &mut impl AsStoreMut) -> Result<()> {
        let func = self.func("getRawPrime");
        func.call(store, &[])?;
        Ok(())
    }

    fn read_shared_rw_memory(&self, store: &mut impl AsStoreMut, i: u32) -> Result<u32> {
        let func = self.func("readSharedRWMemory");
        let result = func.call(store, &[i.into()])?;
        Ok(result[0].unwrap_i32() as u32)
    }

    fn write_shared_rw_memory(&self, store: &mut impl AsStoreMut, i: u32, v: u32) -> Result<()> {
        let func = self.func("writeSharedRWMemory");
        func.call(store, &[i.into(), v.into()])?;
        Ok(())
    }

    fn set_input_signal(
        &self,
        store: &mut impl AsStoreMut,
        hmsb: u32,
        hlsb: u32,
        pos: u32,
    ) -> Result<()> {
        let func = self.func("setInputSignal");
        func.call(store, &[hmsb.into(), hlsb.into(), pos.into()])?;
        Ok(())
    }

    fn get_witness(&self, store: &mut impl AsStoreMut, i: u32) -> Result<()> {
        let func = self.func("getWitness");
        func.call(store, &[i.into()])?;
        Ok(())
    }

    fn get_witness_size(&self, store: &mut impl AsStoreMut) -> Result<u32> {
        self.get_u32(store, "getWitnessSize")
    }
}

impl CircomBase for Wasm {
    fn init(&self, store: &mut impl AsStoreMut, sanity_check: bool) -> Result<()> {
        let func = self.func("init");
        func.call(store, &[Value::I32(i32::from(sanity_check))])?;
        Ok(())
    }

    fn get_ptr_witness_buffer(&self, store: &mut impl AsStoreMut) -> Result<u32> {
        self.get_u32(store, "getWitnessBuffer")
    }

    fn get_ptr_witness(&self, store: &mut impl AsStoreMut, w: u32) -> Result<u32> {
        let func = self.func("getPWitness");
        let res = func.call(store, &[w.into()])?;

        Ok(res[0].unwrap_i32() as u32)
    }

    fn get_n_vars(&self, store: &mut impl AsStoreMut) -> Result<u32> {
        self.get_u32(store, "getNVars")
    }

    fn get_signal_offset32(
        &self,
        store: &mut impl AsStoreMut,
        p_sig_offset: u32,
        component: u32,
        hash_msb: u32,
        hash_lsb: u32,
    ) -> Result<()> {
        let func = self.func("getSignalOffset32");
        func.call(
            store,
            &[
                p_sig_offset.into(),
                component.into(),
                hash_msb.into(),
                hash_lsb.into(),
            ],
        )?;

        Ok(())
    }

    fn set_signal(
        &self,
        store: &mut impl AsStoreMut,
        c_idx: u32,
        component: u32,
        signal: u32,
        p_val: u32,
    ) -> Result<()> {
        let func = self.func("setSignal");
        func.call(
            store,
            &[c_idx.into(), component.into(), signal.into(), p_val.into()],
        )?;

        Ok(())
    }

    // Default to version 1 if it isn't explicitly defined
    fn get_version(&self, store: &mut impl AsStoreMut) -> Result<u32> {
        match self.0.exports.get_function("getVersion") {
            Ok(func) => Ok(func.call(store, &[])?[0].unwrap_i32() as u32),
            Err(_) => Ok(1),
        }
    }

    fn get_u32(&self, store: &mut impl AsStoreMut, name: &str) -> Result<u32> {
        let func = self.func(name);
        let result = func.call(store, &[])?;
        Ok(result[0].unwrap_i32() as u32)
    }

    fn func(&self, name: &str) -> &Function {
        self.0
            .exports
            .get_function(name)
            .unwrap_or_else(|_| panic!("function {} not found", name))
    }
}

impl Wasm {
    pub fn new(instance: Instance) -> Self {
        Self(instance)
    }
}
