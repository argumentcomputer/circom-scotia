use super::{fnv, CircomBase, SafeMemory, Wasm};
use color_eyre::Result;
use crypto_bigint::U256;
use ff::PrimeField;
use wasmer::{imports, Function, Instance, Memory, MemoryType, Module, RuntimeError, Store, AsStoreMut};

// #[cfg(feature = "circom-2")]
// use num::ToPrimitive;

#[cfg(feature = "circom-2")]
use super::Circom2;

use super::Circom;

#[derive(Clone, Debug)]
pub struct WitnessCalculator {
    pub instance: Wasm,
    pub memory: SafeMemory,
    pub n64: u32,
    pub circom_version: u32,
}

// Error type to signal end of execution.
// From https://docs.wasmer.io/integrations/examples/exit-early
#[derive(thiserror::Error, Debug, Clone, Copy)]
#[error("{0}")]
struct ExitCode(u32);

#[cfg(feature = "circom-2")]
pub fn from_vec_u32<F: PrimeField>(arr: Vec<u32>) -> F {
    let mut res = F::ZERO;
    let radix = F::from(0x100000000u64);
    for &val in arr.iter() {
        res = res * radix + F::from(val as u64);
    }
    res
}

/// Little endian
#[cfg(feature = "circom-2")]
pub fn u256_from_vec_u32(data: &[u32]) -> U256 {
    use std::ops::Deref;

    let mut limbs = [0u32; 8];
    limbs.copy_from_slice(data);
    let (pre, limbs, suf) = unsafe { limbs.align_to::<u64>() };
    assert_eq!(pre.len(), 0);
    assert_eq!(suf.len(), 0);

    U256::from_words(limbs.deref().try_into().unwrap())
}

/// Little endian
#[cfg(feature = "circom-2")]
pub fn u256_to_vec_u32(s: U256) -> Vec<u32> {
    let words = s.to_words();
    let (pre, res, suf) = unsafe { words.align_to::<u32>() };
    assert_eq!(pre.len(), 0);
    assert_eq!(suf.len(), 0);

    res.into()
}

impl WitnessCalculator {
    pub fn new(path: impl AsRef<std::path::Path>) -> Result<Self> {
        Self::from_file(path)
    }

    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let store = Store::default();
        let module = Module::from_file(&store, path)?;
        Self::from_module(module, store)
    }

    pub fn from_module(module: Module, mut store: Store) -> Result<Self> {

        // Set up the memory
        let memory = Memory::new(&mut store, MemoryType::new(2000, None, false)).unwrap();
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

        // Circom 2 feature flag with version 2
        #[cfg(feature = "circom-2")]
        fn new_circom2(store: &mut impl AsStoreMut, instance: Wasm, memory: Memory, version: u32) -> Result<WitnessCalculator> {
            let n32 = instance.get_field_num_len32(store)?;
            let mut safe_memory = SafeMemory::new(memory, n32 as usize, U256::ZERO);
            instance.get_raw_prime(store)?;
            let mut arr = vec![0; n32 as usize];
            for i in 0..n32 {
                let res = instance.read_shared_rw_memory(store, i)?;
                arr[i as usize] = res;
            }
            let prime = u256_from_vec_u32(&arr);

            let n64 = ((prime.bits() - 1) / 64 + 1) as u32;
            safe_memory.prime = prime;

            Ok(WitnessCalculator {
                instance,
                memory: safe_memory,
                n64,
                circom_version: version,
            })
        }

        fn new_circom1(store: &mut impl AsStoreMut, instance: Wasm, memory: Memory, version: u32) -> Result<WitnessCalculator> {
            // Fallback to Circom 1 behavior
            let n32 = (instance.get_fr_len(store)? >> 2) - 2;
            let mut safe_memory = SafeMemory::new(memory, n32 as usize, U256::ZERO);
            let ptr = instance.get_ptr_raw_prime(store)?;
            let prime = safe_memory.read_big(store, ptr as usize);

            let n64 = ((prime.bits() - 1) / 64 + 1) as u32;
            safe_memory.prime = prime;

            Ok(WitnessCalculator {
                instance,
                memory: safe_memory,
                n64,
                circom_version: version,
            })
        }

        // Three possibilities:
        // a) Circom 2 feature flag enabled, WASM runtime version 2
        // b) Circom 2 feature flag enabled, WASM runtime version 1
        // c) Circom 1 default behavior
        //
        // Once Circom 2 support is more stable, feature flag can be removed

        cfg_if::cfg_if! {
            if #[cfg(feature = "circom-2")] {
                match version {
                    2 => new_circom2(&mut store, instance, memory, version),
                    1 => new_circom1(&mut store, instance, memory, version),
                    _ => panic!("Unknown Circom version")
                }
            } else {
                new_circom1(instance, memory, version)
            }
        }
    }

    pub fn calculate_witness<F: PrimeField, I: IntoIterator<Item = (String, Vec<U256>)>>(
        &mut self,
        store: &mut impl AsStoreMut,
        inputs: I,
        sanity_check: bool,
    ) -> Result<Vec<F>> {
        self.instance.init(store, sanity_check)?;

        cfg_if::cfg_if! {
            if #[cfg(feature = "circom-2")] {
                match self.circom_version {
                    2 => self.calculate_witness_circom2(store, inputs, sanity_check),
                    1 => self.calculate_witness_circom1(store, inputs, sanity_check),
                    _ => panic!("Unknown Circom version")
                }
            } else {
                self.calculate_witness_circom1(inputs, sanity_check)
            }
        }
    }

    // Circom 1 default behavior
    fn calculate_witness_circom1<F: PrimeField, I: IntoIterator<Item = (String, Vec<U256>)>>(
        &mut self,
        store: &mut impl AsStoreMut,
        inputs: I,
        sanity_check: bool,
    ) -> Result<Vec<F>> {
        self.instance.init(store, sanity_check)?;

        let old_mem_free_pos = self.memory.free_pos(store);
        let p_sig_offset = self.memory.alloc_u32(store);
        let p_fr = self.memory.alloc_fr(store);

        // allocate the inputs
        for (name, values) in inputs.into_iter() {
            let (msb, lsb) = fnv(&name);

            self.instance
                .get_signal_offset32(store, p_sig_offset, 0, msb, lsb)?;

            let sig_offset = self.memory.read_u32(store, p_sig_offset as usize) as usize;

            for (i, value) in values.into_iter().enumerate() {
                self.memory.write_fr(store, p_fr as usize, value)?;
                self.instance
                    .set_signal(store, 0, 0, (sig_offset + i) as u32, p_fr)?;
            }
        }

        let mut w = Vec::new();

        let n_vars = self.instance.get_n_vars(store)?;
        for i in 0..n_vars {
            let ptr = self.instance.get_ptr_witness(store, i)? as usize;
            let el = self.memory.read_fr(store, ptr);
            w.push(el);
        }

        self.memory.set_free_pos(store, old_mem_free_pos);

        Ok(w)
    }

    // Circom 2 feature flag with version 2
    #[cfg(feature = "circom-2")]
    fn calculate_witness_circom2<F: PrimeField, I: IntoIterator<Item = (String, Vec<U256>)>>(
        &mut self,
        store: &mut impl AsStoreMut,
        inputs: I,
        sanity_check: bool,
    ) -> Result<Vec<F>> {
        self.instance.init(store, sanity_check)?;

        let n32 = self.instance.get_field_num_len32(store)?;

        // allocate the inputs
        for (name, values) in inputs.into_iter() {
            let (msb, lsb) = fnv(&name);

            for (i, value) in values.into_iter().enumerate() {
                let f_arr = u256_to_vec_u32(value);
                for j in 0..n32 {
                    self.instance
                        .write_shared_rw_memory(store, j, f_arr[j as usize])?;
                }
                self.instance.set_input_signal(store, msb, lsb, i as u32)?;
            }
        }

        let mut w = Vec::new();

        let witness_size = self.instance.get_witness_size(store)?;
        for i in 0..witness_size {
            self.instance.get_witness(store, i)?;
            let mut arr = vec![0; n32 as usize];
            for j in 0..n32 {
                arr[(n32 as usize) - 1 - (j as usize)] = self.instance.read_shared_rw_memory(store, j)?;
            }
            w.push(from_vec_u32(arr));
        }

        Ok(w)
    }

    pub fn get_witness_buffer(&self, store: &mut impl AsStoreMut) -> Result<Vec<u8>> {
        let ptr = self.instance.get_ptr_witness_buffer(store)? as usize;
        let len = self.instance.get_n_vars(store)? * self.n64 * 8;
        let view = self.memory.view(store);
        let bytes = unsafe { view.data_unchecked() };

        let arr = bytes[ptr..ptr + len as usize]
            .iter()
            .map(|b| *b)
            .collect::<Vec<_>>();

        Ok(arr)
    }
}

// callback hooks for debugging
mod runtime {
    use super::*;

    pub fn error(store: &mut impl AsStoreMut) -> Function {
        #[allow(unused)]
        #[allow(clippy::many_single_char_names)]
        fn func(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32) -> Result<(), RuntimeError> {
            // NOTE: We can also get more information why it is failing, see p2str etc here:
            // https://github.com/iden3/circom_runtime/blob/master/js/witness_calculator.js#L52-L64
            println!("runtime error, exiting early: {a} {b} {c} {d} {e} {f}",);
            Err(RuntimeError::user(Box::new(ExitCode(1))))
        }
        Function::new_typed(store, func)
    }

    // Circom 2.0
    pub fn exception_handler(store: &mut impl AsStoreMut) -> Function {
        #[allow(unused)]
        fn func(a: i32) {}
        Function::new_typed(store, func)
    }

    // Circom 2.0
    pub fn show_memory(store: &mut impl AsStoreMut) -> Function {
        #[allow(unused)]
        fn func() {}
        Function::new_typed(store, func)
    }

    // Circom 2.0
    pub fn print_error_message(store: &mut impl AsStoreMut) -> Function {
        #[allow(unused)]
        fn func() {}
        Function::new_typed(store, func)
    }

    // Circom 2.0
    pub fn write_buffer_message(store: &mut impl AsStoreMut) -> Function {
        #[allow(unused)]
        fn func() {}
        Function::new_typed(store, func)
    }

    pub fn log_signal(store: &mut impl AsStoreMut) -> Function {
        #[allow(unused)]
        fn func(a: i32, b: i32) {}
        Function::new_typed(store, func)
    }

    pub fn log_component(store: &mut impl AsStoreMut) -> Function {
        #[allow(unused)]
        fn func(a: i32) {}
        Function::new_typed(store, func)
    }
}