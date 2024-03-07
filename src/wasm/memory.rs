// Copyright (c) 2021 Georgios Konstantopoulos
// Copyright (c) Lurk Lab
// SPDX-License-Identifier: MIT
//! # Memory Module
//!
//! This module provides the `SafeMemory` struct and associated methods for efficient and secure memory management in
//! WASM (WebAssembly) computations, particularly focused on Circom circuit calculations.

use ff::PrimeField;
use ruint::aliases::U256;
use wasmer::{AsStoreRef, Memory, MemoryView};

use anyhow::Result;
use std::ops::Deref;

use crate::util::u256_as_ff;

/// A wrapper around the [`wasmer::Memory`] object, providing additional functionality
/// and safety checks specific to Circom computations.
#[derive(Clone, Debug)]
pub struct SafeMemory {
    /// The underlying WebAssembly memory instance.
    pub memory: Memory,
    /// A [`U256` ]representing the prime field used in computations.
    pub prime: U256,
    /// The maximum value for a short field element.
    short_max: U256,
    /// The minimum value for a short field element.
    short_min: U256,
    /// The size of the memory chunks, in 32-bit units.
    n32: usize,
}

impl Deref for SafeMemory {
    type Target = Memory;

    fn deref(&self) -> &Self::Target {
        &self.memory
    }
}

impl SafeMemory {
    /// Creates a new [`SafeMemory`] instance for managing memory in WASM computations.
    /// This method initializes various parameters required for prime field operations.
    ///
    /// # Arguments
    ///
    /// * `memory` - A [`wasmer::Memory`] instance representing the WebAssembly memory.
    /// * `n32` - The size of memory chunks, expressed in 32-bit units.
    /// * `prime` - A [`U256`] prime field used in cryptographic computations.
    pub fn new(memory: Memory, n32: usize, prime: U256) -> Self {
        // TODO: Figure out a better way to calculate these
        let short_max = U256::from(0x8000_0000u64);
        let short_min = short_max.wrapping_neg().reduce_mod(prime);

        Self {
            memory,
            prime,
            short_max,
            short_min,
            n32,
        }
    }

    /// Gets an immutable view of the memory in 32-byte chunks.
    ///
    /// # Arguments
    ///
    /// * `store` - A reference to the store that holds the WebAssembly memory.
    pub fn view<'a>(&self, store: &'a impl AsStoreRef) -> MemoryView<'a> {
        self.memory.view(store)
    }

    /// Retrieves the current position of the free memory pointer.
    ///
    /// # Arguments
    ///
    /// * `store` - A reference to the store that holds the WebAssembly memory.
    pub fn free_pos(&self, store: &impl AsStoreRef) -> u32 {
        self.read_u32(store, 0)
    }

    /// Sets the next position for the free memory pointer.
    ///
    /// # Arguments
    ///
    /// * `store` - A reference to the store that holds the WebAssembly memory.
    /// * `ptr` - The memory address to set as the next free position.
    pub fn set_free_pos(&mut self, store: &impl AsStoreRef, ptr: u32) {
        self.write_u32(store, 0, ptr);
    }

    /// Allocates space for a [`u32`] value in memory and returns its pointer.
    ///
    /// # Arguments
    ///
    /// * `store` - A reference to the store that holds the WebAssembly memory.
    pub fn alloc_u32(&mut self, store: &impl AsStoreRef) -> u32 {
        let p = self.free_pos(store);
        self.set_free_pos(store, p + 8);
        p
    }

    /// Writes a [`u32`] value to a specified memory offset.
    ///
    /// # Arguments
    ///
    /// * `store` - A reference to the store that holds the WebAssembly memory.
    /// * `ptr` - The memory address where the [`u32`] value will be written.
    /// * `num` - The [`u32`] value to write.
    pub fn write_u32(&mut self, store: &impl AsStoreRef, ptr: usize, num: u32) {
        let view = self.view(store);
        let buf = unsafe { view.data_unchecked_mut() };
        buf[ptr..ptr + std::mem::size_of::<u32>()].copy_from_slice(&num.to_le_bytes());
    }

    /// Reads a [`u32`] value from a specified memory offset.
    ///
    /// # Arguments
    ///
    /// * `store` - A reference to the store that holds the WebAssembly memory.
    /// * `ptr` - The memory address from where the [`u32`] value will be read.
    pub fn read_u32(&self, store: &impl AsStoreRef, ptr: usize) -> u32 {
        let view = self.view(store);
        let buf = unsafe { view.data_unchecked() };

        let mut bytes = [0; 4];
        bytes.copy_from_slice(&buf[ptr..ptr + std::mem::size_of::<u32>()]);

        u32::from_le_bytes(bytes)
    }

    /// Allocates `self.n32 * 4 + 8` space for a field element in the memory and returns its pointer.
    ///
    /// # Arguments
    ///
    /// * `store` - A reference to the store that holds the WebAssembly memory.
    pub fn alloc_fr(&mut self, store: &impl AsStoreRef) -> u32 {
        let p = self.free_pos(store);
        self.set_free_pos(store, p + self.n32 as u32 * 4 + 8);
        p
    }

    /// Writes a field element ([`U256`]) to memory at the specified offset, truncating
    /// to smaller [`u32`] types if needed and adjusting the sign via 2s complement
    ///
    /// # Arguments
    ///
    /// * `store` - A reference to the store that holds the WebAssembly memory.
    /// * `ptr` - The memory address where the field element will be written.
    /// * `fr` - The [`U256`] field element to write.
    pub fn write_fr(&mut self, store: &impl AsStoreRef, ptr: usize, fr: U256) -> Result<()> {
        if fr < self.short_max && fr > self.short_min {
            self.write_short(store, ptr, fr)?;
        } else {
            self.write_long_normal(store, ptr, fr)?;
        }

        Ok(())
    }

    /// Reads a field element ([`PrimeField`]) from the memory at the specified offset.
    ///
    /// # Arguments
    ///
    /// * `store` - A reference to the store that holds the WebAssembly memory.
    /// * `ptr` - The memory address from where the field element will be read.
    pub fn read_fr<F: PrimeField>(&self, store: &impl AsStoreRef, ptr: usize) -> F {
        let view = self.view(store);
        let view = unsafe { view.data_unchecked_mut() };

        if view[ptr + 7] & 0x80 != 0 {
            let num = self.read_big(store, ptr + 8);
            u256_as_ff(num)
        } else {
            F::from(u64::from(self.read_u32(store, ptr)))
        }
    }

    /// Writes a short field element to memory. Short elements are smaller than the upper limit of the prime field,
    /// and thus can be stored more efficiently.
    ///
    /// # Arguments
    ///
    /// * `store` - A reference to the store that holds the WebAssembly memory.
    /// * `ptr` - The memory address where the field element will be written.
    /// * `fr` - The [`U256`] field element to write.
    fn write_short(&mut self, store: &impl AsStoreRef, ptr: usize, fr: U256) -> Result<()> {
        let num = fr.as_limbs()[0] as u32;
        self.write_u32(store, ptr, num);
        self.write_u32(store, ptr + 4, 0);
        Ok(())
    }

    fn write_long_normal(&mut self, store: &impl AsStoreRef, ptr: usize, fr: U256) -> Result<()> {
        self.write_u32(store, ptr, 0);
        self.write_u32(store, ptr + 4, i32::MIN as u32); // 0x80000000
        self.write_big(store, ptr + 8, fr)?;
        Ok(())
    }

    // Writes a long field element in its normal form to memory. This method is used for elements that do not fit
    /// into the short form.
    ///
    /// # Arguments
    ///
    /// * `store` - A reference to the store that holds the WebAssembly memory.
    /// * `ptr` - The memory address where the field element will be written.
    /// * `fr` - The [`U256`] field element to write.
    fn write_big(&self, store: &impl AsStoreRef, ptr: usize, num: U256) -> Result<()> {
        let view = self.view(store);
        let buf = unsafe { view.data_unchecked_mut() };

        let bytes: [u8; 32] = num.to_le_bytes();
        buf[ptr..ptr + 32].copy_from_slice(&bytes);

        Ok(())
    }

    /// Reads a big integer ([`U256`]) from the specified memory offset.
    /// This method reads `num_bytes * 32` from memory and returns it as a [`U256`] big integer.
    ///
    /// # Arguments
    ///
    /// * `store` - A reference to the store that holds the WebAssembly memory.
    /// * `ptr` - The memory address from where the big integer will be read.
    pub fn read_big(&self, store: &impl AsStoreRef, ptr: usize) -> U256 {
        let view = self.view(store);
        let buf = unsafe { view.data_unchecked() };

        U256::from_le_slice(&buf[ptr..])
    }
}
