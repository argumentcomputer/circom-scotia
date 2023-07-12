use crypto_bigint::{U256, Encoding};
use ff::PrimeField;
use wasmer::{Memory, MemoryView, AsStoreRef};

use color_eyre::Result;
use std::ops::Deref;

use super::witness_calculator::{u256_to_vec_u32, from_vec_u32};

#[derive(Clone, Debug)]
pub struct SafeMemory {
    pub memory: Memory,
    pub prime: U256,

    short_max: U256,
    short_min: U256,
    n32: usize,
}

impl Deref for SafeMemory {
    type Target = Memory;

    fn deref(&self) -> &Self::Target {
        &self.memory
    }
}

impl SafeMemory {
    /// Creates a new SafeMemory
    pub fn new(memory: Memory, n32: usize, prime: U256) -> Self {
        // TODO: Figure out a better way to calculate these
        let short_max = U256::from(0x8000_0000u64);
        let short_min = short_max.neg_mod(&prime);

        Self {
            memory,
            prime,
            short_max,
            short_min,
            n32,
        }
    }

    /// Gets an immutable view to the memory in 32 byte chunks
    pub fn view<'a>(&self, store: &'a impl AsStoreRef) -> MemoryView<'a> {
        self.memory.view(store)
    }

    /// Returns the next free position in the memory
    pub fn free_pos(&self, store: &impl AsStoreRef) -> u32 {
        self.read_u32(store, 0)
    }

    /// Sets the next free position in the memory
    pub fn set_free_pos(&mut self, store: &impl AsStoreRef, ptr: u32) {
        self.write_u32(store, 0, ptr);
    }

    /// Allocates a U32 in memory
    pub fn alloc_u32(&mut self, store: &impl AsStoreRef) -> u32 {
        let p = self.free_pos(store);
        self.set_free_pos(store, p + 8);
        p
    }

    /// Writes a u32 to the specified memory offset
    pub fn write_u32(&mut self, store: &impl AsStoreRef, ptr: usize, num: u32) {
        let view = self.view(store);
        let buf = unsafe { view.data_unchecked_mut() };
        buf[ptr..ptr + std::mem::size_of::<u32>()].copy_from_slice(&num.to_le_bytes());
    }

    /// Reads a u32 from the specified memory offset
    pub fn read_u32(&self, store: &impl AsStoreRef, ptr: usize) -> u32 {
        let view = self.view(store);
        let buf = unsafe { view.data_unchecked() };

        let mut bytes = [0; 4];
        bytes.copy_from_slice(&buf[ptr..ptr + std::mem::size_of::<u32>()]);

        u32::from_le_bytes(bytes)
    }

    /// Allocates `self.n32 * 4 + 8` bytes in the memory
    pub fn alloc_fr(&mut self, store: &impl AsStoreRef) -> u32 {
        let p = self.free_pos(store);
        self.set_free_pos(store, p + self.n32 as u32 * 4 + 8);
        p
    }

    /// Writes a Field Element to memory at the specified offset, truncating
    /// to smaller u32 types if needed and adjusting the sign via 2s complement
    pub fn write_fr(&mut self, store: &impl AsStoreRef, ptr: usize, fr: U256) -> Result<()> {
        if fr < self.short_max && fr > self.short_min {
            self.write_short(store, ptr, fr)?;
        } else {
            self.write_long_normal(store, ptr, fr)?;
        }

        Ok(())
    }

    /// Reads a Field Element from the memory at the specified offset
    pub fn read_fr<F: PrimeField>(&self, store: &impl AsStoreRef, ptr: usize) -> F {
        let view = self.view(store);
        let view = unsafe { view.data_unchecked_mut() };

        let f;
        if view[ptr + 7] & 0x80 != 0 {
            let num = self.read_big(store, ptr + 8);
            f = from_vec_u32(u256_to_vec_u32(num));
        } else {
            f = F::from(self.read_u32(store, ptr) as u64);
        }

        f
    }

    fn write_short(&mut self, store: &impl AsStoreRef, ptr: usize, fr: U256) -> Result<()> {
        let num = fr.to_words()[0] as u32;
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

    fn write_big(&self, store: &impl AsStoreRef, ptr: usize, num: U256) -> Result<()> {
        let view = self.view(store);
        let buf = unsafe { view.data_unchecked_mut() };

        let bytes: [u8; 32] = num.to_le_bytes();
        buf[ptr..ptr + 32].copy_from_slice(&bytes);

        Ok(())
    }

    /// Reads `num_bytes * 32` from the specified memory offset in a Big Integer
    pub fn read_big(&self, store: &impl AsStoreRef, ptr: usize) -> U256 {
        let view = self.view(store);
        let buf = unsafe { view.data_unchecked() };
        let big = U256::from_le_slice(&buf[ptr..]);
        big.into()
    }
}

// TODO: Figure out how to read / write numbers > u32
// circom-witness-calculator: Wasm + Memory -> expose BigInts so that they can be consumed by any proof system
// ark-circom:
// 1. can read zkey
// 2. can generate witness from inputs
// 3. can generate proofs
// 4. can serialize proofs in the desired format
#[cfg(test)]
mod tests {
    use super::*;
    use wasmer::{MemoryType, Store};

    fn new() -> SafeMemory {
        SafeMemory::new(
            Memory::new(&mut Store::default(), MemoryType::new(1, None, false)).unwrap(),
            2,
            U256::from_be_hex(
                "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
            ),
        )
    }

    // #[test]
    // fn i32_bounds() {
    //     let mem = new();
    //     let i32_max = i32::MAX as i64 + 1;
    //     assert_eq!(mem.short_min.to_i64().unwrap(), -i32_max);
    //     assert_eq!(mem.short_max.to_i64().unwrap(), i32_max);
    // }

    // #[test]
    // fn read_write_32() {
    //     let mut mem = new();
    //     let num = u32::MAX;

    //     let inp = mem.read_u32(0);
    //     assert_eq!(inp, 0);

    //     mem.write_u32(0, num);
    //     let inp = mem.read_u32(0);
    //     assert_eq!(inp, num);
    // }

    // #[test]
    // fn read_write_fr_small_positive() {
    //     read_write_fr(U256::from(1_000_000));
    // }

    // #[test]
    // fn read_write_fr_big_positive() {
    //     read_write_fr(U256::from(500000000000u64));
    // }

    // // TODO: How should this be handled?
    // #[test]
    // #[ignore]
    // fn read_write_fr_big_negative() {
    //     read_write_fr(U256::from_str("-500000000000").unwrap())
    // }

    // fn read_write_fr(num: U256) {
    //     let mut mem = new();
    //     mem.write_fr(0, &num).unwrap();
    //     let res = mem.read_fr(0).unwrap();
    //     assert_eq!(res, num);
    // }
}
