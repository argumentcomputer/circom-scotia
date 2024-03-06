use std::mem::transmute;

use ff::{PrimeField, PrimeFieldBits};
use ruint::aliases::U256;

/// Converts a [`U256`] value into an little endian array of `[u32; 8]` limbs
pub fn u256_as_limbs(uint: U256) -> [u32; 8] {
    let limbs = *uint.as_limbs();
    unsafe { transmute(limbs) }
}

/// Converts a little endian array of `[u32; 8]` limbs into a [`U256`] value
pub fn limbs_as_u256(limbs: [u32; 8]) -> U256 {
    let limbs: [u64; 4] = unsafe { transmute(limbs) };
    U256::from_limbs(limbs)
}

/// Converts a field element into an little endian array of `[u32; 8]` limbs
pub fn ff_as_limbs<F: PrimeFieldBits>(f: F) -> [u32; 8] {
    let mut limbs = [0u32; 8];
    for (i, bit) in f.to_le_bits().iter().enumerate() {
        if *bit {
            let limb_index = i / 32;
            let bit_index = i % 32;
            limbs[limb_index] |= 1 << bit_index;
        }
    }
    limbs
}

/// Converts a little endian array of `[u32; 8]` limbs into a field element
pub fn limbs_as_ff<F: PrimeField>(limbs: [u32; 8]) -> F {
    let mut res = F::ZERO;
    let radix = F::from(0x0001_0000_0000_u64);
    for &val in limbs.iter().rev() {
        res = res * radix + F::from(u64::from(val));
    }
    res
}

/// Converts a [`U256`] into a field element. We assume the field's size matches 256 bits
pub fn u256_as_ff<F: PrimeField>(uint: U256) -> F {
    limbs_as_ff(u256_as_limbs(uint))
}

#[allow(unused)]
/// Converts a field element into a [`U256`]. We assume the field's size matches 256 bits
pub fn ff_as_u256<F: PrimeFieldBits>(f: F) -> U256 {
    limbs_as_u256(ff_as_limbs(f))
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use pasta_curves::pallas;
    use rand::Rng;
    use ruint::aliases::U256;

    use super::*;

    #[test]
    fn test_u256_limb_roundtrip() {
        let mut rng = rand::thread_rng();

        for _ in 0..100 {
            let uint = rng.gen::<U256>();
            let limbs = u256_as_limbs(uint);
            let other_uint = limbs_as_u256(limbs);
            assert_eq!(uint, other_uint)
        }
    }

    #[test]
    fn test_ff_limb_roundtrip() {
        let mut rng = rand::thread_rng();

        for _ in 0..100 {
            let f = pallas::Scalar::random(&mut rng);
            let limbs = ff_as_limbs(f);
            let other_f = limbs_as_ff(limbs);
            assert_eq!(f, other_f)
        }
    }

    #[test]
    fn test_u256_ff_roundtrip() {
        let mut rng = rand::thread_rng();

        for _ in 0..100 {
            let f = pallas::Scalar::random(&mut rng);
            let uint = ff_as_u256(f);
            let other_f = u256_as_ff(uint);
            assert_eq!(f, other_f)
        }
    }
}
