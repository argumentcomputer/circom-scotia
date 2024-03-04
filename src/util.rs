use std::mem::transmute;

use ff::PrimeField;
use ruint::aliases::U256;

/// Assumes little endian
pub fn u256_as_limbs(uint: U256) -> [u32; 8] {
    let limbs = *uint.as_limbs();
    unsafe { transmute(limbs) }
}

/// Assumes little endian
pub fn limbs_as_u256(limbs: [u32; 8]) -> U256 {
    let limbs: [u64; 4] = unsafe { transmute(limbs) };
    U256::from_limbs(limbs)
}

/// Assumes little endian
pub fn ff_as_limbs<F: PrimeField>(f: F) -> [u32; 8] {
    let binding = f.to_repr();
    let repr: [u8; 32] = binding.as_ref().try_into().unwrap();
    // this doesn't work if the platform we're on is not little endian :scream:
    unsafe { transmute(repr) }
}

/// Assumes little endian
pub fn limbs_as_ff<F: PrimeField>(limbs: [u32; 8]) -> F {
    let mut repr = F::ZERO.to_repr();
    let limbs: [u8; 32] = unsafe { transmute(limbs) };
    for (i, digit) in repr.as_mut().iter_mut().enumerate() {
        // this doesn't work if the platform we're on is not little endian :scream:
        *digit = limbs[i];
    }

    F::from_repr(repr).unwrap()
}

/// Assumes little endian
pub fn u256_as_ff<F: PrimeField>(uint: U256) -> F {
    limbs_as_ff(u256_as_limbs(uint))
}

#[allow(unused)]
/// Assumes little endian
pub fn ff_as_u256<F: PrimeField>(f: F) -> U256 {
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
