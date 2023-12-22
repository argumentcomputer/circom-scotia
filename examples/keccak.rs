use bellpepper_core::ConstraintSystem;
use circom_scotia::{calculate_witness, r1cs::CircomConfig};

use pasta_curves::vesta::Base as Fr;
use std::env::current_dir;

use bellpepper_core::test_cs::TestConstraintSystem;
use pasta_curves::Fq;

fn main() {
    let root = current_dir().unwrap().join("examples/keccak");
    let wtns = root.join("circom_keccak256.wasm");
    let r1cs = root.join("circom_keccak256.r1cs");

    let mut cs = TestConstraintSystem::<Fr>::new();
    let cfg = CircomConfig::new(wtns, r1cs).unwrap();

    let input_bytes = [
        116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];
    let expected_output = [
        37, 17, 98, 135, 161, 178, 88, 97, 125, 150, 143, 65, 228, 211, 170, 133, 153, 9, 88, 212,
        4, 212, 175, 238, 249, 210, 214, 116, 170, 85, 45, 21,
    ];

    let input_bits = bytes_to_bits(&input_bytes);

    let arg_in = (
        "in".into(),
        input_bits.clone().iter().map(|b| Fr::from(*b)).collect(),
    );
    let input = vec![arg_in];
    let witness = calculate_witness(&cfg, input, true).expect("msg");

    let state_out_fq: &[Fq] = &witness[1..1 + (32 * 8)];
    let state_out_bits: Vec<bool> = state_out_fq
        .iter()
        .map(|fq| if Fq::one() == *fq { true } else { false })
        .collect();
    let state_out_bytes = bits_to_bytes(&state_out_bits);

    assert_eq!(state_out_bytes, expected_output);
}

// Transforms a slice of bits in a slice of bytes. Fills the bytes from least to most significant
// bit.
fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    let mut bytes = vec![0; (bits.len() + 7) / 8]; // Initialize a vector with zeroes

    for (i, &bit) in bits.iter().enumerate() {
        // Iterate over each bit with its index
        let byte_index = i / 8; // Calculate the byte index for the current bit
        if bit {
            // If the current bit is true,
            bytes[byte_index] |= 1 << (i % 8); // Set the corresponding bit in the byte
        }
    }
    bytes // Return the array of bytes
}

// Transforms a slice of bytes to a slice of bits. When dividing one byte in bits, order the bits
// from the least significant to the most significant one.
fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::new(); // Create a new, empty vector to store bits

    for &byte in bytes.iter() {
        // Iterate over each byte in the input slice
        for j in 0..8 {
            // For each bit in the byte
            if byte & (1 << j) > 0 {
                // Check if the bit is set
                bits.push(true); // If the bit is set, push 1 to the vector
            } else {
                bits.push(false); // If the bit is not set, push 0
            }
        }
    }
    bits // Return the vector of bits
}
