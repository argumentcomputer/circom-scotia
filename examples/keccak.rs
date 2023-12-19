use bellpepper_core::ConstraintSystem;
use circom_scotia::{calculate_witness, r1cs::CircomConfig, synthesize};
use ff::{Field, PrimeField, PrimeFieldBits};

use pasta_curves::vesta::Base as Fr;
use std::env::current_dir;

use bellpepper_core::test_cs::TestConstraintSystem;
use bellpepper_core::Comparable;
use pasta_curves::Fq;

fn main() {
    let root = current_dir().unwrap().join("examples/keccak");
    let wtns = root.join("circom_keccak256.wasm");
    let r1cs = root.join("circom_keccak256.r1cs");

    let mut cs = TestConstraintSystem::<Fr>::new();
    let cfg = CircomConfig::new(wtns, r1cs).unwrap();
    // Input that corresponds to [116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // 			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] bytes
    let input_bits = vec![
        false, true, true, true, false, true, false, false, false, true, true, false, false, true,
        false, true, false, true, true, true, false, false, true, true, false, true, true, true,
        false, true, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false,
    ];

    let arg_in = (
        "in".into(),
        input_bits.clone().iter().map(|b| Fr::from(*b)).collect(),
    );
    let input_bytes = bits_to_bytes(&input_bits);
    println!("Input bytes: {:?}", &input_bytes);

    let input = vec![arg_in];
    let witness = calculate_witness(&cfg, input, true).expect("msg");
    // From how it is handled in https://github.com/vocdoni/keccak256-circom/blob/master/test/keccak.js#L32-L33
    let state_out_fq = &witness[1..1 + (32 * 8)];
    let state_out_bits = fq_to_bits(&state_out_fq);
    let state_out_bytes = bits_to_bytes(&state_out_bits);
    println!(
        "Output bits: {:?}",
        state_out_fq
            .iter()
            .map(|n| {
                if n == &Fq::one() {
                    1
                } else {
                    0
                }
            })
            .collect::<Vec<u8>>()
    );
    println!("Output bytes: {:?}", &state_out_bytes);

    // From sha256 example
    let res = synthesize(
        &mut cs.namespace(|| "circom_keccak256"),
        cfg.r1cs.clone(),
        Some(witness),
    );
    let output = res.unwrap();
    dbg!(output.len());
    let state_out_fq = &output[0..0 + (32 * 8)];
    println!(
        "Bits out: {:?}",
        state_out_fq
            .iter()
            .map(|n| {
                let value = n.get_value().unwrap();
                if value == Fq::one() {
                    1
                } else {
                    0
                }
            })
            .collect::<Vec<u8>>()
    );
}

fn fq_to_bits(fq_slice: &[Fq]) -> Vec<bool> {
    let mut bits = Vec::new();
    for &fq in fq_slice {
        if fq == Fq::one() {
            bits.push(true)
        } else {
            bits.push(false)
        }
    }
    bits
}

// Rust bit to byte implementation
// // Fills the byte from most important (leftmost) to the least significant (rightmost) bit
fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    let mut bytes = Vec::new(); // Create a new, empty vector to store bytes

    for chunk in bits.chunks(8) {
        // Iterate over the bits in chunks of 8
        let mut byte = 0u8; // Initialize a new byte to 0
        for (i, &bit) in chunk.iter().enumerate() {
            // Iterate over each bit in the chunk
            if bit {
                // If the current bit is true,
                byte |= 1 << (7 - i); // Set the corresponding bit in the byte
            }
        }
        bytes.push(byte); // Add the composed byte to the vector
    }
    bytes // Return the vector of bytes
}

// Implemented as https://github.com/vocdoni/keccak256-circom/blob/master/test/utils.js#L76-L89
// Fills the byte from least to most significant bit
fn js_bits_to_bytes(bits: &[bool]) -> Vec<u8> {
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
