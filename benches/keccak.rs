use bellpepper_core::{test_cs::TestConstraintSystem, ConstraintSystem};
use circom_scotia::r1cs::CircomInput;
use circom_scotia::{calculate_witness, r1cs::CircomConfig, synthesize};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pasta_curves::vesta::Base as Fr;
use std::env::current_dir;

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

fn setup() -> (CircomConfig<Fr>, Vec<CircomInput<Fr>>) {
    let root = current_dir().unwrap().join("circom/keccak");
    let wtns = root.join("circom_keccak256.wasm");
    let r1cs = root.join("circom_keccak256.r1cs");
    let cfg = CircomConfig::new(wtns, r1cs).unwrap();

    let input_bytes = [
        116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];

    let input_bits = bytes_to_bits(&input_bytes);

    let arg_in = CircomInput {
        name: "in".into(),
        value: input_bits.clone().iter().map(|b| Fr::from(*b)).collect(),
    };
    let input = vec![arg_in];

    (cfg, input)
}

fn calculate_witness_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak");
    group.bench_function("calculate_witness", |b| {
        let (cfg, input) = setup();
        b.iter_batched(
            || input.clone(),
            |input| {
                calculate_witness(&cfg, black_box(input), true)
                    .expect("Failed to calculate witness");
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

fn synthesize_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak");
    group.bench_function("synthesize", |b| {
        let (cfg, input) = setup();
        let witness =
            calculate_witness(&cfg, black_box(input), true).expect("Failed to calculate witness");
        b.iter_batched(
            || witness.clone(),
            |witness| {
                let mut cs = TestConstraintSystem::<Fr>::new();
                synthesize(
                    &mut cs.namespace(|| "sha256_circom"),
                    cfg.r1cs.clone(),
                    Some(witness),
                )
                .expect("Failed to synthesize");
            },
            criterion::BatchSize::LargeInput,
        )
    });
}

fn combined_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak");
    group.bench_function("calculate_witness_and_synthesize", |b| {
        let (cfg, input) = setup();
        b.iter_batched(
            || input.clone(),
            |input| {
                let witness = calculate_witness(&cfg, black_box(input), true)
                    .expect("Failed to calculate witness");

                let mut cs = TestConstraintSystem::<Fr>::new();
                synthesize(
                    &mut cs.namespace(|| "sha256_circom"),
                    cfg.r1cs.clone(),
                    Some(witness),
                )
                .expect("Failed to synthesize");
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    benches,
    calculate_witness_benchmark,
    synthesize_benchmark,
    combined_benchmark
);
criterion_main!(benches);
