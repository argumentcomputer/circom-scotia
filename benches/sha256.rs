use bellpepper_core::{test_cs::TestConstraintSystem, ConstraintSystem};
use circom_scotia::r1cs::CircomInput;
use circom_scotia::{calculate_witness, r1cs::CircomConfig, synthesize};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ff::Field;
use pasta_curves::vesta::Base as Fr;
use std::env::current_dir;

fn setup() -> (CircomConfig<Fr>, Vec<CircomInput<Fr>>) {
    let root = current_dir().unwrap().join("circom/sha256");
    let wtns = root.join("circom_sha256.wasm");
    let r1cs = root.join("circom_sha256.r1cs");
    let cfg = CircomConfig::new(wtns, r1cs).unwrap();

    let arg_in = CircomInput {
        name: "arg_in".into(),
        value: vec![Fr::ZERO, Fr::ZERO],
    };
    let input = vec![arg_in];

    (cfg, input)
}

fn calculate_witness_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");
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
    let mut group = c.benchmark_group("sha256");
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
    let mut group = c.benchmark_group("sha256");
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
