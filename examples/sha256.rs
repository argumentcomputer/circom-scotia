use bellpepper_core::ConstraintSystem;
use circom_scotia::{calculate_witness, r1cs::CircomConfig, synthesize};
use ff::Field;

use pasta_curves::vesta::Base as Fr;
use std::env::current_dir;

use bellpepper_core::test_cs::TestConstraintSystem;
use bellpepper_core::Comparable;

fn main() {
    let root = current_dir().unwrap().join("examples/sha256");
    let wtns = root.join("circom_sha256.wasm");
    let r1cs = root.join("circom_sha256.r1cs");

    let mut cs = TestConstraintSystem::<Fr>::new();
    let cfg = CircomConfig::new(wtns, r1cs).unwrap();

    let arg_in = ("arg_in".into(), vec![Fr::ZERO, Fr::ZERO]);
    let input = vec![arg_in];
    let witness = calculate_witness(&cfg, input, true).expect("msg");

    let output = synthesize(
        &mut cs.namespace(|| "sha256_circom"),
        cfg.r1cs.clone(),
        Some(witness),
    );

    let expected = "0x00000000008619b3767c057fdf8e6d99fde2680c5d8517eb06761c0878d40c40";
    let output_num = format!("{:?}", output.unwrap()[0].get_value().unwrap());
    assert!(output_num == expected);

    assert!(cs.is_satisfied());
    assert_eq!(30134, cs.num_constraints());
    assert_eq!(1, cs.num_inputs());
    assert_eq!(29822, cs.aux().len());

    println!("Congrats! You synthesized and satisfied a circom sha256 circuit in bellpepper!");
}
