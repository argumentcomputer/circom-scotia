// Copyright (c) 2022 Nalin
// Copyright (c) Lurk Lab
// SPDX-License-Identifier: MIT
//
// Contributors:
//
// - Hanting Zhang (winston@lurk-lab.com)
//   - Adapted the original work here: https://github.com/nalinbhardwaj/Nova-Scotia/blob/main/src/circom
//   - Retrofitted to support `wasmer` witness generation.

use std::{
    env::current_dir,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError};
use color_eyre::Result;
use ff::PrimeField;
use r1cs::{CircomConfig, R1CS};

use crate::reader::load_witness_from_file;

pub mod r1cs;
pub mod reader;
pub mod witness;

pub fn generate_witness_from_wasm<F: PrimeField>(
    witness_dir: PathBuf,
    witness_input_json: String,
    witness_output: impl AsRef<Path>,
) -> Vec<F> {
    let root = current_dir().unwrap();
    let witness_generator_input = root.join("circom_input.json");
    fs::write(&witness_generator_input, witness_input_json).unwrap();

    let mut witness_js = witness_dir.clone();
    witness_js.push("generate_witness.js");
    let mut witness_wasm = witness_dir.clone();
    witness_wasm.push("main.wasm");

    let output = Command::new("node")
        .arg(&witness_js)
        .arg(&witness_wasm)
        .arg(&witness_generator_input)
        .arg(witness_output.as_ref())
        .output()
        .expect("failed to execute process");
    if !output.stdout.is_empty() || !output.stderr.is_empty() {
        print!("stdout: {}", std::str::from_utf8(&output.stdout).unwrap());
        print!("stderr: {}", std::str::from_utf8(&output.stderr).unwrap());
    }
    let _ = fs::remove_file(witness_generator_input);
    load_witness_from_file(witness_output)
}

/// TODO docs
pub fn calculate_witness<F: PrimeField>(
    cfg: &CircomConfig<F>,
    input: Vec<(String, Vec<F>)>,
    sanity_check: bool,
) -> Result<Vec<F>> {
    let mut lock = cfg.wtns.lock().unwrap();
    let witness_calculator = &mut *lock;
    witness_calculator.calculate_witness(input, sanity_check)
}

/// Reference work is Nota-Scotia: https://github.com/nalinbhardwaj/Nova-Scotia
pub fn synthesize<F: PrimeField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    r1cs: R1CS<F>,
    witness: Option<Vec<F>>,
) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    //println!("witness: {:?}", witness);
    //println!("num_inputs: {:?}", r1cs.num_inputs);
    //println!("num_aux: {:?}", r1cs.num_aux);
    //println!("num_variables: {:?}", r1cs.num_variables);
    //println!("num constraints: {:?}", r1cs.constraints.len());

    let witness = &witness;

    let mut vars: Vec<AllocatedNum<F>> = vec![];

    for i in 1..r1cs.num_inputs {
        let f: F = {
            match witness {
                None => F::ONE,
                Some(w) => w[i],
            }
        };
        let v = AllocatedNum::alloc(cs.namespace(|| format!("public_{}", i)), || Ok(f))?;

        vars.push(v);
    }

    for i in 0..r1cs.num_aux {
        // Private witness trace
        let f: F = {
            match witness {
                None => F::ONE,
                Some(w) => w[i + r1cs.num_inputs],
            }
        };

        let v = AllocatedNum::alloc(cs.namespace(|| format!("aux_{}", i)), || Ok(f))?;
        vars.push(v);
    }

    let output = vars[0].clone();

    let make_lc = |lc_data: Vec<(usize, F)>| {
        let res = lc_data.iter().fold(
            LinearCombination::<F>::zero(),
            |lc: LinearCombination<F>, (index, coeff)| {
                lc + if *index > 0 {
                    (*coeff, vars[*index - 1].get_variable())
                } else {
                    (*coeff, CS::one())
                }
            },
        );
        res
    };

    for (i, constraint) in r1cs.constraints.into_iter().enumerate() {
        cs.enforce(
            || format!("constraint {}", i),
            |_| make_lc(constraint.0),
            |_| make_lc(constraint.1),
            |_| make_lc(constraint.2),
        );
    }

    Ok(vars)
}
