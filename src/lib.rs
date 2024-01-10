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

use crate::error::WitnessError::{self, FailedExecutionError, FileSystemError, LoadWitnessError};
use crate::r1cs::CircomInput;
use anyhow::{anyhow, Result};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError};
use ff::PrimeField;
use r1cs::{CircomConfig, R1CS};

use crate::reader::load_witness_from_file;

mod error;
pub mod r1cs;
pub mod reader;
pub mod witness;

pub fn generate_witness_from_wasm<F: PrimeField>(
    witness_dir: PathBuf,
    witness_input_json: String,
    witness_output: impl AsRef<Path>,
) -> Result<Vec<F>, WitnessError> {
    // Create the input.json file.
    let root = current_dir().map_err(|err| FileSystemError(err.to_string()))?;
    let witness_generator_input = root.join("circom_input.json");
    fs::write(&witness_generator_input, witness_input_json)
        .map_err(|err| FileSystemError(err.to_string()))?;

    // Prepare and execute the node cmd to generate our witness file.
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
        .map_err(|err| FailedExecutionError(err.to_string()))?;

    // Print output of the node cmd.
    if !output.stdout.is_empty() || !output.stderr.is_empty() {
        println!("stdout: {}", std::str::from_utf8(&output.stdout).unwrap());
        println!("stderr: {}", std::str::from_utf8(&output.stderr).unwrap());
    }

    // Tries to remove input file. Warns if it cannot be done.
    let res = fs::remove_file(witness_generator_input);
    if res.is_err() {
        println!("warning: could not cleanup temporary file {witness_generator_input}")
    }

    // Reads the witness from the generated file.
    load_witness_from_file(witness_output).map_err(|err| LoadWitnessError(err.to_string()))
}

/// TODO docs
pub fn calculate_witness<F: PrimeField>(
    cfg: &CircomConfig<F>,
    input: Vec<CircomInput<F>>,
    sanity_check: bool,
) -> Result<Vec<F>> {
    let mut lock = cfg.wtns.lock().unwrap();
    let witness_calculator = &mut *lock;
    witness_calculator
        .calculate_witness(input, sanity_check)
        .map_err(|err| anyhow!(err))
}

/// Parse the witness that we calculated from the circuit to update our constraint system based on it
/// and  extract the public outputs to return it.
/// Reference work is Nota-Scotia: https://github.com/nalinbhardwaj/Nova-Scotia
pub fn synthesize<F: PrimeField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    r1cs: R1CS<F>,
    witness: Option<Vec<F>>,
) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let witness = &witness;
    let mut vars: Vec<AllocatedNum<F>> = vec![];

    // Retrieve all our public signals (inputs and outputs).
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

    // Retrieve all private traces.
    for i in 0..r1cs.num_aux {
        let f: F = {
            match witness {
                None => F::ONE,
                Some(w) => w[i + r1cs.num_inputs],
            }
        };

        let v = AllocatedNum::alloc(cs.namespace(|| format!("aux_{}", i)), || Ok(f))?;
        vars.push(v);
    }

    // Public output to return.
    let output = match r1cs.num_pub_out {
        0 => vec![],
        1 => vec![vars[0].clone()],
        _ => vars[0..r1cs.num_pub_out - 1usize].to_vec(),
    };

    // Create closure responsible to create the linear combination data.
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

    Ok(output)
}
