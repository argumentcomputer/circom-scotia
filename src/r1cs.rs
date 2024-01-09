// Copyright (c) 2022 Nalin
// Copyright (c) Lurk Lab
// SPDX-License-Identifier: MIT
//
// Contributors:
//
// - Hanting Zhang (winston@lurk-lab.com)
//   - Adapted the original work here: https://github.com/nalinbhardwaj/Nova-Scotia/blob/main/src/circom
//   - Retrofitted to support `wasmer` witness generation.

use std::{path::Path, sync::Mutex};

use anyhow::{anyhow, Result};
use ff::PrimeField;
use serde::{Deserialize, Serialize};

use crate::{reader::load_r1cs, witness::WitnessCalculator};

#[allow(dead_code)]
#[derive(Clone)]
pub(crate) struct CircomCircuit<F: PrimeField> {
    r1cs: R1CS<F>,
    witness: Option<Vec<F>>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct R1CS<F: PrimeField> {
    pub num_pub_in: usize,
    pub num_pub_out: usize,
    pub num_inputs: usize,
    pub num_aux: usize,
    pub num_variables: usize,
    pub constraints: Vec<Constraint<F>>,
}

/// Structure representing inputs for a Circom gadget.
#[derive(Serialize, Deserialize)]
pub struct CircomInput<F: PrimeField> {
    pub name: String,
    pub value: Vec<F>,
}

pub(crate) type Constraint<F> = (Vec<(usize, F)>, Vec<(usize, F)>, Vec<(usize, F)>);

// Add utils for creating this from files / directly from bytes
#[derive(Debug)]
pub struct CircomConfig<F: PrimeField> {
    pub r1cs: R1CS<F>,
    pub wtns: Mutex<WitnessCalculator>,
    pub sanity_check: bool,
}

impl<F: PrimeField> CircomConfig<F> {
    pub fn new(wtns: impl AsRef<Path>, r1cs: impl AsRef<Path>) -> Result<Self> {
        let wtns = Mutex::new(WitnessCalculator::new(wtns).unwrap());
        let r1cs = load_r1cs(r1cs).map_err(|err| anyhow!(err))?;
        Ok(Self {
            wtns,
            r1cs,
            sanity_check: false,
        })
    }
}
