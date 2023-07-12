use std::{path::Path, io};

use ff::PrimeField;
use serde::{Deserialize, Serialize};

use crate::{witness::WitnessCalculator, reader::load_r1cs};

#[allow(dead_code)]
#[derive(Clone)]
pub(crate) struct CircomCircuit<F: PrimeField> {
    r1cs: R1CS<F>,
    witness: Option<Vec<F>>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct R1CS<F: PrimeField> {
    pub(crate) num_inputs: usize,
    pub(crate) num_aux: usize,
    pub(crate) num_variables: usize,
    pub(crate) constraints: Vec<Constraint<F>>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct CircomInput {
    pub(crate) arg_in: Vec<String>,
}

pub(crate) type Constraint<F> = (Vec<(usize, F)>, Vec<(usize, F)>, Vec<(usize, F)>);

// Add utils for creating this from files / directly from bytes
#[derive(Clone, Debug)]
pub struct CircomConfig<F: PrimeField> {
    pub r1cs: R1CS<F>,
    pub wtns: WitnessCalculator,
    pub sanity_check: bool,
}

impl<F: PrimeField> CircomConfig<F> {
    pub fn new(wtns: impl AsRef<Path>, r1cs: impl AsRef<Path>) -> io::Result<Self> {
        let wtns = WitnessCalculator::new(wtns).unwrap();
        let r1cs = load_r1cs(r1cs);
        Ok(Self {
            wtns,
            r1cs,
            sanity_check: false,
        })
    }
}
