use bellperson::gadgets::num::AllocatedNum;
use nova_snark::traits::circuit::StepCircuit;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::str;

use bellperson::{ConstraintSystem, LinearCombination, SynthesisError};
use ff::PrimeField;

#[derive(Serialize, Deserialize)]
pub struct CircuitJson {
    pub constraints: Vec<Vec<BTreeMap<String, String>>>,
    #[serde(rename = "nPubInputs")]
    pub num_inputs: usize,
    #[serde(rename = "nOutputs")]
    pub num_outputs: usize,
    #[serde(rename = "nVars")]
    pub num_variables: usize,
}

pub type Constraint<F> = (Vec<(usize, F)>, Vec<(usize, F)>, Vec<(usize, F)>);

#[derive(Clone)]
pub struct R1CS<F: PrimeField> {
    pub num_inputs: usize,
    pub num_aux: usize,
    pub num_variables: usize,
    pub constraints: Vec<Constraint<F>>,
}

#[derive(Clone)]
pub struct CircomCircuit<F: PrimeField> {
    pub r1cs: R1CS<F>,
    pub witness: Option<Vec<F>>,
    // debug symbols
}

impl<'a, F: PrimeField> CircomCircuit<F> {
    pub fn get_public_outputs(&self) -> Vec<F> {
        // NOTE: assumes exactly half of the (public inputs + outputs) are outputs
        let pub_output_count = (self.r1cs.num_inputs - 1) / 2;
        let mut z_out: Vec<F> = vec![];
        for i in 1..self.r1cs.num_inputs {
            // Public inputs do not exist, so we alloc, and later enforce equality from z values
            let f: F = {
                match &self.witness {
                    None => F::ONE,
                    Some(w) => w[i],
                }
            };

            if i <= pub_output_count {
                // public output
                z_out.push(f);
            }
        }

        z_out
    }

    pub fn vanilla_synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        // println!("witness: {:?}", self.witness);
        // println!("wire_mapping: {:?}", self.wire_mapping);
        // println!("aux_offset: {:?}", self.aux_offset);
        // println!("num_inputs: {:?}", self.r1cs.num_inputs);
        // println!("num_aux: {:?}", self.r1cs.num_aux);
        // println!("num_variables: {:?}", self.r1cs.num_variables);
        // println!("constraints: {:?}", self.r1cs.constraints);
        // println!(
        //     "z: {:?}",
        //     z.into_iter().map(|x| x.get_value()).collect::<Vec<_>>()
        // );

        let witness = &self.witness;

        let mut vars: Vec<AllocatedNum<F>> = vec![];
        let mut z_out: Vec<AllocatedNum<F>> = vec![];
        let pub_output_count = (self.r1cs.num_inputs - 1) / 2;

        for i in 1..self.r1cs.num_inputs {
            // Public inputs do not exist, so we alloc, and later enforce equality from z values
            let f: F = {
                match witness {
                    None => F::ONE,
                    Some(w) => w[i],
                }
            };
            let v = AllocatedNum::alloc(cs.namespace(|| format!("public_{}", i)), || Ok(f))?;

            vars.push(v.clone());
            if i <= pub_output_count {
                // public output
                z_out.push(v);
            }
        }
        for i in 0..self.r1cs.num_aux {
            // Private witness trace
            let f: F = {
                match witness {
                    None => F::ONE,
                    Some(w) => w[i + self.r1cs.num_inputs],
                }
            };

            let v = AllocatedNum::alloc(cs.namespace(|| format!("aux_{}", i)), || Ok(f))?;
            vars.push(v);
        }

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
        for (i, constraint) in self.r1cs.constraints.iter().enumerate() {
            cs.enforce(
                || format!("constraint {}", i),
                |_| make_lc(constraint.0.clone()),
                |_| make_lc(constraint.1.clone()),
                |_| make_lc(constraint.2.clone()),
            );
        }

        for i in (pub_output_count + 1)..self.r1cs.num_inputs {
            cs.enforce(
                || format!("pub input enforce {}", i),
                |lc| lc + z[i - 1 - pub_output_count].get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + vars[i - 1].get_variable(),
            );
        }

        Ok(z_out)
    }
}

impl<'a, F: PrimeField> StepCircuit<F> for CircomCircuit<F> {
    fn arity(&self) -> usize {
        (self.r1cs.num_inputs - 1) / 2
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        // synthesize the circuit
        let z_out = self.vanilla_synthesize(cs, z);

        z_out
    }

    fn output(&self, _z: &[F]) -> Vec<F> {
        self.get_public_outputs()
    }
}
