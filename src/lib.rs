use color_eyre::Result;
use bellperson::{ConstraintSystem, gadgets::num::AllocatedNum, SynthesisError, LinearCombination};
use ff::PrimeField;
use r1cs::R1CS;
use witness::WitnessCalculator;

pub mod r1cs;
pub mod reader;
pub mod witness;

pub fn calculate_witness<F: PrimeField, I: IntoIterator<Item = (String, Vec<F>)>>(
    witness_calculator: &mut WitnessCalculator,
    inputs: I,
    sanity_check: bool,
) -> Result<Vec<F>> {
    witness_calculator.calculate_witness(inputs, sanity_check)
}

/// Reference work is Nota-Scotia: https://github.com/nalinbhardwaj/Nova-Scotia
pub fn synthesize<F: PrimeField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    r1cs: R1CS<F>,
    witness: Option<Vec<F>>,
) -> Result<AllocatedNum<F>, SynthesisError> {
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

    Ok(output)
}
