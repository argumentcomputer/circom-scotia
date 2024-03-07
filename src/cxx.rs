use std::{
    collections::HashMap,
    ops::{BitAnd, Shl, Shr},
    path::Path,
};

use anyhow::Result;
use ff::PrimeField;
use rand::Rng;
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};

use crate::{
    error::CircomConfigError::{LoadR1CSError, WitnessCalculatorInstantiationError},
    r1cs::R1CS,
    reader::load_graph_binary,
};
use crate::{error::ReaderError::FilenameError, reader::load_r1cs};

#[derive(Hash, PartialEq, Eq, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Operation {
    Mul,
    MMul,
    Add,
    Sub,
    Eq,
    Neq,
    Lt,
    Gt,
    Leq,
    Geq,
    Lor,
    Shl,
    Shr,
    Band,
}

impl Operation {
    pub fn eval(&self, a: U256, b: U256, modulus: U256) -> U256 {
        use Operation::*;
        match self {
            Add => a.add_mod(b, modulus),
            Sub => a.add_mod(modulus - b, modulus),
            Mul => a.mul_mod(b, modulus),
            Eq => U256::from(a == b),
            Neq => U256::from(a != b),
            Lt => U256::from(a < b),
            Gt => U256::from(a > b),
            Leq => U256::from(a <= b),
            Geq => U256::from(a >= b),
            Lor => U256::from(a != U256::ZERO || b != U256::ZERO),
            Shl => compute_shl_uint(a, b),
            Shr => compute_shr_uint(a, b),
            Band => a.bitand(b),
            _ => unimplemented!("operator {:?} not implemented", self),
        }
    }
}

fn compute_shl_uint(a: U256, b: U256) -> U256 {
    debug_assert!(b.lt(&U256::from(256)));
    let ls_limb = b.as_limbs()[0];
    a.shl(ls_limb as usize)
}

fn compute_shr_uint(a: U256, b: U256) -> U256 {
    debug_assert!(b.lt(&U256::from(256)));
    let ls_limb = b.as_limbs()[0];
    a.shr(ls_limb as usize)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Node {
    Input(usize),
    Constant(U256),
    Op(Operation, usize, usize),
}

pub struct Graph<F: PrimeField> {
    r1cs: R1CS<F>,
    nodes: Vec<Node>,
    inputs: Vec<U256>,

    modulus: U256,
}

impl<F: PrimeField> Graph<F> {
    /// Create a new [`Graph`] instance.
    ///
    /// `wtns`: Path to the WASM file used for witness calculation.
    /// `r1cs`: Path to the R1CS file representing the circuit constraints.
    ///
    /// Returns a result containing the new [`CircomConfig`] instance or an error if the files
    /// cannot be loaded or parsed correctly.
    pub fn new(graph: impl AsRef<Path>, r1cs: impl AsRef<Path>) -> Result<Self> {
        let path_graph_string = graph.as_ref().to_str().ok_or(FilenameError)?.to_string();
        let path_r1cs_string = r1cs.as_ref().to_str().ok_or(FilenameError)?.to_string();

        let (nodes, inputs, hi) =
            load_graph_binary(&path_graph_string).map_err(|err| LoadR1CSError {
                path: path_graph_string,
                source: err.into(),
            })?;
        let r1cs = load_r1cs(r1cs).map_err(|err| LoadR1CSError {
            path: path_r1cs_string.clone(),
            source: err.into(),
        })?;
        let modulus = U256::from_str_radix(&F::MODULUS[2..], 16).map_err(|err| LoadR1CSError {
            path: path_r1cs_string,
            source: err.into(),
        })?;
        Ok(Self {
            r1cs,
            nodes,
            inputs,
            modulus,
        })
    }

    /// Evaluate the graph
    pub fn evaluate(&self) -> Vec<U256> {
        assert!(self.is_valid());

        // Evaluate the graph.
        let mut values = Vec::with_capacity(self.nodes.len());
        for (_, &node) in self.nodes.iter().enumerate() {
            let value = match node {
                Node::Constant(c) => c,
                Node::Input(i) => self.inputs[i],
                Node::Op(op, a, b) => op.eval(values[a], values[b], self.modulus),
            };
            values.push(value);
        }

        values
    }

    pub fn optimize(&mut self, outputs: &mut [usize]) {
        self.tree_shake(outputs);
        self.propagate();
        self.value_numbering(outputs);
        self.constants();
        self.tree_shake(outputs);
    }

    /// All references must be backwards.
    fn is_valid(&self) -> bool {
        for (i, &node) in self.nodes.iter().enumerate() {
            if let Node::Op(_, a, b) = node {
                if a >= i || b >= i {
                    return false;
                }
            }
        }
        true
    }

    /// Remove unused nodes
    pub fn tree_shake(&mut self, outputs: &mut [usize]) {
        assert!(self.is_valid());

        // Mark all nodes that are used.
        let mut used = vec![false; self.nodes.len()];
        for &i in outputs.iter() {
            used[i] = true;
        }

        // Work backwards from end as all references are backwards.
        for i in (0..self.nodes.len()).rev() {
            if used[i] {
                if let Node::Op(_, a, b) = self.nodes[i] {
                    used[a] = true;
                    used[b] = true;
                }
            }
        }

        // Remove unused nodes
        let n = self.nodes.len();
        let mut retain = used.iter();
        self.nodes.retain(|_| *retain.next().unwrap());
        let removed = n - self.nodes.len();

        // Renumber references.
        let mut renumber = vec![None; n];
        let mut index = 0;
        for (i, &used) in used.iter().enumerate() {
            if used {
                renumber[i] = Some(index);
                index += 1;
            }
        }
        assert_eq!(index, self.nodes.len());
        for node in self.nodes.iter_mut() {
            if let Node::Op(_, a, b) = node {
                *a = renumber[*a].unwrap();
                *b = renumber[*b].unwrap();
            }
        }
        for output in outputs.iter_mut() {
            *output = renumber[*output].unwrap();
        }

        eprintln!("Removed {removed} unused nodes");
    }

    /// Constant propagation
    pub fn propagate(&mut self) {
        assert!(self.is_valid());

        let mut constants = 0_usize;
        for i in 0..self.nodes.len() {
            if let Node::Op(op, a, b) = self.nodes[i] {
                if let (Node::Constant(va), Node::Constant(vb)) = (self.nodes[a], self.nodes[b]) {
                    self.nodes[i] = Node::Constant(op.eval(va, vb, self.modulus));
                    constants += 1;
                } else if a == b {
                    // Not constant but equal
                    use Operation::*;
                    if let Some(c) = match op {
                        Eq | Leq | Geq => Some(true),
                        Neq | Lt | Gt => Some(false),
                        _ => None,
                    } {
                        self.nodes[i] = Node::Constant(U256::from(c));
                        constants += 1;
                    }
                }
            }
        }

        eprintln!("Propagated {constants} constants");
    }

    /// Value numbering
    pub fn value_numbering(&mut self, outputs: &mut [usize]) {
        assert!(self.is_valid());

        // Evaluate the graph in random field elements.
        let values = self.random_eval();

        // Find all nodes with the same value.
        let mut value_map = HashMap::new();
        for (i, &value) in values.iter().enumerate() {
            value_map.entry(value).or_insert_with(Vec::new).push(i);
        }

        // For nodes that are the same, pick the first index.
        let mut renumber = Vec::with_capacity(self.nodes.len());
        for value in values {
            renumber.push(value_map[&value][0]);
        }

        // Renumber references.
        for node in self.nodes.iter_mut() {
            if let Node::Op(_, a, b) = node {
                *a = renumber[*a];
                *b = renumber[*b];
            }
        }
        for output in outputs.iter_mut() {
            *output = renumber[*output];
        }

        eprintln!("Global value numbering applied");
    }

    /// Probabilistic constant determination
    pub fn constants(&mut self) {
        assert!(self.is_valid());

        // Evaluate the graph in random field elements.
        let values_a = self.random_eval();
        let values_b = self.random_eval();

        // Find all nodes with the same value.
        let mut constants = 0;
        for i in 0..self.nodes.len() {
            if let Node::Constant(_) = self.nodes[i] {
                continue;
            }
            if values_a[i] == values_b[i] {
                self.nodes[i] = Node::Constant(values_a[i]);
                constants += 1;
            }
        }
        eprintln!("Found {} constants", constants);
    }

    /// Randomly evaluate the graph
    fn random_eval(&self) -> Vec<U256> {
        let mut rng = rand::thread_rng();
        let mut values = Vec::with_capacity(self.nodes.len());
        let mut inputs = HashMap::new();
        let mut prfs = HashMap::new();
        for node in self.nodes.iter() {
            use Operation::*;
            let value = match node {
                // Constants evaluate to themselves
                Node::Constant(c) => *c,

                // Algebraic Ops are evaluated directly
                // Since the field is large, by Swartz-Zippel if
                // two values are the same then they are likely algebraically equal.
                Node::Op(op @ (Add | Sub | Mul), a, b) => {
                    op.eval(values[*a], values[*b], self.modulus)
                }

                // Input and non-algebraic ops are random functions
                // TODO: https://github.com/recmo/uint/issues/95 and use .gen_range(..M)
                Node::Input(i) => *inputs
                    .entry(*i)
                    .or_insert_with(|| rng.gen::<U256>() % self.modulus),
                Node::Op(op, a, b) => *prfs
                    .entry((*op, values[*a], values[*b]))
                    .or_insert_with(|| rng.gen::<U256>() % self.modulus),
            };
            values.push(value);
        }
        values
    }
}
