# Circom Scotia

### Middleware to compile [Circom](https://github.com/iden3/circom) circuits to [Nova](https://github.com/microsoft/Nova) prover

![roses-rose-pattern-porcelain-white-background-555e78a5593799197d0f9a5c4e3ba32d](https://github.com/lurk-lab/circom-scotia/assets/76727734/99f20cf5-5371-48ef-8dee-ff2b8526b761)

This repository provides necessary middleware to take generated output of the Circom compiler (R1CS constraints and generated witnesses) and use them with Bellperson. It is based off the work of [Nova-Scotia](https://github.com/nalinbhardwaj/Nova-Scotia) and Arkworks' [Circom-Compat](https://github.com/arkworks-rs/circom-compat).

## How?

To use it yourself, install version 2.1.6 of greater of [Circom](https://docs.circom.io). To install this branch, clone the git repo (using `git clone https://github.com/nalinbhardwaj/circom.git && git checkout pasta`). Then build and install the `circom` binary by running `cargo install --path circom`. This will overwrite any existing `circom` binary. Refer to the [Circom documentation](https://docs.circom.io/getting-started/installation/#installing-dependencies) for more information.

When you're ready, compile your circuit using `circom [file].circom --r1cs --wasm --prime vesta` for the vesta curve. We will later use the R1CS file and the witness generator, so make note of their filepaths. You can independently test these step circuits by running witness generation as described in the [Circom documentation](https://docs.circom.io/getting-started/computing-the-witness/).

Now, start a new Rust project and add Nova Scotia to your dependencies. Then, you can start using your Circom circuits with Bellperson. Start by defining the paths to the Circom output and loading the R1CS file:

```rust


let circuit_file = root.join("examples/bitcoin/circom/bitcoin_benchmark.r1cs");
let witness_generator_file =
    root.join("examples/bitcoin/circom/bitcoin_benchmark_cpp/bitcoin_benchmark");

let r1cs = load_r1cs(&circuit_file); // loads R1CS file into memory
```

Circom supports witness generation using both C++ and WASM, so you can choose which one to use by passing `witness_generator_file` either as the generated C++ binary or as the WASM output of Circom (the `circuit.wasm` file). If you use WASM, we assume you have a compatible version of `node` installed on your system.

Then, create the public parameters (CRS) using the `create_public_params` function:

```rust
let pp = create_public_params(r1cs.clone());
```

Now, construct the input to Circom witness generator at each step of recursion. This is a HashMap representation of the JSON input to your Circom input. For instance, in the case of the [bitcoin](https://github.com/nalinbhardwaj/Nova-Scotia/blob/main/examples/bitcoin.rs#L40) example, `private_inputs` is a list of `HashMap`s, each containing block headers and block hashes for the blocks that step of recursion verifies, and the public input `step_in` is the previous block hash in the chain.

To instantiate this recursion, we use `create_recursive_circuit` from Nova Scotia:

```rust
let recursive_snark = create_recursive_circuit(
    witness_generator_file,
    r1cs,
    private_inputs,
    start_public_input.clone(),
    &pp,
).unwrap();
```

Verification is done using the `verify` function defined by Nova, which additionally takes secondary inputs that Nova Scotia will initialise to `vec![<G2 as Group>::Scalar::zero()]`, so just pass that in:

```rust
println!("Verifying a RecursiveSNARK...");
let start = Instant::now();
let res = recursive_snark.verify(
    &pp,
    iteration_count,
    start_public_input.clone(),
    vec![<G2 as Group>::Scalar::zero()],
);
println!(
    "RecursiveSNARK::verify: {:?}, took {:?}",
    res,
    start.elapsed()
);
let verifier_time = start.elapsed();
assert!(res.is_ok());
```

For proper examples and more details, see the `toy.rs` and the `bitcoin.rs` examples documented below:

### [`toy.rs`](https://github.com/nalinbhardwaj/Nova-Scotia/blob/main/examples/toy.rs)

toy.rs is a [very simple toy step circuit](https://github.com/nalinbhardwaj/Nova-Scotia/blob/main/examples/toy/toy.circom) meant for testing purposes. It is helpful to start by looking at its Circom code and the Rust code that instantiates it in Nova. It is a simple variant of fibonacci that additionally takes a private input to add at each step.

### [`bitcoin.rs`](https://github.com/nalinbhardwaj/Nova-Scotia/blob/main/examples/bitcoin.rs)

bitcoin.rs is a more complex example that uses Nova to create a prover for bitcoin chain proof-of-work. For nearly the cost of just one block proof-of-work verification, Nova can compress the verification of the entire bitcoin chain. [The Circom circuit is more complex](https://github.com/nalinbhardwaj/Nova-Scotia/blob/main/examples/bitcoin/circom/bitcoin.circom) for this construction (since it runs hashing and other bit-twiddling to verify each block in ~150k constraints). This is also helpful to look at for [benchmarking](https://github.com/nalinbhardwaj/Nova-Scotia/blob/main/examples/bitcoin.rs#L23) purposes, since you can play around with the number of blocks verified in each step of recursion. Here are some simple benchmarks for different configurations of recursion for 120 blocks being proven and verified:

| Number of recursion steps | Blocks verified per step | Prover time | Verifier time (uncompressed) |
| ------------------------- | ------------------------ | ----------- | ---------------------------- |
| 120                       | 1                        | 57.33s      | 197.20ms                     |
| 60                        | 2                        | 46.11s      | 307.08ms                     |
| 40                        | 3                        | 43.60s      | 449.02ms                     |
| 30                        | 4                        | 41.17s      | 560.53ms                     |
| 24                        | 5                        | 39.73s      | 728.09ms                     |

Note that the verification times are linear in the number of blocks per step of recursion, while the proving time reduces with fewer recursive steps. In practice, you would use the output of Nova as an input to another SNARK scheme like Plonk/groth16 (as previously mentioned) to obtain full succinctness.

Additionally, these are numbers on my (not great) laptop, so you should expect better performance on a beefier machine, especially because Nova supports GPU accelerated MSMs for proving under the hood.

## In-browser proving and verification

Nova Scotia also supports proving and verification of proofs in browser, along with serde of proofs and public parameters. We provide an example of in-browser proving using Rust compiled to WASM in the [`browser-test`](https://github.com/nalinbhardwaj/Nova-Scotia/tree/main/browser-test) folder of the repository. The [`test-client`](https://github.com/nalinbhardwaj/Nova-Scotia/tree/main/browser-test/test-client) in the folder is a Create React App demonstrating in-browser proving and verification. If you are interested in similar usage, please look through the folders to understand how they work. It may also be useful to look at the [halo2 guide to WASM compiling](https://zcash.github.io/halo2/user/wasm-port.html).

![image](https://user-images.githubusercontent.com/6984346/216265979-5a7e3081-5211-4327-a12b-5fb3178d1016.png)

## Notes for interested contributors

### TODO list

- [ ] Switch Nova to BN254/grumpkin cycle to make it work on Ethereum chain! This should be doable since Nova only needs DLOG hardness.
- [ ] Write Relaxed R1CS verifiers in plonk/groth16 libraries (ex. Halo 2, Circom).
- [ ] Make Nova work with secp/secq cycle for efficient ECDSA signature verification + aggregation

Seperately, since Nova's `StepCircuit` trait is pretty much the same as Bellperson's `Circuit` trait, we can probably also use the transpilation in this repo to use [Bellperson](https://github.com/filecoin-project/bellperson) with Circom circuits/proofs, along with its [snarkpack](https://eprint.iacr.org/2021/529) aggregation features.

If you are interested in any of these tasks and want to work on them, please reach out! [0xPARC's PARC Squad](https://0xparc.org/blog/parc-squad) may also be able to provide financial and technical support for related work.

### Credits

Credits to the original [Nova implementation and paper](https://github.com/microsoft/Nova) by Srinath Setty/Microsoft Research, and the [Circom language](https://github.com/iden3/circom) from the iden3 team.

The parsing and generation strongly borrows from other similar repos like [plonkit](https://github.com/Fluidex/plonkit), [ark-circom](https://github.com/gakonst/ark-circom), [zkutil](https://github.com/poma/zkutil) etc.

I have never been to Nova Scotia. This repo is named Nova Scotia because crypto already has [Tornado Cash Nova](https://tornado-cash.medium.com/tornado-cash-introduces-arbitrary-amounts-shielded-transfers-8df92d93c37c) and [Arbitrum Nova](https://nova.arbitrum.io) besides Microsoft Nova, so its time we start adding suffixes to the term to maximize confusion around it.

The art at the top of the page is by [Tadashi Moriyama](https://www.tadashimoriyama.com/portfolio?pgid=jy5bsm8q-ddbca395-1a1d-4936-a014-a924a5ca4e1e), all credits to him. I'm just a fan of it. :)
