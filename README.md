# Circom Scotia

### Middleware to compile [Circom](https://github.com/iden3/circom) circuits to [Bellperson](https://github.com/filecoin-project/bellperson)

![rose-pattern-porcelain-white-background](assets/rose-pattern-porcelain.jpg)

This repository provides necessary middleware to take generated output of the Circom compiler (R1CS constraints and generated witnesses) and use them with Bellperson. It is based off the work of [Nova-Scotia](https://github.com/nalinbhardwaj/Nova-Scotia) and Arkworks' [Circom-Compat](https://github.com/arkworks-rs/circom-compat). Please see **Credits** at the bottom for proper credits towards the various works used here.

## How?

To use it yourself, install version 2.1.6 of greater of [Circom](https://docs.circom.io). Refer to the [Circom documentation](https://docs.circom.io/getting-started/installation/#installing-dependencies) for more information.

When you're ready, compile your circuit using `circom [file].circom --r1cs --wasm --prime vesta` for the vesta curve. We will later use the R1CS file (`[file].r1cs`) and the witness generator (`[file]_js/[file].wasm`), so make note of their filepaths. You can independently test these circuits by running witness generation as described in the [Circom documentation](https://docs.circom.io/getting-started/computing-the-witness/).

Now, start a new Rust project and add Circom Scotia (`cargo add circom-scotia`) to your dependencies. Then, you can start using your Circom circuits with Bellperson. Start by defining the paths to the Circom output and loading the R1CS file and witness generator:

```rust
let root = current_dir().unwrap().join("examples/sha256");
let wtns = root.join("sha256.wasm");
let r1cs = root.join("sha256.r1cs");

let cfg = CircomConfig::new(wtns, r1cs).unwrap();
```

Then, create the inputs, which must be in the shape that the original Circom project expected them to be in, and calculate the witness. The original Circom input would've looked something like this:

```json
{ "arg_in": ["a", "b"] }
```

So, we reflect the same names and dimensions of input. The witness can then be calculated by providing the loaded configuration and the input.

```rust
let arg_in = ("arg_in".into(), vec![Fr::ZERO, Fr::ZERO]);
let input = vec![arg_in];

let witness = calculate_witness(&cfg, input, true).unwrap();
```

Now, setup a test constraint system, and synthesize the generated witness with the `r1cs` information we previously loaded.

```rust
let mut cs = TestConstraintSystem::<Fr>::new();

let output = synthesize(
    &mut cs.namespace(|| "sha256_circom"),
    cfg.r1cs.clone(),
    Some(witness),
);
```

Finally, we can compare our expected output and confirm that the circuit is indeed satisfied. 

```rust
let expected = "0x00000000008619b3767c057fdf8e6d99fde2680c5d8517eb06761c0878d40c40";
let output_num = format!("{:?}", output.unwrap().get_value().unwrap());

assert!(output_num == expected);
assert!(cs.is_satisfied());
```

For the full code, see the [`sha256.rs`](https://github.com/lurk-lab/circom-scotia/blob/main/examples/sha256.rs) example.

## Notes for interested contributors

### TODO list

- [ ] Generic big integers were replaced by `U256`, so currently we do not generalize to prime field of size greater than 256 bits.


### Credits

Credits to the [Circom language](https://github.com/iden3/circom) from the iden3 team.

The parsing and generation borrows judiciously from [Nova-Scotia](https://github.com/nalinbhardwaj/Nova-Scotia) and [ark-circom](https://github.com/gakonst/ark-circom), respectively. All the loading code is essentially copied over. The `wasmer` witness generator was copied, then retrofitted for support without `arkworks` libraries such as `ark-ff` or `ark-bignum`; these were replaced with `ff` and `crypto-bignum`. The other bits that glue everything together is original.

