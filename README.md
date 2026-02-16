# hekate-groestl

A high-throughput variant of the [Groestl](https://www.groestl.info/) permutation, re-engineered for
Arithmetic Circuits. It serves as the cryptographic backbone for the Hekate ZK Engine,
leveraging the linear properties of binary fields to minimize recursive GKR verifier
overhead while maximizing native CPU execution via SIMD intrinsics.

---

> **⚠️ SECURITY NOTICE**
>
> * Non-Standard: Not NIST-compliant. Do not use for general-purpose hashing.
> * Domain: Operates strictly over $GF(2^{128})$. Incompatible with standard Groestl-256.
> * Status: Research-grade software. Unaudited.

---

## Architecture

* **Compact State:** Uses a $4 \times 4$ matrix of $GF(2^{128})$ elements. Total state size is 256 bytes (2048
  bits), fitting entirely within CPU registers for maximum register renaming efficiency.
* **Algebraic S-Box:** Uses an Itoh-Tsujii addition chain to compute $S(x) = x^{127} + 0x63$.
  This provides a maximal algebraic degree of 127 while maintaining a constant GKR depth of
  6 layers via fused `SquareAndMul` gates.
* **Hardware Acceleration:** With `Block128` it leverages `PMULL` (ARM) and `PCLMULQDQ` (x86)
  instructions for single-cycle field multiplication.
* **ZK-Friendly MDS:** Utilizes a custom MDS matrix `[1, 1, 2, 3]` with small coefficients to minimize linear
  constraint depth.

### Hakete Groestl != NIST Groestl

| Feature    | Standard Groestl-256    | Hekate Groestl                      |
|:-----------|:------------------------|:------------------------------------|
| Domain     | $GF(2^8)$ (Bytes)       | $GF(2^{128})$                       |
| State Size | 64 bytes (512 bits)     | 256 bytes (2048 bits)               |
| S-Box      | $x^{-1}$ in $GF(2^8)$   | $x^{127} + c$ in $GF(2^{128})$      |
| MDS Matrix | $8 \times 8$ (Branch 9) | $4 \times 4$ (Branch 5)             |
| Padding    | Bit-padding             | Field Padding (`0x80` Tag + Length) |

## Installation

```toml
[dependencies]
hekate-groestl = { git = "https://github.com/oumuamua-corp/hekate-groestl" }
```

## Usage

Ensure your field implementation supports hardware intrinsics for performance.

**CRITICAL NOTE:** Hekate Groestl arithmetic (S-Box, MDS) is optimized for the Hardware (Flat) Basis
using `PMULL`/`PCLMULQDQ`. You **MUST** convert your standard Tower Field elements to Hardware Basis
before hashing and convert the result back. If you skip this, the hardware instructions will interpret
the bits of your Tower element as a polynomial in the Flat basis, producing mathematically meaningless
results (garbage) without raising any runtime errors.

```rust
use hekate_groestl::Hasher;
use hekate_math::{Block128, HardwareField};

#[test]
fn main() {
    let mut hasher = Hasher::new();

    // 1. PREPARE INPUT
    // You must project our "human-readable" Tower elements into
    // the Hardware (Flat) basis where the S-Box math lives.
    //
    // WARNING: If you omit .to_hardware(), the hasher will
    // silently compute incorrect algebraic results!
    let input_tower = [
        Block128::from(0xDEAD_BEEF_u64),
        Block128::from(0xCAFE_BABE_u64),
    ];
    let input_flat = input_tower.map(|x| x.to_hardware());

    // 2. UPDATE
    hasher.update_elements(&input_flat);

    // 3. FINALIZE
    // Returns [Low, High] parts in Hardware Basis.
    let [raw_lo, raw_hi] = hasher.finalize_raw();

    println!("Hash (Flat Basis): {:?} {:?}", raw_lo, raw_hi);

    // 4. CONVERT BACK
    // Project the result back to the canonical Tower basis to use
    // in the rest of your application or for verification.
    let digest_lo = raw_lo.convert_hardware();
    let digest_hi = raw_hi.convert_hardware();

    println!("Hash (Tower Basis): {:?} {:?}", digest_lo, digest_hi);
}
```

## Implementation Details

The core permutation follows the SP-Network design:

1. **AddRoundConstant:** XOR round constants.
2. **SubBytes:** Applies $x \mapsto x^{127} + 0x63$ (High-degree Itoh-Tsujii S-Box).
3. **ShiftBytes:** Column rotation for diffusion.
4. **MixBytes:** Column-wise multiplication by MDS matrix `[1, 1, 2, 3]`.

Security Note: To prevent length extension attacks, a strict padding scheme
(Tag `0x80` + Zero Fill + `u64` Length) is enforced before the final permutation.

## Performance

Performance comparison against standard cryptographic primitives.
Hekate Groestl runs on the `Block128` hardware backend (NEON/PMULL).

| Primitive        | Field           | Latency (Permutation) | Throughput (Merkle) | Throughput (Bulk) |
|:-----------------|:----------------|:----------------------|:--------------------|:------------------|
| Hekate Groestl   | $GF(2^{128})$   | 4.05 µs               | ~164 K/s            | ~31.2 MiB/s       |
| Miden RPO        | $F_p$ (64-bit)  | 3.00 µs               | ~337 K/s            | ~20.5 MiB/s       | 
| Poseidon (BN254) | $F_p$ (254-bit) | 18.74 µs              | ~52 K/s             | ~3.2 MiB/s        | 

> **Optimization Note:**
> * The Merkle throughput listed above (~164 K/s) uses the standard padded sponge API for maximum security.
> * 2-to-1 Compression (Node): Using the dedicated compression function achieves ~250 K/s.
> * Raw PRP (No Padding): For specialized circuits, the raw permutation throughput
    reaches ~500 K/s, exceeding Miden RPO in raw element processing.

*Benchmarks reproduced via `cargo bench`.*

### GKR Gadget

While `hekate-groestl` is open-source, it is designed to be the native hash for the
proprietary [Hekate ZK Engine](https://github.com/oumuamua-corp/hekate). Below are
the proving metrics when integrated into a streaming GKR prover on consumer hardware (Apple M3 Max).

| Metric           | Value           | Impact                                                                |
|:-----------------|:----------------|:----------------------------------------------------------------------|
| Proving Latency  | ~1.85 ms / hash | Sub-2ms proving time per invocation (Batch: 4096).                    |
| Algebraic Degree | 127             | Maximum non-linearity for security against algebraic attacks.         |
| Circuit Depth    | 6 Layers        | Constant depth via fused `SquareAndMul` gates, independent of degree. |
| RAM Overhead     | O(log N)        | Minimal memory footprint due to GKR streaming architecture.           |

> **Note:** These benchmarks reflect the efficiency of the primitive inside a specialized GKR circuit.
> Performance in generic R1CS/PlonK systems may vary due to the lack of native binary field support.

## License

This project is licensed under the Apache 2.0 License. See [LICENSE](./LICENSE) for details.

