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
* **Algebraic S-Box:** Replaces the AES S-Box with the power map $S(x) = x^{254} + 0x63$. In characteristic-2 fields,
  this decomposes into cheap linear squaring operations in GKR circuits.
* **Hardware Acceleration:** Generic over `TowerFieldElement`. When used with `Block128`, it leverages `PMULL` (ARM) and
  `PCLMULQDQ` (x86) instructions for single-cycle field multiplication.
* **ZK-Friendly MDS:** Utilizes a custom MDS matrix `[1, 1, 2, 3]` with small coefficients to minimize linear
  constraint depth.

### Hakete Groestl != NIST Groestl

| Feature    | Standard Groestl-256    | Hekate-Groestl V2                   | Rationale                    |
|:-----------|:------------------------|:------------------------------------|:-----------------------------|
| Domain     | $GF(2^8)$ (Bytes)       | $GF(2^{128})$                       | Circuit Efficiency           |
| State Size | 64 bytes (512 bits)     | 256 bytes (2048 bits)               | Capacity / Security          |
| S-Box      | $x^{-1}$ in $GF(2^8)$   | $x^{254} + c$ in $GF(2^{128})$      | GKR Arithmetization          |
| MDS Matrix | $8 \times 8$ (Branch 9) | $4 \times 4$ (Branch 5)             | L1 Cache / Register Pressure |
| Padding    | Bit-padding             | Field Padding (`0x80` Tag + Length) | Length Extension Defense     |

## Installation

```toml
[dependencies]
hekate-groestl = { git = "https://github.com/oumuamua-corp/hekate-groestl" }
```

## Usage

Ensure your field implementation supports hardware intrinsics for performance.

```rust
use hekate_groestl::{HekateGroestl, TowerFieldElement};

// Assuming Block128 implements TowerFieldElement
type F = Block128;

fn main() {
    // Initialize (12 rounds recommended for 4x4 matrix)
    let mut hasher = HekateGroestl::<F>::new(12);

    // Update with Native Field Elements
    let input = [F::from(0xDEAD_BEEF_u64), F::from(0xCAFE_BABE_u64)];
    hasher.update_elements(&input);

    // Finalize to 256-bit Digest (2 x Block128)
    // Returns [Low, High] parts for 128-bit collision resistance.
    let [digest_lo, digest_hi] = hasher.finalize_raw();

    println!("Hash: {:?} {:?}", digest_lo, digest_hi);
}
```

## Implementation Details

The core permutation follows the SP-Network design:

1. **AddRoundConstant:** XOR round constants.
2. **SubBytes:** Applies $x \mapsto x^{254} + 0x63$ (Native Field S-Box).
3. **ShiftBytes:** Column rotation for diffusion.
4. **MixBytes:** Column-wise multiplication by MDS matrix `[1, 1, 2, 3]`.

Security Note: To prevent length extension attacks, a strict padding scheme
(Tag `0x80` + Zero Fill + `u64` Length) is enforced before the final permutation.

## Performance

Performance comparison against standard cryptographic primitives.
Hekate Groestl runs on the `Block128` hardware backend (NEON/PMULL).

| Primitive             | Field           | Latency (Permutation) | Throughput (Merkle) | Speedup Factor  |
|:----------------------|:----------------|:----------------------|:--------------------|:----------------|
| Hekate-Groestl        | $GF(2^{128})$   | 3.8 µs                | ~187 K/s            | 1.0x (Baseline) |
| Miden RPO             | $F_p$ (64-bit)  | 3.00 µs               | ~337 K/s            | ~1.8x Faster    | 
| Poseidon (BN254)      | $F_p$ (254-bit) | 18.74 µs              | ~52 K/s             | ~3.6x Slower    | 
| MockBlock128 (Scalar) | $GF(2^{128})$   | 309.0 µs              | 2.1 K/s             | Slow Fallback   |

> Optimization Note: The Merkle throughput for Hekate uses the standard padded sponge API.
> Using a dedicated 2-to-1 compression function (without padding) is expected to double this rate,
> bringing it closer to raw permutation latency (~260 K/s).

## License

This project is licensed under the Apache 2.0 License. See [LICENSE](./LICENSE) for details.

