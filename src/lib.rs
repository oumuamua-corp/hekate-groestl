#![no_std]

mod field;

use digest::{FixedOutput, HashMarker, Output, OutputSizeUser, typenum::U32};

pub use digest::{Reset, Update};
pub use field::TowerFieldElement;

#[cfg(any(test, feature = "test-utils"))]
pub use field::mock::MockBlock128;

pub const STATE_SIZE: usize = 16;

/// MixBytes coefficients (MDS Matrix).
pub const MIX_P: [u8; 4] = [0x01, 0x01, 0x02, 0x03];

// Permutation shift offsets for 4x4

/// Standard cyclic [0, 1, 2, 3].
pub const SHIFT_P: [usize; 4] = [0, 1, 2, 3];

/// Inverse cyclic [1, 3, 2, 0] to maximize diffusion distance.
pub const SHIFT_Q: [usize; 4] = [1, 3, 2, 0];

/// S-Box Affine Constant.
pub const SBOX_C: u64 = 0x63;

/// Padding Separator.
pub const PADDING_TAG: u64 = 0x80;

/// A Generic Hekate Groestl Hasher. Adapts the field-based
/// arithmetic to the byte-oriented `Digest` trait by
/// treating input bytes as individual field elements.
#[derive(Clone, Debug)]
pub struct HekateGroestl<F: TowerFieldElement> {
    state: [F; STATE_SIZE],
    buffer: [F; STATE_SIZE],
    total_len: u64,
    buf_len: usize,
    rounds: usize,
}

impl<F: TowerFieldElement> Default for HekateGroestl<F> {
    fn default() -> Self {
        Self {
            state: [F::default(); STATE_SIZE],
            buffer: [F::default(); STATE_SIZE],
            total_len: 0,
            buf_len: 0,
            rounds: 12,
        }
    }
}

impl<F: TowerFieldElement> HekateGroestl<F> {
    pub fn new(rounds: usize) -> Self {
        Self {
            rounds,
            ..Default::default()
        }
    }

    /// Direct field element update (bypassing byte conversion).
    pub fn update_elements(&mut self, input: &[F]) {
        for &elem in input {
            // Convert Input (Tower) -> State (Flat)
            self.buffer[self.buf_len] = elem.to_flat();
            self.buf_len += 1;
            self.total_len += 1;

            if self.buf_len == STATE_SIZE {
                compress(&mut self.state, &self.buffer, self.rounds);

                self.buf_len = 0;
            }
        }
    }

    /// Emulates the Transcript Sponge Squeeze behavior.
    /// Uses Secure Padding (Tag + Length) to prevent
    /// extension attacks.
    pub fn squeeze_sponge(&mut self) -> F {
        self.buffer[self.buf_len] = F::from(PADDING_TAG);
        self.buf_len += 1;

        if self.buf_len > STATE_SIZE - 1 {
            // Fill rest with zeros, compress, then start fresh
            for i in self.buf_len..STATE_SIZE {
                self.buffer[i] = F::default();
            }

            compress(&mut self.state, &self.buffer, self.rounds);

            self.buf_len = 0;
        }

        // Fill Zeros up to the last element
        for i in self.buf_len..(STATE_SIZE - 1) {
            self.buffer[i] = F::default();
        }

        self.buffer[STATE_SIZE - 1] = F::from(self.total_len);

        // Compress the Padding Block
        compress(&mut self.state, &self.buffer, self.rounds);

        // Reset buffer for future absorbs (Sponge continues)
        self.buf_len = 0;

        // =======================================
        // Hash Chain Logic (Permutation + Fold)
        // =======================================

        // A. Run P-Permutation on current state
        // S_next = P(S_curr)
        let mut s_next = self.state;
        permutation(&mut s_next, false, self.rounds);

        // B. Output Transform: T = S_next ^ S_curr
        let mut transformed = [F::default(); STATE_SIZE];
        for i in 0..STATE_SIZE {
            transformed[i] = s_next[i] + self.state[i];
        }

        // C. Update Internal State -> S_next
        self.state = s_next;

        // D. Folding (XOR Reduce T from 64 -> 1)
        let mut reduce_buf = transformed;
        let mut len = STATE_SIZE;

        while len > 1 {
            let half = len / 2;
            for i in 0..half {
                reduce_buf[i] += reduce_buf[i + half];
            }

            len = half;
        }

        reduce_buf[0]
    }
}

/// RustCrypto trait implementation
/// Maps [u8] -> [F] 1:1.
impl<F: TowerFieldElement> Update for HekateGroestl<F> {
    fn update(&mut self, data: &[u8]) {
        for &b in data {
            // Convert byte -> Tower Field -> Flat Field
            self.buffer[self.buf_len] = F::from(b as u64).to_flat();
            self.buf_len += 1;
            self.total_len += 1;

            if self.buf_len == STATE_SIZE {
                compress(&mut self.state, &self.buffer, self.rounds);

                self.buf_len = 0;
            }
        }
    }
}

impl<F: TowerFieldElement> OutputSizeUser for HekateGroestl<F> {
    type OutputSize = U32; // 256-bit output (2 x Block128)
}

impl<F: TowerFieldElement> FixedOutput for HekateGroestl<F> {
    fn finalize_into(self, out: &mut Output<Self>) {
        let result_elements = self.finalize_raw();

        let bytes0 = result_elements[0].to_bytes();
        let bytes1 = result_elements[1].to_bytes();

        out[0..16].copy_from_slice(&bytes0);
        out[16..32].copy_from_slice(&bytes1);
    }
}

impl<F: TowerFieldElement> HekateGroestl<F> {
    /// Finalize and return 2 field elements (256 bits).
    /// Returns [HashLow, HashHigh].
    pub fn finalize_raw(self) -> [F; 2] {
        let mut final_hasher = self;

        // Append Padding Tag
        final_hasher.buffer[final_hasher.buf_len] = F::from(PADDING_TAG).to_flat();
        final_hasher.buf_len += 1;

        if final_hasher.buf_len > STATE_SIZE - 1 {
            // Fill the rest with zeros and compress
            for i in final_hasher.buf_len..STATE_SIZE {
                final_hasher.buffer[i] = F::default();
            }

            compress(
                &mut final_hasher.state,
                &final_hasher.buffer,
                final_hasher.rounds,
            );

            // Start a new fresh block
            final_hasher.buffer = [F::default(); STATE_SIZE];
            final_hasher.buf_len = 0;
        }

        // Fill Zeros up to the last element
        for i in final_hasher.buf_len..(STATE_SIZE - 1) {
            final_hasher.buffer[i] = F::default();
        }

        // Append Total Length
        final_hasher.buffer[STATE_SIZE - 1] = F::from(final_hasher.total_len).to_flat();

        // Final Compress
        compress(
            &mut final_hasher.state,
            &final_hasher.buffer,
            final_hasher.rounds,
        );

        // Output Transform: T = P(S) ^ S
        let transformed = output_transform(&final_hasher.state, final_hasher.rounds);

        // Folding
        let mut reduce_buf = transformed;
        let mut len = STATE_SIZE;

        while len > 1 {
            let half = len / 2;
            for i in 0..half {
                reduce_buf[i] += reduce_buf[i + half];
            }

            len = half;
        }

        // Convert Final State (Flat) -> Output (Tower)
        // Return the first two accumulators.
        [reduce_buf[0].from_flat(), reduce_buf[1].from_flat()]
    }
}

impl<F: TowerFieldElement> HashMarker for HekateGroestl<F> {}

impl<F: TowerFieldElement> Reset for HekateGroestl<F> {
    fn reset(&mut self) {
        self.state = [F::default(); STATE_SIZE];
        self.buf_len = 0;
        self.total_len = 0;
    }
}

/// The core compression function:
/// f(h, m) = P(h^m) ^ Q(m) ^ h
#[inline(always)]
pub fn compress<F: TowerFieldElement>(h: &mut [F; STATE_SIZE], m: &[F; STATE_SIZE], rounds: usize) {
    let mut p_in = [F::default(); STATE_SIZE];
    for i in 0..STATE_SIZE {
        p_in[i] = h[i] + m[i];
    }

    let mut q_in = *m;
    permutation(&mut p_in, false, rounds);
    permutation(&mut q_in, true, rounds);

    // Update State:
    // h_next = P(h^m) ^ Q(m) ^ h_prev
    for i in 0..STATE_SIZE {
        h[i] = p_in[i] + q_in[i] + h[i];
    }
}

/// Core Groestl Permutation (P/Q).
/// Executes the Hekate Groestl round function.
#[inline(always)]
pub fn permutation<F: TowerFieldElement>(state: &mut [F; STATE_SIZE], is_q: bool, rounds: usize) {
    let shifts = if is_q { &SHIFT_Q } else { &SHIFT_P };
    let mut temp = [F::default(); STATE_SIZE];

    for round in 0..rounds {
        // A. AddRoundConstant
        for i in 0..STATE_SIZE {
            // Layout is 4x4 now
            let row = i / 4;
            let col = i % 4;

            // Target row for constant injection
            let target_row = if is_q { 3 } else { 0 };

            if row == target_row {
                let rc = if is_q {
                    (((col as u8) ^ 0x08) << 4) ^ 0xFF ^ (round as u8)
                } else {
                    ((col as u8) << 4) ^ (round as u8)
                };

                state[i] += F::from(rc as u64).to_flat();
            }
        }

        // B. SubBytes (Native S-Box)
        let mut i = 0;
        while i < STATE_SIZE {
            F::batch_sbox_flat(&mut state[i..i + 4]);
            i += 4;
        }

        // C. ShiftBytes (4x4)
        temp.copy_from_slice(state);

        for r in 0..4 {
            for c in 0..4 {
                let shift = shifts[r];
                state[r * 4 + c] = temp[r * 4 + ((c + shift) % 4)];
            }
        }

        // D. MixBytes
        temp.copy_from_slice(state);

        // Process 4 columns independently
        for c in 0..4 {
            // Load column 'c' elements
            let s0 = temp[0 * 4 + c];
            let s1 = temp[1 * 4 + c];
            let s2 = temp[2 * 4 + c];
            let s3 = temp[3 * 4 + c];

            // Precompute Doubling (x * 2)
            let d0 = s0.double_flat();
            let d1 = s1.double_flat();
            let d2 = s2.double_flat();
            let d3 = s3.double_flat();

            // Matrix-Vector Product [1, 1, 2, 3]
            // Multiplications:
            // x * 1 = x
            // x * 2 = d
            // x * 3 = d + x

            // Row 0: [1, 1, 2, 3] -> s0 + s1 + 2s2 + 3s3
            state[0 * 4 + c] = s0 + s1 + d2 + (d3 + s3);

            // Row 1: [3, 1, 1, 2] -> 3s0 + s1 + s2 + 2s3
            state[1 * 4 + c] = (d0 + s0) + s1 + s2 + d3;

            // Row 2: [2, 3, 1, 1] -> 2s0 + 3s1 + s2 + s3
            state[2 * 4 + c] = d0 + (d1 + s1) + s2 + s3;

            // Row 3: [1, 2, 3, 1] -> s0 + 2s1 + 3s2 + s3
            state[3 * 4 + c] = s0 + d1 + (d2 + s2) + s3;
        }
    }
}

/// The Output Transformation:
/// Omega(h) = P(h) ^ h
#[inline(always)]
pub fn output_transform<F: TowerFieldElement>(
    state: &[F; STATE_SIZE],
    rounds: usize,
) -> [F; STATE_SIZE] {
    let mut p_out = *state;
    permutation(&mut p_out, false, rounds); // P(h)

    for i in 0..STATE_SIZE {
        p_out[i] += state[i]; // XOR: P(h) ^ h
    }

    p_out
}
