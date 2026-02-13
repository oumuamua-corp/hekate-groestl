#![no_std]

use digest::{FixedOutput, HashMarker, Output, OutputSizeUser, typenum::U32};
use hekate_math::{
    Block128, CanonicalSerialize, HardwareField, PACKED_WIDTH_128, PackableField, PackedBlock128,
    TowerField,
};

pub use digest::{Reset, Update};

pub const ROUNDS: usize = 10;
pub const STATE_SIZE: usize = 16;

/// Output length in bytes (256 bits).
pub const OUT_LEN: usize = 32;

/// Domain tag for dedicated 2-to-1 compression
/// based on the Groestl-style compression.
pub const TAG_NODE_COMPRESS_FLAT: u128 = 0x5e3a90c2c7c3d00b8f29a6d5f14c8a71;

/// Domain tag for dedicated 2-to-1 compression
/// based on a single P-permutation.
pub const TAG_NODE_PERMUTATION_FLAT: u128 = 0x9d1c3f7a2a6b5c0e1e8a7f2d4b6c1903;

/// MixBytes coefficients (MDS Matrix).
/// Verified to be MDS in Flat Basis (AES Polynomial 0x87).
pub const MIX_P: [u8; 4] = [0x01, 0x01, 0x02, 0x03];

/// Standard cyclic.
pub const SHIFT_P: [usize; 4] = [0, 1, 2, 3];

/// Inverse cyclic to maximize diffusion distance.
pub const SHIFT_Q: [usize; 4] = [1, 3, 2, 0];

/// S-Box Affine Constant in Flat Basis (0x63).
pub const SBOX_C_FLAT: u128 = 0x109a14b16f02ddc303e0c80926dd7a11;

/// Padding Separator in Flat Basis (0x80).
pub const PADDING_TAG_FLAT: u128 = 0x049b075c0f15ad1e11f9bedcdd1861f4;

/// Round Constants for Permutation P (Flat Basis).
/// Layout: [Round][Column]
pub const RC_P_FLAT: [[u128; 4]; 14] = [
    [
        0x00000000000000000000000000000000,
        0x4cf4b7439cbfbb84ec7759ca3488aee1,
        0x93252331bf042b11512625b1f09fa87e,
        0xdfd1947223bb9095bd517c7bc417069f,
    ],
    [
        0x00000000000000000000000000000001,
        0x4cf4b7439cbfbb84ec7759ca3488aee0,
        0x93252331bf042b11512625b1f09fa87f,
        0xdfd1947223bb9095bd517c7bc417069e,
    ],
    [
        0xb61257cfad572414ed09ef16e07b94c6,
        0xfae6e08c31e89f90017eb6dcd4f33a27,
        0x253774fe12530f05bc2fcaa710e43cb8,
        0x69c3c3bd8eecb4815058936d246c9259,
    ],
    [
        0xb61257cfad572414ed09ef16e07b94c7,
        0xfae6e08c31e89f90017eb6dcd4f33a26,
        0x253774fe12530f05bc2fcaa710e43cb9,
        0x69c3c3bd8eecb4815058936d246c9258,
    ],
    [
        0x053d8555a9979a1ca13fe8ac5560ce0d,
        0x49c93216352821984d48b16661e860ec,
        0x9618a6641693b10df019cd1da5ff6673,
        0xdaec11278a2c0a891c6e94d79177c892,
    ],
    [
        0x053d8555a9979a1ca13fe8ac5560ce0c,
        0x49c93216352821984d48b16661e860ed,
        0x9618a6641693b10df019cd1da5ff6672,
        0xdaec11278a2c0a891c6e94d79177c893,
    ],
    [
        0xb32fd29a04c0be084c3607bab51b5acb,
        0xffdb65d9987f058ca0415e708193f42a,
        0x200af1abbbc495191d10220b4584f2b5,
        0x6cfe46e8277b2e9df1677bc1710c5c54,
    ],
    [
        0xb32fd29a04c0be084c3607bab51b5aca,
        0xffdb65d9987f058ca0415e708193f42b,
        0x200af1abbbc495191d10220b4584f2b4,
        0x6cfe46e8277b2e9df1677bc1710c5c55,
    ],
    [
        0xf72dd6ca714abd6e6afd8694e8dda26f,
        0xbbd96189edf506ea868adf5edc550c8e,
        0x6408f5fbce4e967f3bdba32518420a11,
        0x28fc42b852f12dfbd7acfaef2ccaa4f0,
    ],
    [
        0xf72dd6ca714abd6e6afd8694e8dda26e,
        0xbbd96189edf506ea868adf5edc550c8f,
        0x6408f5fbce4e967f3bdba32518420a10,
        0x28fc42b852f12dfbd7acfaef2ccaa4f1,
    ],
    [
        0x413f8105dc1d997a87f4698208a636a9,
        0x0dcb364640a222fe6b8330483c2e9848,
        0xd21aa2346319b26bd6d24c33f8399ed7,
        0x9eee1577ffa609ef3aa515f9ccb13036,
    ],
    [
        0x413f8105dc1d997a87f4698208a636a8,
        0x0dcb364640a222fe6b8330483c2e9849,
        0xd21aa2346319b26bd6d24c33f8399ed6,
        0x9eee1577ffa609ef3aa515f9ccb13037,
    ],
    [
        0xf210539fd8dd2772cbc26e38bdbd6c62,
        0xbee4e4dc44629cf627b537f28935c283,
        0x613570ae67d90c639ae44b894d22c41c,
        0x2dc1c7edfb66b7e77693124379aa6afd,
    ],
    [
        0xf210539fd8dd2772cbc26e38bdbd6c63,
        0xbee4e4dc44629cf627b537f28935c282,
        0x613570ae67d90c639ae44b894d22c41d,
        0x2dc1c7edfb66b7e77693124379aa6afc,
    ],
];

/// Round Constants for Permutation Q (Flat Basis)
/// Layout: [Round][Column]
pub const RC_Q_FLAT: [[u128; 4]; 14] = [
    [
        0xae7ef06d2b6041352455fffbafe8b892,
        0xe28a472eb7dffab1c822a6319b601673,
        0x3d5bd35c94646a247573da4a5f7710ec,
        0x71af641f08dbd1a0990483806bffbe0d,
    ],
    [
        0xae7ef06d2b6041352455fffbafe8b893,
        0xe28a472eb7dffab1c822a6319b601672,
        0x3d5bd35c94646a247573da4a5f7710ed,
        0x71af641f08dbd1a0990483806bffbe0c,
    ],
    [
        0x186ca7a286376521c95c10ed4f932c54,
        0x549810e11a88dea5252b49277b1b82b5,
        0x8b49849339334e30987a355cbf0c842a,
        0xc7bd33d0a58cf5b4740d6c968b842acb,
    ],
    [
        0x186ca7a286376521c95c10ed4f932c55,
        0x549810e11a88dea5252b49277b1b82b4,
        0x8b49849339334e30987a355cbf0c842b,
        0xc7bd33d0a58cf5b4740d6c968b842aca,
    ],
    [
        0xab43753882f7db29856a1757fa88769f,
        0xe7b7c27b1e4860ad691d4e9dce00d87e,
        0x386656093df3f038d44c32e60a17dee1,
        0x7492e14aa14c4bbc383b6b2c3e9f7000,
    ],
    [
        0xab43753882f7db29856a1757fa88769e,
        0xe7b7c27b1e4860ad691d4e9dce00d87f,
        0x386656093df3f038d44c32e60a17dee0,
        0x7492e14aa14c4bbc383b6b2c3e9f7001,
    ],
    [
        0x1d5122f72fa0ff3d6863f8411af3e259,
        0x51a595b4b31f44b98414a18b2e7b4cb8,
        0x8e7401c690a4d42c3945ddf0ea6c4a27,
        0xc280b6850c1b6fa8d532843adee4e4c6,
    ],
    [
        0x1d5122f72fa0ff3d6863f8411af3e258,
        0x51a595b4b31f44b98414a18b2e7b4cb9,
        0x8e7401c690a4d42c3945ddf0ea6c4a26,
        0xc280b6850c1b6fa8d532843adee4e4c7,
    ],
    [
        0x595326a75a2afc5b4ea8796f47351afd,
        0x15a791e4c69547dfa2df20a573bdb41c,
        0xca760596e52ed74a1f8e5cdeb7aab283,
        0x8682b2d579916ccef3f9051483221c62,
    ],
    [
        0x595326a75a2afc5b4ea8796f47351afc,
        0x15a791e4c69547dfa2df20a573bdb41d,
        0xca760596e52ed74a1f8e5cdeb7aab282,
        0x8682b2d579916ccef3f9051483221c63,
    ],
    [
        0xef417168f77dd84fa3a19679a74e8e3b,
        0xa3b5c62b6bc263cb4fd6cfb393c620da,
        0x7c6452594879f35ef287b3c857d12645,
        0x3090e51ad4c648da1ef0ea02635988a4,
    ],
    [
        0xef417168f77dd84fa3a19679a74e8e3a,
        0xa3b5c62b6bc263cb4fd6cfb393c620db,
        0x7c6452594879f35ef287b3c857d12644,
        0x3090e51ad4c648da1ef0ea02635988a5,
    ],
    [
        0x5c6ea3f2f3bd6647ef9791c31255d4f0,
        0x109a14b16f02ddc303e0c80926dd7a11,
        0xcf4b80c34cb94d56beb1b472e2ca7c8e,
        0x83bf3780d006f6d252c6edb8d642d26f,
    ],
    [
        0x5c6ea3f2f3bd6647ef9791c31255d4f1,
        0x109a14b16f02ddc303e0c80926dd7a10,
        0xcf4b80c34cb94d56beb1b472e2ca7c8f,
        0x83bf3780d006f6d252c6edb8d642d26e,
    ],
];

/// Extension trait for Groestl
/// specific operations on Block128.
pub trait Block128Ext: Sized + Copy {
    fn square(self) -> Self;
    fn double(self) -> Self;
    fn batch_sbox(chunk: &mut [Self]);
}

/// Digest in native field elements (256 bits).
/// All values are assumed to be in the Hardware (Flat) basis.
pub type Digest256 = [Block128; 2];

/// Newtype struct for the hash output (32 bytes).
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Hash([u8; OUT_LEN]);

impl Hash {
    /// Returns the bytes of the hash.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; OUT_LEN] {
        &self.0
    }
}

/// A Generic Hekate Groestl Hasher. Adapts the field-based
/// arithmetic to the byte-oriented `Digest` trait by
/// treating input bytes as individual field elements.
#[derive(Clone, Debug)]
pub struct Hasher {
    state: [Block128; STATE_SIZE],
    buffer: [Block128; STATE_SIZE],
    total_len: u64,
    buf_len: usize,
}

impl Default for Hasher {
    fn default() -> Self {
        Self {
            state: [Block128::default(); STATE_SIZE],
            buffer: [Block128::default(); STATE_SIZE],
            total_len: 0,
            buf_len: 0,
        }
    }
}

impl Hasher {
    pub fn new() -> Self {
        Self::default()
    }

    /// Direct field element update (bypassing byte conversion).
    pub fn update_elements(&mut self, input: &[Block128]) {
        for &elem in input {
            self.buffer[self.buf_len] = elem;
            self.buf_len += 1;
            self.total_len += 1;

            if self.buf_len == STATE_SIZE {
                compress(&mut self.state, &self.buffer);
                self.buf_len = 0;
            }
        }
    }

    /// Emulates the Transcript Sponge Squeeze behavior.
    /// Uses Secure Padding (Tag + Length) to prevent
    /// extension attacks.
    pub fn squeeze_sponge(&mut self) -> Block128 {
        self.buffer[self.buf_len] = Block128::from(PADDING_TAG_FLAT);
        self.buf_len += 1;

        if self.buf_len > STATE_SIZE - 1 {
            for i in self.buf_len..STATE_SIZE {
                self.buffer[i] = Block128::default();
            }

            compress(&mut self.state, &self.buffer);
            self.buf_len = 0;
        }

        for i in self.buf_len..(STATE_SIZE - 1) {
            self.buffer[i] = Block128::default();
        }

        self.buffer[STATE_SIZE - 1] = Block128::from(self.total_len).to_hardware();

        compress(&mut self.state, &self.buffer);
        self.buf_len = 0;

        // =======================================
        // Hash Chain Logic (Permutation + Fold)
        // =======================================

        // Run P-Permutation on current state
        // S_next = P(S_curr)
        let mut s_next = self.state;
        permutation(&mut s_next, false);

        // Output Transform:
        // T = S_next ^ S_curr
        let mut transformed = [Block128::default(); STATE_SIZE];
        for i in 0..STATE_SIZE {
            transformed[i] = s_next[i] + self.state[i];
        }

        self.state = s_next;

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

        reduce_buf[0]
    }

    /// Finalize and return 2 field elements (256 bits).
    /// Returns [HashLow, HashHigh].
    pub fn finalize_raw(self) -> [Block128; 2] {
        let mut final_hasher = self;
        final_hasher.buffer[final_hasher.buf_len] = Block128::from(PADDING_TAG_FLAT);
        final_hasher.buf_len += 1;

        if final_hasher.buf_len > STATE_SIZE - 1 {
            for i in final_hasher.buf_len..STATE_SIZE {
                final_hasher.buffer[i] = Block128::default();
            }

            compress(&mut final_hasher.state, &final_hasher.buffer);

            // Start a new fresh block
            final_hasher.buffer = [Block128::default(); STATE_SIZE];
            final_hasher.buf_len = 0;
        }

        for i in final_hasher.buf_len..(STATE_SIZE - 1) {
            final_hasher.buffer[i] = Block128::default();
        }

        final_hasher.buffer[STATE_SIZE - 1] = Block128::from(final_hasher.total_len).to_hardware();

        // Final Compress
        compress(&mut final_hasher.state, &final_hasher.buffer);

        // Output Transform:
        // T = P(S) ^ S
        let transformed = output_transform(&final_hasher.state);

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

        [reduce_buf[0], reduce_buf[1]]
    }

    /// Finalize and return typed Hash struct.
    pub fn finalize(self) -> Hash {
        let [low, high] = self.finalize_raw();

        let mut out_bytes = [0u8; OUT_LEN];
        out_bytes[0..16].copy_from_slice(&low.to_bytes());
        out_bytes[16..32].copy_from_slice(&high.to_bytes());

        Hash(out_bytes)
    }
}

/// RustCrypto trait implementation
/// Maps [u8] -> [F] 1:1.
impl Update for Hasher {
    fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.buffer[self.buf_len] = Block128::from(b as u64).to_hardware();
            self.buf_len += 1;
            self.total_len += 1;

            if self.buf_len == STATE_SIZE {
                compress(&mut self.state, &self.buffer);

                self.buf_len = 0;
            }
        }
    }
}

impl OutputSizeUser for Hasher {
    type OutputSize = U32; // 256-bit output (2 x Block128)
}

impl FixedOutput for Hasher {
    fn finalize_into(self, out: &mut Output<Self>) {
        let result_elements = self.finalize_raw();
        let out0 = result_elements[0];
        let out1 = result_elements[1];

        out[0..16].copy_from_slice(&out0.to_bytes());
        out[16..32].copy_from_slice(&out1.to_bytes());
    }
}

impl HashMarker for Hasher {}

impl Reset for Hasher {
    fn reset(&mut self) {
        self.state = [Block128::default(); STATE_SIZE];
        self.buf_len = 0;
        self.total_len = 0;
    }
}

impl Block128Ext for Block128 {
    #[inline(always)]
    fn square(self) -> Self {
        // NOTE: mul_hardware is faster than
        // squaring using ARM AArch64 NEON + PMULL.
        self.mul_hardware(self)
    }

    #[inline(always)]
    fn double(self) -> Self {
        // x * 2 in Flat Basis is just
        // a shift + conditional XOR.
        //
        // Poly:
        // x^128 + x^7 + x^2 + x + 1 (0x87)

        let val = self.0;
        let mask = ((val as i128) >> 127) as u128;
        let res = (val << 1) ^ (mask & 0x87);

        Self(res)
    }

    #[inline(always)]
    fn batch_sbox(chunk: &mut [Self]) {
        let c_packed = PackedBlock128::broadcast(Block128(SBOX_C_FLAT));

        // Explicit SIMD Loop;
        // Process 4 elements at a time using PackedBlock128
        let mut chunks = chunk.chunks_exact_mut(PACKED_WIDTH_128);
        for simd_chunk in &mut chunks {
            let x_vec = Self::pack(simd_chunk);

            // Chain:
            // 6 steps of (acc^2 * x)
            let mut acc = x_vec;
            for _ in 0..6 {
                let sq = Self::mul_hardware_packed(acc, acc); // acc^2
                acc = Self::mul_hardware_packed(sq, x_vec); // acc^2 * x
            }

            // Affine transform:
            // + c (XOR)
            let res = acc + c_packed;
            Self::unpack(res, simd_chunk);
        }

        // Scalar Tail
        for item in chunks.into_remainder() {
            let x = *item;

            // Compute x^127
            let mut acc = x;
            for _ in 0..6 {
                acc = acc.square().mul_hardware(x);
            }

            *item = acc + Block128(SBOX_C_FLAT);
        }
    }
}

/// The core compression function:
/// f(h, m) = P(h^m) ^ Q(m) ^ h
#[inline(always)]
pub fn compress(h: &mut [Block128; STATE_SIZE], m: &[Block128; STATE_SIZE]) {
    let mut p_in = [Block128::default(); STATE_SIZE];
    for i in 0..STATE_SIZE {
        p_in[i] = h[i] + m[i];
    }

    let mut q_in = *m;
    permutation(&mut p_in, false);
    permutation(&mut q_in, true);

    // Update State:
    // h_next = P(h^m) ^ Q(m) ^ h_prev
    for i in 0..STATE_SIZE {
        h[i] = p_in[i] + q_in[i] + h[i];
    }
}

/// Dedicated 2-to-1 compression for Merkle-style
/// hashing. This variant uses the Groestl-style
/// compression function:
/// `f(h, m) = P(h ^ m) ^ Q(m) ^ h`
#[inline(always)]
pub fn compress_node(left: Digest256, right: Digest256) -> Digest256 {
    let mut h = [Block128::ZERO; STATE_SIZE];
    let mut m = [Block128::ZERO; STATE_SIZE];

    m[0] = Block128(TAG_NODE_COMPRESS_FLAT);

    m[1] = left[0];
    m[2] = left[1];
    m[3] = right[0];
    m[4] = right[1];

    compress(&mut h, &m);

    fold_state_to_digest(&h)
}

/// Dedicated 2-to-1 compression for Merkle-style
/// hashing. This variant treats the P-permutation
/// as a PRP and uses a single permutation
/// (sponge-like absorb + permute).
#[inline(always)]
pub fn compress_node_prp(left: Digest256, right: Digest256) -> Digest256 {
    let mut state = [Block128::ZERO; STATE_SIZE];

    state[0] = Block128(TAG_NODE_PERMUTATION_FLAT);

    state[1] = left[0];
    state[2] = left[1];
    state[3] = right[0];
    state[4] = right[1];

    permutation(&mut state, false);

    fold_state_to_digest(&state)
}

/// Core Groestl Permutation (P/Q).
/// Executes the Hekate Groestl round function.
#[inline(always)]
pub fn permutation(state: &mut [Block128; STATE_SIZE], is_q: bool) {
    let shifts = if is_q { &SHIFT_Q } else { &SHIFT_P };
    let r_consts = if is_q { &RC_Q_FLAT } else { &RC_P_FLAT };

    let mut temp = [Block128::default(); STATE_SIZE];
    for round_consts in r_consts.iter().take(ROUNDS) {
        // A. AddRoundConstant
        let target_row = if is_q { 3 } else { 0 };
        let base = target_row * 4;

        state[base] += Block128(round_consts[0]);
        state[base + 1] += Block128(round_consts[1]);
        state[base + 2] += Block128(round_consts[2]);
        state[base + 3] += Block128(round_consts[3]);

        // B. SubBytes (Native S-Box)
        let mut i = 0;
        while i < STATE_SIZE {
            Block128::batch_sbox(&mut state[i..i + 4]);
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
            let s0 = temp[c];
            let s1 = temp[4 + c];
            let s2 = temp[8 + c];
            let s3 = temp[12 + c];

            // Precompute Doubling (x * 2)
            let d0 = s0.double();
            let d1 = s1.double();
            let d2 = s2.double();
            let d3 = s3.double();

            // Matrix-Vector Product [1, 1, 2, 3]
            // Multiplications:
            // x * 1 = x
            // x * 2 = d
            // x * 3 = d + x

            // Row 0:
            // [1, 1, 2, 3]
            state[c] = s0 + s1 + d2 + (d3 + s3);

            // Row 1:
            // [3, 1, 1, 2]
            state[4 + c] = (d0 + s0) + s1 + s2 + d3;

            // Row 2:
            // [2, 3, 1, 1]
            state[8 + c] = d0 + (d1 + s1) + s2 + s3;

            // Row 3:
            // [1, 2, 3, 1]
            state[12 + c] = s0 + d1 + (d2 + s2) + s3;
        }
    }
}

/// The Output Transformation:
/// Omega(h) = P(h) ^ h
#[inline(always)]
pub fn output_transform(state: &[Block128; STATE_SIZE]) -> [Block128; STATE_SIZE] {
    let mut p_out = *state;
    permutation(&mut p_out, false); // P(h)

    for i in 0..STATE_SIZE {
        p_out[i] += state[i]; // XOR: P(h) ^ h
    }

    p_out
}

#[inline(always)]
fn fold_state_to_digest(state: &[Block128; STATE_SIZE]) -> Digest256 {
    let mut out0 = Block128::ZERO;
    let mut out1 = Block128::ZERO;
    let mut i = 0usize;

    while i < STATE_SIZE {
        if i.is_multiple_of(2) {
            out0 += state[i];
        } else {
            out1 += state[i];
        }

        i += 1;
    }

    [out0, out1]
}
