use digest::Reset;
use hekate_groestl::{
    HekateGroestl, MockBlock128, PADDING_TAG, SBOX_C, STATE_SIZE, TowerFieldElement,
};
// use hekate_math::{Block128, TowerField};

type F = MockBlock128;

pub trait TestSpecs {
    const EXPECTED_EMPTY: (u128, u128);
    const EXPECTED_63: (u128, u128);
    const EXPECTED_64: (u128, u128);
    const EXPECTED_65: (u128, u128);
    const EXPECTED_STRESS: (u128, u128);
}

impl TestSpecs for MockBlock128 {
    const EXPECTED_EMPTY: (u128, u128) = (
        231544243570936695890252920215900882497,
        181496149354194658589900991473099649715,
    );
    const EXPECTED_63: (u128, u128) = (
        112382376028668818366387308863191216182,
        333209648633903853220244947377006154588,
    );
    const EXPECTED_64: (u128, u128) = (
        188992532781123005174854729494913082655,
        64327772276299969457339236741993011684,
    );
    const EXPECTED_65: (u128, u128) = (
        172719149391864165382655662840866441868,
        75234147545833458380791077338758993315,
    );
    const EXPECTED_STRESS: (u128, u128) = (
        264126084882245126538474710977007374511,
        15620324879113596409312762011045416599,
    );
}

// ===========================
// Block128 from hekate-math
// ===========================

// impl TestSpecs for Block128 {
//     const EXPECTED_EMPTY: (u128, u128) = (
//         205871003809839618273896152258605816194,
//         17307473543555229120023010707152897093,
//     );
//     const EXPECTED_63: (u128, u128) = (
//         41770126233590649025459811010828258024,
//         122927315337041225626965231703771520123,
//     );
//     const EXPECTED_64: (u128, u128) = (
//         6840665174378233521323979894102961910,
//         73160439600647428038608902885047713616,
//     );
//     const EXPECTED_65: (u128, u128) = (
//         295873874427844902334136767424126568329,
//         47058790173897607536493245077030103624,
//     );
//     const EXPECTED_STRESS: (u128, u128) = (
//         119166818995122269852585956784284504879,
//         224994826101521322410344323754535305833,
//     );
// }

/// Native S-Box: S(x) = x^254 + 0x63
///
/// Calculation:
/// x^254 = x^(2 + 4 + 8 + 16 + 32 + 64 + 128)
#[inline(always)]
fn native_sbox<F: TowerFieldElement>(x: F) -> F {
    // Term = x^2
    let mut term = x * x;
    let mut acc = term;

    // Accumulate powers:
    // x^4, x^8 ... x^128
    for _ in 0..6 {
        term = term * term;
        acc *= term;
    }

    acc + F::from(SBOX_C)
}

// ==================================
// GROUP 1: RED TEAMING & SECURITY
// ==================================

#[test]
fn padding_collision_attack() {
    // SCENARIO:
    // Attacker tries to forge a message M' that includes
    // the padding of M, hoping that Hash(M) == Hash(M').
    // If we don't encode the length,
    // Hash([A]) will equal Hash([A, Padding]).

    let rounds = 10;

    // 1. Calculate Hash(M) where M = [5]
    let mut hasher_original = HekateGroestl::<F>::new(rounds);
    let m_original = [F::from(5u64)];
    hasher_original.update_elements(&m_original);

    let h1 = hasher_original.finalize_raw();

    // 2. Calculate Hash(M_forged)
    // Manually construct a block that
    // looks exactly like M + Padding(M).
    // Standard Padding:
    // [Data, TAG(0x80), 0..., Length]
    let mut m_forged = [F::ZERO; STATE_SIZE];

    // Copy original data
    m_forged[0] = m_original[0];

    // Append Tag (0x80)
    m_forged[1] = F::from(PADDING_TAG);

    // Middle is already zeros...

    // Append Length of original
    // message (1 element) at the end.
    m_forged[STATE_SIZE - 1] = F::from(1u64);

    // Run hasher on the forged input
    let mut hasher_forged = HekateGroestl::<F>::new(rounds);
    hasher_forged.update_elements(&m_forged);

    let h2 = hasher_forged.finalize_raw();

    println!("H(M)      = {:?}", h1);
    println!("H(Forged) = {:?}", h2);

    // 3. ASSERTION
    // They MUST be different.
    // Logic:
    // H(M) processes 1 block: [5, 0x80, ..., 1]
    // H(Forged) processes 1st block: [5, 0x80, ..., 1] (State becomes same as H(M))
    //           BUT then it sees buf_len=0, total_len=64.
    //           It appends NEW padding: [0x80, ..., 64].
    //           It compresses a SECOND block.
    // Result: State diverges significantly.
    assert_ne!(
        h1, h2,
        "Padding collision detected! Length extension attack possible."
    );
}

#[test]
fn empty_vs_zero_collision() {
    // Edge case: Hash([]) vs Hash([0])
    // Without length padding, an empty
    // message might be padded to [0x80, 0...]
    // A message [0] might be padded to [0, 0x80, 0...]
    // Ensure they are distinct.

    let h_empty = HekateGroestl::<F>::new(10);
    let res_empty = h_empty.finalize_raw();

    let mut h_zero = HekateGroestl::<F>::new(10);
    h_zero.update_elements(&[F::ZERO]);

    let res_zero = h_zero.finalize_raw();

    assert_ne!(res_empty, res_zero, "Hash([]) collided with Hash([0])");
}

#[test]
fn zero_append_attack() {
    // SCENARIO:
    // Hash([A]) should NOT equal Hash([A, 0]).
    // In some insecure sponge constructions,
    // appending a "zero" (neutral element) might
    // not change the state if padding is weak.
    // With Length Padding, [A] has len=1, [A, 0] has len=2.

    let rounds = 10;
    let val = F::from(12345u64);

    // 1. Hash([A])
    let mut h1_gen = HekateGroestl::<F>::new(rounds);
    h1_gen.update_elements(&[val]);

    let h1 = h1_gen.finalize_raw();

    // 2. Hash([A, 0])
    let mut h2_gen = HekateGroestl::<F>::new(rounds);
    h2_gen.update_elements(&[val, F::ZERO]);

    let h2 = h2_gen.finalize_raw();

    println!("H([A])    = {:?}", h1);
    println!("H([A, 0]) = {:?}", h2);

    // 3. ASSERTION
    assert_ne!(
        h1, h2,
        "Zero-Append attack succeeded! Hash([A]) == Hash([A, 0])"
    );
}

#[test]
//#[cfg(not(debug_assertions))]
fn state_saturation_avalanche() {
    // SCENARIO:
    // Avalanche Effect check. Changing exactly 1 bit
    // in the input MUST change ~50% of the output bits
    // (approx 64 bits for Block128). If only a few bytes
    // change, the MDS matrix is not diffusing entropy correctly.

    let rounds = 10;

    // Use a fixed pattern to make
    // the test deterministic.
    let seed_val = 0x1234_5678_9ABC_DEF0_DEAD_BEEF_CAFE_BABE_u128;
    let seed = F::from(seed_val);

    // 1. Calculate Baseline Hash
    let mut h1_gen = HekateGroestl::<F>::new(rounds);
    h1_gen.update_elements(&[seed]);

    let h1 = h1_gen.finalize_raw();

    let mut total_bit_changes = 0;
    let iterations = 128; // Test flipping every single bit position

    for i in 0..iterations {
        // 2. Flip exactly 1 bit at index 'i'
        // In characteristic 2 fields (Block128), Addition IS XOR.
        // So adding (1 << i) flips the i-th bit.
        let flip_mask = F::from(1u128 << i);
        let modified_input = seed + flip_mask;

        let mut h2_gen = HekateGroestl::<F>::new(rounds);
        h2_gen.update_elements(&[modified_input]);

        let h2 = h2_gen.finalize_raw();

        // 3. Measure Difference (Hamming Distance)
        // XOR output hashes to find changed bits
        let diff0 = h1[0] + h2[0];
        let diff1 = h1[1] + h2[1];
        let bit_changes = diff0.0.count_ones() + diff1.0.count_ones();

        total_bit_changes += bit_changes;

        // Local Sanity Check:
        // For 256-bit hash, expect ~128 flips.
        // Threshold: > 40
        assert!(
            bit_changes > 40,
            "Weak diffusion! Flipping bit {} changed only {} bits.",
            i,
            bit_changes
        );
    }

    let avg_changes = total_bit_changes as f64 / iterations as f64;
    println!(
        "Average Bit Flips = {:.2} / 256 (Ideal: 128.0)",
        avg_changes
    );

    // 4. Global Assertion (Updated for 256-bit)
    // Ideal is 128.
    assert!(
        avg_changes > 110.0,
        "Average avalanche is too low (< 110). Diffusion is insufficient."
    );
}

// ==================================
// GROUP 2: BUFFER MANAGEMENT
// ==================================

#[test]
fn buffer_empty_input() {
    // SCENARIO:
    // Call finalize() immediately after
    // initialization without any update().
    //
    // EXPECTATION:
    // 1. Must NOT panic (buffer management handles empty state).
    // 2. Must return a valid hash (result of processing the Padding Block).
    //    Padding Block for empty input: [0x80, 0, ..., 0 (len=0)].

    let rounds = 10;
    let hasher = HekateGroestl::<F>::new(rounds);
    let digest = hasher.finalize_raw();

    println!("Hash(Empty) = Low: {:?}, High: {:?}", digest[0], digest[1]);

    assert!(
        digest[0] != F::ZERO || digest[1] != F::ZERO,
        "Hash of empty input should not be zero"
    );

    assert_eq!(digest[0], F::from(F::EXPECTED_EMPTY.0), "Low part mismatch");
    assert_eq!(
        digest[1],
        F::from(F::EXPECTED_EMPTY.1),
        "High part mismatch"
    );
}

#[test]
fn buffer_exact_boundary() {
    // SCENARIO:
    // Input length is exactly STATE_SIZE (64).
    // The buffer fills up completely during update().
    // The secure padding logic in finalize() must
    // realize it needs to append the Padding Tag and
    // Length, effectively creating a NEW block.

    let rounds = 10;
    let mut hasher = HekateGroestl::<F>::new(rounds);

    // Create 64 elements
    let mut input = [F::default(); STATE_SIZE];
    for i in 0..STATE_SIZE {
        let val = (i as u64)
            .wrapping_mul(0x1234_5678_90AB_CDEF)
            .wrapping_add(0xCAFE_BABE);
        input[i] = F::from(val);
    }

    // This triggers a compress() inside
    // update() because buf_len hits 64.
    hasher.update_elements(&input);

    // At this point:
    // buf_len = 0
    // total_len = 64
    // finalize_raw() must start a fresh block:
    // [0x80, 0..., 0, 64]
    let digest = hasher.finalize_raw();
    println!("Hash(64) = Low: {:?}, High: {:?}", digest[0], digest[1]);

    assert!(
        digest[0] != F::ZERO || digest[1] != F::ZERO,
        "Hash of full block should be valid non-zero"
    );

    assert_eq!(digest[0], F::from(F::EXPECTED_64.0), "Low part mismatch");
    assert_eq!(digest[1], F::from(F::EXPECTED_64.1), "High part mismatch");
}

#[test]
fn buffer_boundary_overflow_65() {
    // SCENARIO:
    // Input length is 65 (State Size + 1).
    // 1. update() fills the first 64, triggers compress().
    // 2. The 65th element remains in the buffer at index 0.
    // 3. finalize() adds Tag at index 1,
    //    Fills zeros, Adds Length at index 63.
    // Result: 2 full blocks processed.

    let rounds = 10;
    let mut hasher = HekateGroestl::<F>::new(rounds);

    // 65 elements
    let mut input = [F::default(); STATE_SIZE + 1];
    for i in 0..input.len() {
        let val = (i as u64)
            .wrapping_mul(0x1122_3344_5566_7788)
            .wrapping_add(0xDEAD_1010);
        input[i] = F::from(val);
    }

    hasher.update_elements(&input);

    let digest = hasher.finalize_raw();
    println!("Hash(65) = Low: {:?}, High: {:?}", digest[0], digest[1]);

    assert!(
        digest[0] != F::ZERO || digest[1] != F::ZERO,
        "Hash of 65 elements failed"
    );

    assert_eq!(digest[0], F::from(F::EXPECTED_65.0), "Low part mismatch");
    assert_eq!(digest[1], F::from(F::EXPECTED_65.1), "High part mismatch");
}

#[test]
fn buffer_boundary_underflow_63() {
    // SCENARIO:
    // Input length is 63.
    // Buffer is filled 0..62.
    // finalize() appends Tag at index 63.
    // Now buf_len = 64.
    //
    // CRITICAL CHECK:
    // The Length (u64) MUST go into index 63.
    // But index 63 is occupied by Tag!
    //
    // The Hasher MUST:
    // 1. Detect that there is no space for Length.
    // 2. Compress the current block (Data + Tag).
    // 3. Create a NEW block containing just Zeros + Length.

    let rounds = 10;
    let mut hasher = HekateGroestl::<F>::new(rounds);

    let mut input = [F::default(); STATE_SIZE - 1];
    for i in 0..input.len() {
        let val = (i as u64)
            .wrapping_mul(0x9988_7766_5544_3322)
            .wrapping_add(0xBEEF_2020);
        input[i] = F::from(val);
    }

    hasher.update_elements(&input);

    let digest = hasher.finalize_raw();
    println!("Hash(63) = Low: {:?}, High: {:?}", digest[0], digest[1]);

    assert!(
        digest[0] != F::ZERO || digest[1] != F::ZERO,
        "Hash of 63 elements failed"
    );

    assert_eq!(digest[0], F::from(F::EXPECTED_63.0), "Low part mismatch");
    assert_eq!(digest[1], F::from(F::EXPECTED_63.1), "High part mismatch");
}

// ==================================
// GROUP 3: API CONSISTENCY
// ==================================

#[test]
fn chunked_update_consistency() {
    // SCENARIO:
    // The hash result must be independent
    // of how the input is chunked.
    // Hash(Part1 + Part2) == Hash(Part1)
    // updated then Hash(Part2). This verifies
    // that the internal buffer correctly
    // accumulates partial blocks.

    let rounds = 10;

    // Create a distinct pattern of data:
    // 0, 1, 2, ... 149
    //
    // 150 elements cover:
    // 2 Full Blocks (64*2=128) + 1 Partial (22)
    let total_elements = 150;
    let data: Vec<F> = (0..total_elements).map(|i| F::from(i as u64)).collect();

    // 1. Full Update (All at once)
    let mut h_full = HekateGroestl::<F>::new(rounds);
    h_full.update_elements(&data);

    let res_full = h_full.finalize_raw();

    // 2. Split Update (75 + 75)
    // Cuts right in the middle of the second block.
    let mut h_split = HekateGroestl::<F>::new(rounds);
    let (part1, part2) = data.split_at(75);
    h_split.update_elements(part1);
    h_split.update_elements(part2);

    let res_split = h_split.finalize_raw();

    // 3. Iterative Update (Element by Element)
    // Worst-case fragmentation.
    let mut h_iter = HekateGroestl::<F>::new(rounds);
    for elem in &data {
        h_iter.update_elements(&[*elem]);
    }

    let res_iter = h_iter.finalize_raw();

    println!("Hash(Full)  = {:?}", res_full);
    println!("Hash(Split) = {:?}", res_split);
    println!("Hash(Iter)  = {:?}", res_iter);

    assert_eq!(
        res_full, res_split,
        "Split update failed consistency check."
    );
    assert_eq!(
        res_full, res_iter,
        "Iterative update failed consistency check."
    );
}

#[test]
fn reset_functionality() {
    // SCENARIO:
    // 1. Update with A.
    // 2. Reset.
    // 3. Update with B.
    // 4. Result must equal Hash(B) (as if A never happened).
    // This verifies that reset() clears
    // state, buffer, and total_len.

    let rounds = 10;
    let a_val = F::from(0xAAAAAAAA_u64);
    let b_val = F::from(0xBBBBBBBB_u64);

    let mut hasher = HekateGroestl::<F>::new(rounds);

    // Pollute state with A
    hasher.update_elements(&[a_val]);

    // Reset (Should wipe A)
    hasher.reset();

    // Update with B
    hasher.update_elements(&[b_val]);

    let res_reset = hasher.finalize_raw();

    // Reference: Clean Hash(B)
    let mut h_ref = HekateGroestl::<F>::new(rounds);
    h_ref.update_elements(&[b_val]);

    let res_clean = h_ref.finalize_raw();

    println!("Hash(Reset -> B) = {:?}", res_reset);
    println!("Hash(Clean B)    = {:?}", res_clean);

    assert_eq!(
        res_reset, res_clean,
        "Reset failed to clear internal state."
    );

    // Sanity check:
    // Ensure A actually changes the hash if NO reset
    let mut h_dirty = HekateGroestl::<F>::new(rounds);
    h_dirty.update_elements(&[a_val]);
    h_dirty.update_elements(&[b_val]);

    let res_dirty = h_dirty.finalize_raw();

    assert_ne!(
        res_reset, res_dirty,
        "Sanity check failed: A+B should not equal B."
    );
}

#[test]
fn math_sbox_determinism() {
    // SCENARIO:
    // Verify that the S-Box function
    // S(x) = x^254 + 0x63 is deterministic
    // and computes correctly for known test vectors.

    // 1. Case: Input 0
    // Calculation:
    // 0^254 + 0x63 = 0 + 0x63 = 0x63.
    let zero = F::ZERO;
    let s_zero = native_sbox(zero);

    assert_eq!(
        s_zero,
        F::from(0x63u64),
        "S-Box(0) calculation failed. Expected 0x63."
    );

    // 2. Case: Input 1
    // Calculation:
    // 1^254 + 0x63 = 1 + 0x63.
    // In Characteristic 2 fields (binary), Addition is XOR.
    // 0x63 (01100011) XOR 0x01 (00000001) = 0x62 (01100010).
    let one = F::ONE;
    let s_one = native_sbox(one);

    assert_eq!(
        s_one,
        F::from(0x62u64),
        "S-Box(1) calculation failed. Expected 1 ^ 0x63 = 0x62."
    );

    // 3. Case: Determinism (Stability)
    // Ensure repeated calls do not drift
    // or use uninitialized memory.
    let val = F::from(0x1234567890ABCDEF_u64);
    let res1 = native_sbox(val);
    let res2 = native_sbox(val);
    let res3 = native_sbox(val);

    assert_eq!(res1, res2, "S-Box is non-deterministic (run 1 vs 2)");
    assert_eq!(res1, res3, "S-Box is non-deterministic (run 1 vs 3)");
}

// ==================================
// GROUP 4: STRESS & STRUCTURE
// ==================================

#[test]
#[cfg(not(debug_assertions))]
fn stress_n_block_mini() {
    // SCENARIO:
    // Feed N blocks to the hasher.
    // Checks for:
    // 1. Memory leaks.
    // 2. Counter overflows.
    // 3. Performance stability.

    const BLOCKS_COUNT: usize = 50_000;

    let rounds = 10;
    let mut hasher = HekateGroestl::<F>::new(rounds);

    // A full block of data
    let mut block = [F::default(); STATE_SIZE];
    for i in 0..STATE_SIZE {
        let val = (i as u64)
            .wrapping_mul(0xAAAA_BBBB_CCCC_DDDD)
            .wrapping_add(0x1337_C0DE);
        block[i] = F::from(val);
    }

    for _ in 0..BLOCKS_COUNT {
        hasher.update_elements(&block);
    }

    let digest = hasher.finalize_raw();
    println!("Hash(Stress) = Low: {:?}, High: {:?}", digest[0], digest[1]);

    assert!(
        digest[0] != F::ZERO || digest[1] != F::ZERO,
        "Hash(Stress) failed"
    );

    assert_eq!(
        digest[0],
        F::from(F::EXPECTED_STRESS.0),
        "Low part mismatch"
    );
    assert_eq!(
        digest[1],
        F::from(F::EXPECTED_STRESS.1),
        "High part mismatch"
    );
}

#[test]
fn structure_output_folding_transform() {
    // SCENARIO:
    // Verify that Output Transform (Omega = P(S) ^ S)
    // and Folding are active. Since we cannot inject
    // raw state, we check for non-triviality.
    //
    // If Output Transform was missing:
    // Hash([0]) might be related to Permutation(0).
    // If Folding was broken (e.g. returning just state[0]):
    // Entropy would be low.

    let rounds = 10;

    // 1. Hash of Zero
    // If P(S)^S logic is missing, or S-box is
    // identity for 0 (it's not, it's 0x63),
    // we want to ensure result is mixed.
    let mut h0 = HekateGroestl::<F>::new(rounds);
    h0.update_elements(&[F::ZERO]);

    let res0 = h0.finalize_raw();
    assert!(
        res0[0] != F::ZERO || res0[1] != F::ZERO,
        "Output Transform produced zero for zero input"
    );

    // 2. Folding Verification (Indirect)
    let mut h1 = HekateGroestl::<F>::new(rounds);
    h1.update_elements(&[F::ZERO]);

    let res1 = h1.finalize_raw();
    assert_eq!(res0, res1, "Folding/Transform is non-deterministic");
}
