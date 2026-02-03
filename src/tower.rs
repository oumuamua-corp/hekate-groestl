use crate::SBOX_C;
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub};

/// The contract for field elements used in Tower Groestl.
/// This trait abstracts the mathematical backend, allowing
/// the hashing logic to run on native CPU types (Block128),
/// GPU buffers, or symbolic variables.
pub trait TowerFieldElement:
    Copy
    + Clone
    + Default
    + PartialEq
    + Eq
    + From<u64>
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + AddAssign
    + MulAssign
{
    /// Serialize element to bytes (Little Endian implied).
    /// Required for 'digest' output.
    fn to_bytes(&self) -> [u8; 16];

    // =============================================================
    // BASIS TRANSFORMATION LAYER (Optional Optimizations)
    // =============================================================

    /// Convert from Logical (Tower)
    /// Basis to Execution (Flat) Basis.
    ///
    /// This allows the implementation to switch
    /// to a basis that is computationally cheaper
    /// for multiplication (e.g., polynomial basis
    /// for hardware AES-NI instructions).
    ///
    /// Default: Identity (No-op).
    #[inline(always)]
    fn to_flat(self) -> Self {
        self
    }

    /// Convert from Execution (Flat) Basis
    /// back to Logical (Tower) Basis.
    ///
    /// Default: Identity (No-op).
    #[inline(always)]
    fn from_flat(self) -> Self {
        self
    }

    // =============================================================
    // FLAT BASIS ARITHMETIC
    // =============================================================

    #[inline(always)]
    fn mul_flat(self, rhs: Self) -> Self {
        self * rhs
    }

    #[inline(always)]
    fn square_flat(self) -> Self {
        self * self
    }

    #[inline(always)]
    fn double_flat(self) -> Self {
        self * Self::from(2)
    }

    /// Batch S-Box processing in Flat Basis.
    ///
    /// This allows overriding the loop to use internal
    /// SIMD registers without constant basis conversions.
    #[inline(always)]
    fn batch_sbox_flat(chunk: &mut [Self]) {
        let c_flat = Self::from(SBOX_C).to_flat();
        for item in chunk {
            let x = *item;

            // x^2
            let mut term = x.square_flat();
            let mut acc = term;

            // Accumulate powers:
            // x^4, x^8 ... x^128
            for _ in 0..6 {
                term = term.square_flat();
                acc = acc.mul_flat(term);
            }

            // Affine transformation: + 0x63
            *item = acc + c_flat;
        }
    }
}
