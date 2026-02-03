use crate::tower::TowerFieldElement;
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub};

/// Mock Field Element simulating GF(2^128).
/// Uses standard AES-GCM polynomial for reduction:
/// x^128 + x^7 + x^2 + x + 1 (0x87).
/// This allows verifying the Hasher logic (padding, buffer)
/// without exposing the proprietary Tower Field arithmetic.
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct MockBlock128(pub u128);

impl MockBlock128 {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);

    /// Computes the multiplicative inverse: 1 / x.
    /// Uses Fermat's Little Theorem: a^(2^128 - 2) = a^-1.
    pub fn invert(&self) -> Option<Self> {
        if *self == Self::ZERO {
            return None;
        }

        // Exponent is 2^128 - 2.
        // In Rust u128, u128::MAX represents 2^128 - 1.
        // So we need u128::MAX - 1.
        let mut exp = u128::MAX - 1;
        let mut base = *self;
        let mut acc = Self::ONE;

        // Standard "Square and Multiply" algorithm
        while exp > 0 {
            if (exp & 1) == 1 {
                acc = acc * base;
            }
            base = base * base;
            exp >>= 1;
        }

        Some(acc)
    }
}

impl From<u64> for MockBlock128 {
    fn from(val: u64) -> Self {
        Self(val as u128)
    }
}

impl From<u128> for MockBlock128 {
    #[inline]
    fn from(val: u128) -> Self {
        Self(val)
    }
}

// Addition in GF(2^n) is XOR
impl Add for MockBlock128 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

impl Sub for MockBlock128 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        self.add(rhs) // In char 2, sub == add
    }
}

impl AddAssign for MockBlock128 {
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

// Multiplication in GF(2^128) using simple
// bit-serial approach (Shift-and-Add).
// Polynomial:
// x^128 + x^7 + x^2 + x + 1.
impl Mul for MockBlock128 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        let mut x = self.0;
        let mut y = rhs.0;
        let mut res = 0u128;

        // Iterate over 128 bits
        for _ in 0..128 {
            // If LSB of y is 1, add x to result
            if (y & 1) != 0 {
                res ^= x;
            }

            // Shift x left (multiply by x)
            let carry = (x >> 127) != 0;
            x <<= 1;

            // If overflowed x^128, XOR with
            // the irreducible poly (0x87)
            // Poly: x^128 + x^7 + x^2 + x + 1
            if carry {
                x ^= 0x87;
            }

            // Move to next bit of y
            y >>= 1;
        }

        Self(res)
    }
}

impl MulAssign for MockBlock128 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

// Implement the Trait required by HekateGroestl
impl TowerFieldElement for MockBlock128 {
    fn to_bytes(&self) -> [u8; 16] {
        self.0.to_le_bytes()
    }
}
