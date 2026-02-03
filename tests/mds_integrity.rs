use hekate_groestl::MIX_P;
use hekate_groestl::mock::MockBlock128;
// use hekate_math::{Block128, TowerField};

// type F = Block128;
type F = MockBlock128;

/// Checks if a matrix is MDS (Maximum Distance Separable).
/// An NxN matrix is MDS iff EVERY square submatrix is non-singular.
/// Check determinants of all square submatrices.
fn is_mds_circulant(row: &[u8; 4]) -> bool {
    let n = 4;

    // Construct the full 4x4 matrix
    let mut matrix = [[F::ZERO; 4]; 4];
    for r in 0..n {
        for c in 0..n {
            let idx = (n - r + c) % n;
            let val = row[idx];
            matrix[r][c] = F::from(val as u64);
        }
    }

    // Iterate over all submatrix sizes k from 1 to 4
    for k in 1..=n {
        for r_mask in 1u8..16 {
            if r_mask.count_ones() as usize != k {
                continue;
            }

            for c_mask in 1u8..16 {
                if c_mask.count_ones() as usize != k {
                    continue;
                }

                // Construct submatrix
                let mut sub = Vec::with_capacity(k * k);
                for r in 0..4 {
                    if (r_mask >> r) & 1 == 1 {
                        for c in 0..4 {
                            if (c_mask >> c) & 1 == 1 {
                                sub.push(matrix[r][c]);
                            }
                        }
                    }
                }

                // Check singularity
                if determinant(&sub, k) == F::ZERO {
                    return false;
                }
            }
        }
    }

    true
}

/// Computes determinant using explicit formulas
/// for small N and Gaussian elimination for N > 3.
/// Input is a flat vector representing an n*n matrix.
fn determinant(flat_matrix: &[F], n: usize) -> F {
    // 1. Base Cases & Optimizations
    match n {
        0 => return F::ONE,
        1 => return flat_matrix[0],
        2 => {
            // | a b |
            // | c d | -> ad + bc (in char 2 subtraction is addition)
            return (flat_matrix[0] * flat_matrix[3]) + (flat_matrix[1] * flat_matrix[2]);
        }
        3 => {
            // Rule of Sarrus for 3x3
            // 0 1 2
            // 3 4 5
            // 6 7 8
            let m = flat_matrix;

            // Diagonals
            let d1 = m[0] * m[4] * m[8];
            let d2 = m[1] * m[5] * m[6];
            let d3 = m[2] * m[3] * m[7];

            // Anti-diagonals
            let a1 = m[2] * m[4] * m[6];
            let a2 = m[1] * m[3] * m[8];
            let a3 = m[0] * m[5] * m[7];

            // Sum all (signs don't matter in char 2)
            return d1 + d2 + d3 + a1 + a2 + a3;
        }
        _ => {} // Fallback to Gauss
    }

    // 2. Gaussian Elimination for N > 3
    // Convert matrix to Upper Triangular form.
    // The determinant is then the product of the diagonal entries.
    //
    // Row operations:
    // R_j = R_j + scalar * R_i (Determinant invariant)
    //
    // Row swaps:
    // Det = -Det (In char 2, -Det == Det, so invariant)

    let mut mat = flat_matrix.to_vec();

    for i in 0..n {
        // A. Find Pivot in column i, starting from row i
        let mut pivot_row = i;
        while pivot_row < n && mat[pivot_row * n + i] == F::ZERO {
            pivot_row += 1;
        }

        // If no pivot found, column
        // is all zeros -> Singular matrix
        if pivot_row == n {
            return F::ZERO;
        }

        // B. Swap rows if needed
        if pivot_row != i {
            for col in 0..n {
                mat.swap(i * n + col, pivot_row * n + col);
            }
        }

        // C. Eliminate rows below pivot
        // We want mat[j][i] == 0 for all j > i
        let pivot_val = mat[i * n + i];

        // Invert pivot (guaranteed non-zero check passed above)
        let pivot_inv = pivot_val
            .invert()
            .expect("Pivot inversion failed logic error");

        for j in (i + 1)..n {
            let target_val = mat[j * n + i];
            if target_val != F::ZERO {
                let factor = target_val * pivot_inv;

                // Row_j += factor * Row_i
                // Start from `col = i` because previous cols are 0
                for col in i..n {
                    let val_i = mat[i * n + col];
                    let val_j = mat[j * n + col];

                    // In char 2, add == sub
                    mat[j * n + col] = val_j + (factor * val_i);
                }
            }
        }
    }

    // 3. Product of Diagonal
    let mut det = F::ONE;
    for i in 0..n {
        det = det * mat[i * n + i];
    }

    det
}

#[test]
fn verify_mds_integrity() {
    println!(">>> Verifying Groestl MDS Constants in Block128 Tower Field...");

    let is_valid = is_mds_circulant(&MIX_P);
    if is_valid {
        println!("Groestl constants form a valid MDS matrix");
    } else {
        panic!("The diffusion property is BROKEN. MDS Mismatch detected");
    }
}
