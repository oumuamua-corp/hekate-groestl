use hekate_groestl::MIX_P;
use hekate_math::{Block128, HardwareField, TowerField};

/// Helper to invert in flat basis.
fn invert_flat(val: Block128) -> Option<Block128> {
    let tower_val = val.convert_hardware();
    let inv_tower = tower_val.invert()?;

    Some(inv_tower.to_hardware())
}

/// Checks if a matrix is MDS (Maximum Distance Separable).
/// An NxN matrix is MDS iff EVERY square submatrix is non-singular.
/// Check determinants of all square submatrices.
fn is_mds_circulant(row: &[u8; 4]) -> bool {
    let n = 4;

    // Construct the full 4x4 matrix
    let mut matrix = [[Block128::ZERO; 4]; 4];
    for (r, out_row) in matrix.iter_mut().enumerate() {
        for (c, cell) in out_row.iter_mut().enumerate() {
            let idx = (n - r + c) % n;
            *cell = Block128::from(row[idx] as u64).to_hardware();
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
                for (r, row_vals) in matrix.iter().enumerate() {
                    if (r_mask >> r) & 1 == 1 {
                        for (c, &val) in row_vals.iter().enumerate() {
                            if (c_mask >> c) & 1 == 1 {
                                sub.push(val);
                            }
                        }
                    }
                }

                // Check singularity
                if determinant(&sub, k) == Block128::ZERO {
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
fn determinant(flat_matrix: &[Block128], n: usize) -> Block128 {
    // 1. Base Cases & Optimizations
    match n {
        0 => return Block128::ONE.to_hardware(),
        1 => return flat_matrix[0],
        2 => {
            // | a b |
            // | c d | -> ad + bc
            let ad = flat_matrix[0].mul_hardware(flat_matrix[3]);
            let bc = flat_matrix[1].mul_hardware(flat_matrix[2]);

            return ad + bc;
        }
        3 => {
            // Rule of Sarrus
            let m = flat_matrix;

            // Diagonals
            let d1 = m[0].mul_hardware(m[4]).mul_hardware(m[8]);
            let d2 = m[1].mul_hardware(m[5]).mul_hardware(m[6]);
            let d3 = m[2].mul_hardware(m[3]).mul_hardware(m[7]);

            // Anti-diagonals
            let a1 = m[2].mul_hardware(m[4]).mul_hardware(m[6]);
            let a2 = m[1].mul_hardware(m[3]).mul_hardware(m[8]);
            let a3 = m[0].mul_hardware(m[5]).mul_hardware(m[7]);

            return d1 + d2 + d3 + a1 + a2 + a3;
        }
        _ => {} // Fallback to Gauss
    }

    // 2. Gaussian Elimination for N > 3 (Flat Basis)
    let mut mat = flat_matrix.to_vec();

    for i in 0..n {
        // A. Find Pivot
        let mut pivot_row = i;
        while pivot_row < n && mat[pivot_row * n + i] == Block128::ZERO {
            pivot_row += 1;
        }

        if pivot_row == n {
            return Block128::ZERO;
        }

        // B. Swap rows
        if pivot_row != i {
            for col in 0..n {
                mat.swap(i * n + col, pivot_row * n + col);
            }
        }

        // C. Eliminate rows
        let pivot_val = mat[i * n + i];

        // Invert in Flat Basis
        let pivot_inv = invert_flat(pivot_val).expect("Pivot inversion failed logic error");

        for j in (i + 1)..n {
            let target_val = mat[j * n + i];
            if target_val != Block128::ZERO {
                let factor = target_val.mul_hardware(pivot_inv);

                // Row_j += factor * Row_i
                // Start from `col = i` because previous cols are 0
                for col in i..n {
                    let val_i = mat[i * n + col];
                    let val_j = mat[j * n + col];

                    // Row_j += factor * Row_i
                    mat[j * n + col] = val_j + factor.mul_hardware(val_i);
                }
            }
        }
    }

    // 3. Product of Diagonal
    let mut det = Block128::ONE.to_hardware();
    for i in 0..n {
        det = det.mul_hardware(mat[i * n + i]);
    }

    det
}

#[test]
fn verify_mds_integrity() {
    println!(">>> Verifying Groestl MDS Constants (Hardware Basis)...");

    // Check if MIX_P coefficients are valid
    // for the hardware polynomial (0x87).
    let is_valid = is_mds_circulant(&MIX_P);
    if is_valid {
        println!("Groestl constants form a valid MDS matrix in Flat Basis");
    } else {
        panic!("The diffusion property is BROKEN in Flat Basis. MDS Mismatch detected");
    }
}
