use hekate_math::{Block128, HardwareField, TowerField};

type F = Block128;

/// Cost function for ZK/Circuit efficiency.
/// Lower is better.
fn get_zk_cost(val: u8) -> u32 {
    match val {
        1 => 0, // Identity (Free)
        2 => 1, // Double (1 Shift + 1 Const XOR)
        3 => 2, // Double + Add
        4 => 2, // Double + Double
        5 => 3, // Double^2 + 1
        6 => 3, // (Double + 1) * 2
        7 => 4,
        8 => 3,               // Double^3
        _ => 10 + val as u32, // Expensive constants
    }
}

/// Helper to invert in Flat Basis. Native inversion
/// is only implemented for Tower Basis yet,
/// switch basis, invert, and switch back.
fn invert_flat(val: F) -> Option<F> {
    let tower_val = val.convert_hardware();
    let inv_tower = tower_val.invert()?;

    Some(inv_tower.to_hardware())
}

/// Checks if a 4x4 Circulant Matrix is MDS.
fn is_mds_circulant_4x4(row: &[u8; 4]) -> bool {
    let n = 4;

    // Construct the full 4x4 matrix
    let mut matrix = [[F::ZERO; 4]; 4];
    for r in 0..n {
        for c in 0..n {
            // Circulant shift
            let idx = (n - r + c) % n;
            let val = row[idx];
            matrix[r][c] = F::from(val as u64).to_hardware();
        }
    }

    // Check all square submatrices (1x1 to 4x4)
    for k in 1..=n {
        // Iterate over all row/col masks (bitmask 0..15)
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
                if determinant_generic(&sub, k) == F::ZERO {
                    return false;
                }
            }
        }
    }

    true
}

/// Generic determinant for small N
fn determinant_generic(flat: &[F], n: usize) -> F {
    match n {
        1 => flat[0],
        2 => {
            let ad = flat[0].mul_hardware(flat[3]);
            let bc = flat[1].mul_hardware(flat[2]);

            ad + bc
        }
        3 => {
            // Sarrus rule
            let m = flat;

            // Diagonals
            let d1 = m[0].mul_hardware(m[4]).mul_hardware(m[8]);
            let d2 = m[1].mul_hardware(m[5]).mul_hardware(m[6]);
            let d3 = m[2].mul_hardware(m[3]).mul_hardware(m[7]);

            // Anti-diagonals
            let a1 = m[2].mul_hardware(m[4]).mul_hardware(m[6]);
            let a2 = m[1].mul_hardware(m[3]).mul_hardware(m[8]);
            let a3 = m[0].mul_hardware(m[5]).mul_hardware(m[7]);

            d1 + d2 + d3 + a1 + a2 + a3
        }
        4 => determinant_gaussian(flat, 4),
        _ => determinant_gaussian(flat, n),
    }
}

fn determinant_gaussian(flat_matrix: &[F], n: usize) -> F {
    let mut mat = flat_matrix.to_vec();
    let mut det = F::ONE.to_hardware();

    for i in 0..n {
        let mut pivot = i;
        while pivot < n && mat[pivot * n + i] == F::ZERO {
            pivot += 1;
        }

        if pivot == n {
            return F::ZERO;
        }

        if pivot != i {
            for col in 0..n {
                mat.swap(i * n + col, pivot * n + col);
            }
        }

        let pivot_val = mat[i * n + i];
        let pivot_inv = invert_flat(pivot_val).expect("Pivot is zero, but checked above");

        for j in (i + 1)..n {
            let target = mat[j * n + i];
            if target != F::ZERO {
                let factor = target.mul_hardware(pivot_inv);
                for col in i..n {
                    let val_i = mat[i * n + col];
                    let val_j = mat[j * n + col];
                    mat[j * n + col] = val_j + factor.mul_hardware(val_i);
                }
            }
        }

        det = det.mul_hardware(pivot_val);
    }

    det
}

#[test]
fn find_optimal_mds_4x4() {
    println!(">>> Searching for Optimal 4x4 MDS Matrix for Hekate Groestl...");

    // Candidates:
    // Small coefficients preferred for ZK.
    // Prioritize 1, 2, 3, 4, 5, 8.
    let candidates = [1, 2, 3, 4, 5, 6, 7, 8, 9];

    let mut best_cost = u32::MAX;
    let mut best_row = [0u8; 4];

    // Brute force 4 coefficients:
    // 9^4 = 6561 (Instant)
    for &c0 in &candidates {
        for &c1 in &candidates {
            for &c2 in &candidates {
                for &c3 in &candidates {
                    let row = [c0, c1, c2, c3];

                    // Optimization: Check cost first
                    let current_cost =
                        get_zk_cost(c0) + get_zk_cost(c1) + get_zk_cost(c2) + get_zk_cost(c3);

                    if current_cost >= best_cost {
                        continue;
                    }

                    if is_mds_circulant_4x4(&row) {
                        println!("Found MDS Candidate: {:?} (Cost: {})", row, current_cost);

                        best_cost = current_cost;
                        best_row = row;
                    }
                }
            }
        }
    }

    println!("========================================");
    println!("WINNER: OPTIMAL MATRIX");
    println!("Row: {:?}", best_row);
    println!("Cost: {}", best_cost);
    println!("========================================");

    println!("Expected Operations per Row:");

    for &x in &best_row {
        match x {
            1 => println!(" * 1: Copy"),
            2 => println!(" * 2: Shift + Reduce"),
            3 => println!(" * 3: Shift + Reduce + XOR"),
            _ => println!(" * {}: Complex", x),
        }
    }
}
