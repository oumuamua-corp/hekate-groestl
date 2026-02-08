use hekate_groestl::{compress_node, compress_node_prp};
use hekate_math::{Block128, HardwareField, TowerField};

#[test]
fn compress_node_is_deterministic() {
    let left = [
        Block128::from(0xDEAD_BEEF_CAFE_BABE_u128).to_hardware(),
        Block128::from(0x0123_4567_89AB_CDEF_u128).to_hardware(),
    ];
    let right = [
        Block128::from(0x0BAD_F00D_FEED_FACE_u128).to_hardware(),
        Block128::from(0xFEDC_BA98_7654_3210_u128).to_hardware(),
    ];

    let a1 = compress_node(left, right);
    let a2 = compress_node(left, right);
    assert_eq!(a1, a2);

    let b1 = compress_node_prp(left, right);
    let b2 = compress_node_prp(left, right);
    assert_eq!(b1, b2);
}

#[test]
fn compress_node_is_order_sensitive() {
    let left = [
        Block128::from(1u128).to_hardware(),
        Block128::from(2u128).to_hardware(),
    ];
    let right = [
        Block128::from(3u128).to_hardware(),
        Block128::from(4u128).to_hardware(),
    ];

    let a_lr = compress_node(left, right);
    let a_rl = compress_node(right, left);
    assert_ne!(a_lr, a_rl);

    let b_lr = compress_node_prp(left, right);
    let b_rl = compress_node_prp(right, left);
    assert_ne!(b_lr, b_rl);
}

#[test]
fn compress_node_variants_are_domain_separated() {
    let left = [
        Block128::from(0xAA55_AA55_AA55_AA55_u128).to_hardware(),
        Block128::from(0x55AA_55AA_55AA_55AA_u128).to_hardware(),
    ];
    let right = [
        Block128::from(0x0u128).to_hardware(),
        Block128::from(0xFFFF_FFFF_FFFF_FFFF_u128).to_hardware(),
    ];

    let a = compress_node(left, right);
    let b = compress_node_prp(left, right);

    assert_ne!(a, b);

    // Sanity:
    // avoid trivial all-zero outputs.
    assert_ne!(a, [Block128::ZERO, Block128::ZERO]);
    assert_ne!(b, [Block128::ZERO, Block128::ZERO]);
}
