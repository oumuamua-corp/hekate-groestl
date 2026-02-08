use core::hint::black_box;
use core::time::Duration;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use hekate_groestl::{Hasher, compress_node, compress_node_prp};
use hekate_math::{Block128, HardwareField};

fn merkle_node_compression(c: &mut Criterion) {
    let mut group = c.benchmark_group("MerkleNode");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(500);
    group.throughput(Throughput::Elements(2));

    let left = [
        Block128::from(0xDEAD_BEEF_u64).to_hardware(),
        Block128::from(0xCAFE_BABE_u64).to_hardware(),
    ];
    let right = [
        Block128::from(0xAAAA_BBBB_u64).to_hardware(),
        Block128::from(0xCCCC_DDDD_u64).to_hardware(),
    ];

    // 1. General-purpose Hasher struct
    group.bench_function("Hasher", |b| {
        b.iter(|| {
            let mut hasher = Hasher::new();
            hasher.update_elements(black_box(&left));
            hasher.update_elements(black_box(&right));

            black_box(hasher.finalize_raw())
        })
    });

    // 2. Uses P and Q permutations (Davies-Meyer)
    group.bench_function("Compress_Node", |b| {
        b.iter(|| compress_node(black_box(left), black_box(right)))
    });

    // 3. Uses single P permutation (Sponge-like)
    group.bench_function("Compress_Node_PRP", |b| {
        b.iter(|| compress_node_prp(black_box(left), black_box(right)))
    });

    group.finish();
}

fn bulk_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("BulkThroughput");
    group.sample_size(10);

    // 1 MB worth of field elements
    // 65536 elements * 16 bytes = 1 MiB
    let num_elements = 65_536;
    let total_bytes = (num_elements * 16) as u64;

    group.throughput(Throughput::Bytes(total_bytes));

    // Prepare large data vector
    let data: Vec<Block128> = (0..num_elements)
        .map(|i| Block128::from(i as u64).to_hardware())
        .collect();

    group.bench_function("1MB_Buffer", |b| {
        b.iter(|| {
            let mut hasher = Hasher::new();
            hasher.update_elements(black_box(&data));

            black_box(hasher.finalize_raw())
        })
    });

    group.finish();
}

criterion_group!(benches, merkle_node_compression, bulk_hashing);
criterion_main!(benches);
