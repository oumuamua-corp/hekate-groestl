use core::hint::black_box;
use criterion::{Criterion, criterion_group, criterion_main};
use hekate_groestl::{ROUNDS, STATE_SIZE, compress_node, compress_node_prp, permutation};
use hekate_math::{Block128, HardwareField};

type F = Block128;

fn permutation_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("Latency");
    let mut state = [F::default().to_hardware(); STATE_SIZE];

    group.bench_function(format!("Permutation_{ROUNDS}_Rounds"), |b| {
        b.iter(|| {
            // Measure the raw P-permutation function
            permutation(black_box(&mut state), black_box(false));
        })
    });

    group.finish();
}

fn compression_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("Compression_Latency");

    let left = [Block128::default().to_hardware(); 2];
    let right = [Block128::default().to_hardware(); 2];

    group.bench_function("Compress_Node", |b| {
        b.iter(|| compress_node(black_box(left), black_box(right)))
    });

    group.bench_function("Compress_Node_PRP", |b| {
        b.iter(|| compress_node_prp(black_box(left), black_box(right)))
    });

    group.finish();
}

criterion_group!(benches, permutation_latency, compression_latency);
criterion_main!(benches);
