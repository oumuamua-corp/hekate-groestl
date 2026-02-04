use core::hint::black_box;
use core::time::Duration;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use hekate_groestl::{HekateGroestl, MockBlock128};
// use hekate_math::Block128;

type F = MockBlock128;
//type F = Block128;

fn merkle_node_compression(c: &mut Criterion) {
    let mut group = c.benchmark_group("MerkleNode");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(500);
    group.throughput(Throughput::Elements(2));

    let input = [F::from(0xDEADBEEFu128), F::from(0xCAFEBABEu128)];

    group.bench_function("2-to-1", |b| {
        b.iter(|| {
            let mut hasher = HekateGroestl::<F>::new(12);
            hasher.update_elements(black_box(&input));

            black_box(hasher.finalize_raw())
        })
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
    let data: Vec<F> = (0..num_elements).map(|i| F::from(i as u64)).collect();

    group.bench_function("1MB_Buffer", |b| {
        b.iter(|| {
            let mut hasher = HekateGroestl::<F>::new(10);
            hasher.update_elements(black_box(&data));

            black_box(hasher.finalize_raw())
        })
    });

    group.finish();
}

criterion_group!(benches, merkle_node_compression, bulk_hashing);
criterion_main!(benches);
