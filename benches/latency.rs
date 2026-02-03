use core::hint::black_box;
use criterion::{Criterion, criterion_group, criterion_main};
use hekate_groestl::mock::MockBlock128;
use hekate_groestl::{STATE_SIZE, permutation};
// use hekate_math::Block128;

type F = MockBlock128;
//type F = Block128;

fn permutation_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("Latency");

    // Initialize a zero state
    let mut state = [F::default(); STATE_SIZE];
    let rounds = 12;

    group.bench_function("Permutation_12_Rounds", |b| {
        b.iter(|| {
            // Measure the raw P-permutation function
            permutation(
                black_box(&mut state),
                black_box(false), // is_q = false (P-permutation)
                black_box(rounds),
            );
        })
    });

    group.finish();
}

criterion_group!(benches, permutation_latency);
criterion_main!(benches);
