use hekate_groestl::{HekateGroestl, MockBlock128, STATE_SIZE, compress};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

type F = MockBlock128;

#[test]
fn profile_memory_usage() {
    let _profiler = dhat::Profiler::builder().testing().build();

    println!(">>> Starting Memory Audit...");

    // Pre-allocate data on stack
    let input = [F::from(0xDEADBEEFu128); STATE_SIZE];
    let mut state = [F::default(); STATE_SIZE];
    let msg = [F::default(); STATE_SIZE];
    let rounds = 10;

    let stats_before = dhat::HeapStats::get();

    // 1: Full Hash Cycle
    {
        let mut hasher = HekateGroestl::<F>::new(rounds);
        hasher.update_elements(&input);
        let _res = hasher.finalize_raw();
        std::hint::black_box(_res);
    }

    // 2: Low-level Compress
    {
        compress(&mut state, &msg, rounds);
    }

    let stats_after = dhat::HeapStats::get();

    // Calculate delta. usage.
    let total_blocks_allocated = stats_after.total_blocks - stats_before.total_blocks;
    let total_bytes_allocated = stats_after.total_bytes - stats_before.total_bytes;

    println!("--- Memory Stats ---");
    println!("Total Allocations: {} blocks", total_blocks_allocated);
    println!("Total Bytes:       {} bytes", total_bytes_allocated);
    println!(
        "Peak Heap:         {:.2} KB",
        stats_after.max_bytes as f64 / 1024.0
    );

    if total_blocks_allocated > 0 {
        panic!("Expected 0 allocations, found {}", total_blocks_allocated);
    }
}
