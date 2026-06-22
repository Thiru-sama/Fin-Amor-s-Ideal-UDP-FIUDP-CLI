use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use fiudp_cli::internals::{FecEngine, ReedSolomonEngine};
use fiudp_cli::SHARD_SIZE;
use rand::RngCore;

fn bench_fec_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("FEC");
    let fec = ReedSolomonEngine;

    // A typical 800x480 1bpp image is 48000 bytes.
    // SHARD_SIZE is 1400 bytes, so ~35 data shards.
    let data_shards_counts = [10, 35, 100]; 
    let parity_ratios = [0.1, 0.25, 0.5]; // 10%, 25%, 50% parity

    for &ds in &data_shards_counts {
        for &ratio in &parity_ratios {
            let ps = (ds as f64 * ratio).ceil() as usize;
            let total_shards = ds + ps;

            let mut shards_data = vec![vec![0u8; SHARD_SIZE]; total_shards];
            for i in 0..ds {
                rand::thread_rng().fill_bytes(&mut shards_data[i]);
            }

            group.throughput(criterion::Throughput::Bytes((ds * SHARD_SIZE) as u64));
            
            group.bench_with_input(BenchmarkId::new(format!("RS_{}ds_{}ps", ds, ps), ratio), &ratio, |b, _| {
                b.iter(|| {
                    // We need to re-borrow the mutable slices each time
                    let mut shard_refs: Vec<&mut [u8]> = shards_data.iter_mut().map(|v| v.as_mut_slice()).collect();
                    fec.encode(
                        black_box(ds),
                        black_box(ps),
                        black_box(&mut shard_refs)
                    ).unwrap();
                })
            });
        }
    }
    
    group.finish();
}

criterion_group!(benches, bench_fec_encode);
criterion_main!(benches);
