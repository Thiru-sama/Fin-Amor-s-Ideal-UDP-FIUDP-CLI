use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use fiudp_cli::error::Result;
use fiudp_cli::internals::{
    ChaChaEncryptor, FiudpSender, InputReader, PacketSender, ParityRatio, ReedSolomonEngine,
};
use fiudp_cli::types::{RendezvousSecs, SessionId};
use std::time::Duration;

// --- Mock Implementations for benchmarking ---

struct MockReader {
    payload: Vec<u8>,
}

impl InputReader for MockReader {
    fn read_all(&self) -> Result<Vec<u8>> {
        Ok(self.payload.clone())
    }
}

struct MockSender;

impl PacketSender for MockSender {
    fn send(&self, _packet: &[u8]) -> Result<()> {
        // Do nothing, just simulate a successful write to OS buffers
        Ok(())
    }
}

fn bench_pipeline_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("Pipeline");

    // Standard e-ink TRMNL payload sizes:
    // 5KB (compressed/indexed), 48KB (raw 1bpp 800x480)
    let payload_sizes = [5_000, 48_000, 100_000];
    let parity_ratio = ParityRatio::try_from(25).unwrap(); // 25% FEC

    let key = [0x42; 32];

    for &size in &payload_sizes {
        let payload = vec![0xAA; size]; // Dummy data

        group.throughput(criterion::Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                // We recreate the pipeline components for each iteration to avoid state issues,
                // but these are very lightweight to instantiate.
                let reader = MockReader {
                    payload: payload.clone(),
                };
                let fec = ReedSolomonEngine;
                let encryptor = ChaChaEncryptor::new(key);
                let sender = MockSender;

                let pipeline = FiudpSender::new(
                    reader,
                    fec,
                    encryptor,
                    sender,
                    Duration::from_secs(0),
                    0,
                    0,
                    false,
                );

                pipeline
                    .send(
                        black_box(parity_ratio),
                        black_box(RendezvousSecs::new(3600)),
                        black_box(SessionId::new(1)),
                    )
                    .unwrap();
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_pipeline_throughput);
criterion_main!(benches);
