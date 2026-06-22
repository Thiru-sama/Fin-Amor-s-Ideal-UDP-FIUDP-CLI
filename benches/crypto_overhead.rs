use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fiudp_cli::internals::{ChaChaEncryptor, Encryptor, derive_nonce};
use fiudp_cli::{SHARD_SIZE, HEADER_SIZE, NONCE_SIZE};
use fiudp_cli::types::{SessionId, ShardIndex};
use rand::RngCore;

fn bench_encrypt_shard(c: &mut Criterion) {
    // Setup
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    let encryptor = ChaChaEncryptor::new(key);
    
    let session_id = SessionId::new(42);
    let shard_index = ShardIndex::new(1);
    let nonce = derive_nonce(session_id, shard_index);
    
    let mut aad = [0u8; HEADER_SIZE];
    rand::thread_rng().fill_bytes(&mut aad);

    let mut buffer = vec![0u8; SHARD_SIZE];
    rand::thread_rng().fill_bytes(&mut buffer);

    let mut group = c.benchmark_group("Crypto");
    group.throughput(criterion::Throughput::Bytes(SHARD_SIZE as u64));
    
    group.bench_function("chacha20_poly1305_encrypt_shard", |b| {
        b.iter(|| {
            // We use a clone of the buffer so we don't just re-encrypt ciphertext,
            // though for raw performance of ChaCha20 it doesn't strictly matter.
            // To keep the inner loop fast, we just encrypt the same buffer in-place repeatedly.
            let _tag = encryptor.encrypt_in_place(
                black_box(&nonce),
                black_box(&aad),
                black_box(&mut buffer)
            ).unwrap();
        })
    });
    
    group.finish();
}

criterion_group!(benches, bench_encrypt_shard);
criterion_main!(benches);
