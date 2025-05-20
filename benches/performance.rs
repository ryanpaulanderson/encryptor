use criterion::{black_box, criterion_group, criterion_main, Criterion};
use encryptor::{chacha20_block, encrypt_decrypt_in_place};
use secrecy::Secret;

fn bench_chacha20_block(c: &mut Criterion) {
    let key = Secret::new([0u8; 32]);
    let nonce = [0u8; 12];
    c.bench_function("chacha20_block", |b| {
        b.iter(|| {
            black_box(chacha20_block(&key, 1, &nonce));
        });
    });
}

fn bench_encrypt_decrypt_in_place(c: &mut Criterion) {
    let key = Secret::new([0u8; 32]);
    let nonce = [0u8; 12];
    let data = vec![0u8; 1024];
    c.bench_function("encrypt_decrypt_in_place", |b| {
        b.iter(|| {
            let mut buf = data.clone();
            let mut counter = 0u32;
            encrypt_decrypt_in_place(&mut buf, &key, &nonce, &mut counter);
            black_box(buf);
        });
    });
}

criterion_group!(
    benches,
    bench_chacha20_block,
    bench_encrypt_decrypt_in_place
);
criterion_main!(benches);
