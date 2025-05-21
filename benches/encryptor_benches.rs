use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ed25519_dalek::SigningKey;
use encryptor::{chacha20_block, encrypt_decrypt_in_place, sign, verify, Ed25519PrivKey};
use rand_core::OsRng;
use secrecy::SecretBox;

fn bench_chacha20_block(c: &mut Criterion) {
    let key = SecretBox::new(Box::new([0u8; 32]));
    let nonce = [0u8; 12];
    c.bench_function("chacha20_block", |b| {
        b.iter(|| {
            black_box(chacha20_block(&key, 1, &nonce));
        });
    });
}

fn bench_encrypt_decrypt_in_place(c: &mut Criterion) {
    let key = SecretBox::new(Box::new([0u8; 32]));
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

fn bench_keypair_generation(c: &mut Criterion) {
    c.bench_function("keypair_generation", |b| {
        b.iter(|| {
            let key: Ed25519PrivKey = SigningKey::generate(&mut OsRng);
            black_box(key);
        });
    });
}

fn bench_encrypt_with_keypair(c: &mut Criterion) {
    let mut rng = OsRng;
    let sk = SigningKey::generate(&mut rng);
    let key = SecretBox::new(Box::new([0u8; 32]));
    let nonce = [0u8; 12];
    let data = vec![0u8; 1024];
    c.bench_function("encrypt_with_keypair", |b| {
        b.iter(|| {
            let mut buf = data.clone();
            let mut counter = 1u32;
            encrypt_decrypt_in_place(&mut buf, &key, &nonce, &mut counter);
            let sig = sign(&buf, &sk);
            black_box(sig);
        });
    });
}

fn bench_decrypt_with_keypair(c: &mut Criterion) {
    let mut rng = OsRng;
    let sk = SigningKey::generate(&mut rng);
    let pk = sk.verifying_key();
    let key = SecretBox::new(Box::new([0u8; 32]));
    let nonce = [0u8; 12];
    let data = vec![0u8; 1024];
    // pre-encrypt and sign so benchmark focuses on verify+decrypt
    let mut cipher = data.clone();
    let mut counter = 1u32;
    encrypt_decrypt_in_place(&mut cipher, &key, &nonce, &mut counter);
    let sig = sign(&cipher, &sk);
    c.bench_function("decrypt_with_keypair", |b| {
        b.iter(|| {
            let mut buf = cipher.clone();
            assert!(verify(&buf, &sig, &pk));
            let mut ctr = 1u32;
            encrypt_decrypt_in_place(&mut buf, &key, &nonce, &mut ctr);
            black_box(buf);
        });
    });
}

criterion_group!(
    benches,
    bench_chacha20_block,
    bench_encrypt_decrypt_in_place,
    bench_keypair_generation,
    bench_encrypt_with_keypair,
    bench_decrypt_with_keypair
);
criterion_main!(benches);
