use criterion::{criterion_group, criterion_main, Criterion};
use encryptor::{encrypt_file, EncryptOptions, Password};
use std::fs;
use std::hint::black_box;
use std::time::Duration;

fn file_encryption(c: &mut Criterion) {
    let directory = tempfile::tempdir().expect("benchmark directory");
    let input = directory.path().join("input");
    fs::write(&input, vec![0x5a; 1_048_576]).expect("benchmark input");
    let mut sequence = 0u64;

    let mut group = c.benchmark_group("authenticated_file_workflow");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));
    group.bench_function("encrypt_1mib_including_argon2", |bencher| {
        bencher.iter(|| {
            sequence += 1;
            let output = directory.path().join(format!("output-{sequence}"));
            let password = Password::new("benchmark password".to_owned()).expect("password");
            let outcome = encrypt_file(
                black_box(&input),
                &output,
                &password,
                EncryptOptions::unsigned(),
            )
            .expect("benchmark encryption");
            let _ = black_box(outcome);
            fs::remove_file(output).expect("remove benchmark output");
        });
    });
    group.finish();
}

criterion_group!(benches, file_encryption);
criterion_main!(benches);
