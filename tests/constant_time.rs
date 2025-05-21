use encryptor::{ct_eq, decrypt_priv_key, encrypt_priv_key, Argon2Config, ENC_KEY_LEN};
use std::time::Instant;

// Run the given closure `iters` times, returning elapsed duration
fn bench<F: FnMut()>(mut f: F, iters: usize) -> std::time::Duration {
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    start.elapsed()
}

#[test]
fn ct_eq_timing_consistency() {
    const LEN: usize = 1024;
    const ITERS: usize = 250;

    let a = vec![0u8; LEN];
    let mut b = vec![0u8; LEN];

    let equal = bench(
        || {
            for _ in 0..100 {
                let _ = ct_eq(&a, &b);
            }
        },
        ITERS,
    );

    b[0] = 1;
    let diff_first = bench(
        || {
            for _ in 0..100 {
                let _ = ct_eq(&a, &b);
            }
        },
        ITERS,
    );

    b[0] = 0;
    b[LEN - 1] = 1;
    let diff_last = bench(
        || {
            for _ in 0..100 {
                let _ = ct_eq(&a, &b);
            }
        },
        ITERS,
    );

    // Compute relative difference between durations
    fn similar(a: std::time::Duration, b: std::time::Duration) -> bool {
        let (long, short) = if a > b { (a, b) } else { (b, a) };
        let diff = long - short;
        diff.as_secs_f64() < long.as_secs_f64() * 0.2
    }

    assert!(
        similar(equal, diff_first),
        "equal vs first byte diff timing skew too high"
    );
    assert!(
        similar(diff_first, diff_last),
        "first vs last byte diff timing skew too high"
    );
}

#[test]
fn decrypt_priv_key_timing_consistency() {
    const ITERS: usize = 250;

    let seed = [0u8; 32];
    let cfg = Argon2Config {
        mem_cost_kib: 64,
        time_cost: 1,
        parallelism: 1,
    };
    let enc = encrypt_priv_key(&seed, "pw", &cfg).unwrap();

    let decrypt_good = bench(
        || {
            let _ = decrypt_priv_key(&enc, "pw");
        },
        ITERS,
    );

    let mut diff_first = enc.clone();
    diff_first[ENC_KEY_LEN - 16] ^= 1;
    let decrypt_diff_first = bench(
        || {
            let _ = decrypt_priv_key(&diff_first, "pw");
        },
        ITERS,
    );

    let mut diff_last = enc.clone();
    diff_last[ENC_KEY_LEN - 1] ^= 1;
    let decrypt_diff_last = bench(
        || {
            let _ = decrypt_priv_key(&diff_last, "pw");
        },
        ITERS,
    );

    fn similar(a: std::time::Duration, b: std::time::Duration) -> bool {
        let (long, short) = if a > b { (a, b) } else { (b, a) };
        let diff = long - short;
        diff.as_secs_f64() < long.as_secs_f64() * 0.2
    }

    assert!(
        similar(decrypt_good, decrypt_diff_first),
        "decrypt vs diff_first timing skew too high"
    );
    assert!(
        similar(decrypt_diff_first, decrypt_diff_last),
        "diff_first vs diff_last timing skew too high"
    );
}
