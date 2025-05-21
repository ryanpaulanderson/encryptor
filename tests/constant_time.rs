use encryptor::ct_eq;
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
    const ITERS: usize = 100_000;

    let a = vec![0u8; LEN];
    let mut b = vec![0u8; LEN];

    let equal = bench(
        || {
            let _ = ct_eq(&a, &b);
        },
        ITERS,
    );

    b[0] = 1;
    let diff_first = bench(
        || {
            let _ = ct_eq(&a, &b);
        },
        ITERS,
    );

    b[0] = 0;
    b[LEN - 1] = 1;
    let diff_last = bench(
        || {
            let _ = ct_eq(&a, &b);
        },
        ITERS,
    );

    // Compute relative difference between durations
    fn similar(a: std::time::Duration, b: std::time::Duration) -> bool {
        let (long, short) = if a > b { (a, b) } else { (b, a) };
        let diff = long - short;
        diff.as_secs_f64() < long.as_secs_f64() * 0.20
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
