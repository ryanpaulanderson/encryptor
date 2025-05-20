use proptest::prelude::*;
use rand::random;
use std::fs;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_chacha20_poly1305");

fn run_roundtrip(input: &str, password: &str) {
    let mut enc = std::env::temp_dir();
    enc.push(format!("enc-{}.bin", random::<u32>()));
    let mut dec = std::env::temp_dir();
    dec.push(format!("dec-{}.txt", random::<u32>()));

    let status = Command::new(BIN)
        .args(["encrypt", input, enc.to_str().unwrap(), password])
        .status()
        .expect("encrypt run");
    assert!(status.success());

    let status = Command::new(BIN)
        .args([
            "decrypt",
            enc.to_str().unwrap(),
            dec.to_str().unwrap(),
            password,
        ])
        .status()
        .expect("decrypt run");
    assert!(status.success());

    let orig = fs::read(input).unwrap();
    let new = fs::read(&dec).unwrap();
    assert_eq!(orig, new);

    let _ = fs::remove_file(enc);
    let _ = fs::remove_file(dec);
}

#[test]
fn roundtrip_sample_file() {
    run_roundtrip("tests/data/sample.txt", "pass123");
}

#[test]
fn roundtrip_empty_file() {
    run_roundtrip("tests/data/empty.txt", "pass123");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn roundtrip_random_password(pass in "[a-zA-Z0-9]{0,2048}") {
        run_roundtrip("tests/data/sample.txt", &pass);
    }
}
