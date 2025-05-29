use proptest::prelude::*;
use rand::random;
use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_chacha20_poly1305");

fn run_roundtrip(input: &str, password: &str) {
    let mut enc = std::env::temp_dir();
    enc.push(format!("enc-{}.bin", random::<u32>()));
    let mut dec = std::env::temp_dir();
    dec.push(format!("dec-{}.txt", random::<u32>()));

    let mut enc_cmd = Command::new(BIN)
        .args(["encrypt", input, enc.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("encrypt run");
    enc_cmd
        .stdin
        .as_mut()
        .unwrap()
        .write_all(format!("{}\n", password).as_bytes())
        .unwrap();
    let status = enc_cmd.wait().expect("encrypt wait");
    assert!(status.success());

    let mut dec_cmd = Command::new(BIN)
        .args(["decrypt", enc.to_str().unwrap(), dec.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("decrypt run");
    dec_cmd
        .stdin
        .as_mut()
        .unwrap()
        .write_all(format!("{}\n", password).as_bytes())
        .unwrap();
    let status = dec_cmd.wait().expect("decrypt wait");
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
    #![proptest_config(ProptestConfig::with_cases(8))]
    #[test]
    fn roundtrip_random_password(pass in "[a-zA-Z0-9]{0,2048}") {
        run_roundtrip("tests/data/sample.txt", &pass);
    }
}
