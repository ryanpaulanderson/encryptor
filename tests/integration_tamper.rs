use proptest::prelude::*;
use rand::random;
use sha2::{Digest, Sha256};
use std::fs;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_chacha20_poly1305");

fn encrypt_file(input: &str, password: &str) -> std::path::PathBuf {
    let mut out = std::env::temp_dir();
    out.push(format!("enc-{}-{}.bin", password, random::<u32>()));
    let status = Command::new(BIN)
        .args(["encrypt", input, out.to_str().unwrap(), password])
        .status()
        .expect("run encrypt");
    assert!(status.success());
    out
}

fn decrypt_file(
    input: &std::path::Path,
    output: &std::path::Path,
    password: &str,
    verify: Option<&str>,
) -> std::process::ExitStatus {
    let mut cmd = Command::new(BIN);
    cmd.arg("decrypt").arg(input).arg(output).arg(password);
    if let Some(v) = verify {
        cmd.arg("--verify-hash").arg(v);
    }
    cmd.status().expect("run decrypt")
}

#[test]
fn verify_hash_success() {
    let input = "tests/data/sample.txt";
    let pass = "hashpass";
    let enc = encrypt_file(input, pass);

    let data = fs::read(&enc).unwrap();
    let digest = Sha256::digest(&data);
    let hex = hex::encode(digest);

    let mut dec = std::env::temp_dir();
    dec.push("dec-hash.txt");
    let status = decrypt_file(&enc, &dec, pass, Some(&hex));
    assert!(status.success());

    let orig = fs::read(input).unwrap();
    let new = fs::read(&dec).unwrap();
    assert_eq!(orig, new);

    let _ = fs::remove_file(enc);
    let _ = fs::remove_file(dec);
}

#[test]
fn verify_hash_failure() {
    let input = "tests/data/sample.txt";
    let pass = "hashfail";
    let enc = encrypt_file(input, pass);

    let data = fs::read(&enc).unwrap();
    let digest = Sha256::digest(&data);
    let hex = hex::encode(digest);

    // modify encrypted file so hash does not match
    let mut tampered = data.clone();
    tampered[encryptor::HEADER_LEN + 4] ^= 0x01;
    fs::write(&enc, &tampered).unwrap();

    let mut dec = std::env::temp_dir();
    dec.push("dec-fail.txt");
    let status = decrypt_file(&enc, &dec, pass, Some(&hex));
    assert!(!status.success());

    let _ = fs::remove_file(enc);
    let _ = fs::remove_file(dec);
}

#[test]
fn tampered_ciphertext_detected() {
    let input = "tests/data/sample.txt";
    let pass = "tamperct";
    let enc = encrypt_file(input, pass);

    let mut ct = fs::read(&enc).unwrap();
    ct[encryptor::HEADER_LEN + 14] ^= 0x20; // flip a bit in ciphertext
    fs::write(&enc, &ct).unwrap();

    let mut dec = std::env::temp_dir();
    dec.push("dec-ct.txt");
    let status = decrypt_file(&enc, &dec, pass, None);
    assert!(!status.success());

    let _ = fs::remove_file(enc);
    let _ = fs::remove_file(dec);
}

#[test]
fn tampered_header_detected() {
    let input = "tests/data/sample.txt";
    let pass = "tamperhdr";
    let enc = encrypt_file(input, pass);

    let mut data = fs::read(&enc).unwrap();
    // flip a bit in the magic/header
    data[0] ^= 0xFF;
    fs::write(&enc, &data).unwrap();

    let mut dec = std::env::temp_dir();
    dec.push("dec-hdr.txt");
    let status = decrypt_file(&enc, &dec, pass, None);
    assert!(!status.success());

    let _ = fs::remove_file(enc);
    let _ = fs::remove_file(dec);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn malformed_header_cases(case in 0u8..5) {
        let input = "tests/data/sample.txt";
        let pass = "propbad";
        let enc = encrypt_file(input, pass);
        let mut data = fs::read(&enc).unwrap();

        match case {
            0 => { // wrong magic
                data[..4].copy_from_slice(b"BAD!");
            }
            1 => { // wrong version
                data[4] = data[4].wrapping_add(1);
            }
            2 => { // truncated salt byte
                data.remove(8);
            }
            3 => { // truncated nonce byte
                data.remove(24);
            }
            _ => { // extra byte after header
                data.insert(encryptor::HEADER_LEN, 0); // insert zero before ciphertext
            }
        }

        fs::write(&enc, &data).unwrap();
        let mut dec = std::env::temp_dir();
        dec.push("dec-malform.txt");
        let status = decrypt_file(&enc, &dec, pass, None);
        assert!(!status.success());

        let _ = fs::remove_file(enc);
        let _ = fs::remove_file(dec);
    }
}
