use ed25519_dalek::SigningKey;
use rand::random;
use std::fs;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_chacha20_poly1305");

fn gen_keys(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let sk_bytes: [u8; 32] = random();
    let sk = SigningKey::from_bytes(&sk_bytes);
    let pk = sk.verifying_key();
    let priv_path = dir.join("priv.key");
    let pub_path = dir.join("pub.key");
    fs::write(&priv_path, sk.to_bytes()).unwrap();
    fs::write(&pub_path, pk.to_bytes()).unwrap();
    (priv_path, pub_path)
}

#[test]
fn sign_verify_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let (priv_key, pub_key) = gen_keys(dir.path());
    let enc = dir.path().join("out.bin");
    let dec = dir.path().join("dec.txt");

    let status = Command::new(BIN)
        .args([
            "encrypt",
            "tests/data/sample.txt",
            enc.to_str().unwrap(),
            "pass",
            "--sign-key",
            priv_key.to_str().unwrap(),
        ])
        .status()
        .expect("encrypt");
    assert!(status.success());

    let status = Command::new(BIN)
        .args([
            "decrypt",
            enc.to_str().unwrap(),
            dec.to_str().unwrap(),
            "pass",
            "--verify-key",
            pub_key.to_str().unwrap(),
        ])
        .status()
        .expect("decrypt");
    assert!(status.success());
    assert_eq!(
        fs::read("tests/data/sample.txt").unwrap(),
        fs::read(dec).unwrap()
    );
}

#[test]
fn verify_fails_on_bad_signature() {
    let dir = tempfile::tempdir().unwrap();
    let (priv_key, pub_key) = gen_keys(dir.path());
    let enc = dir.path().join("out.bin");
    let dec = dir.path().join("dec.txt");

    Command::new(BIN)
        .args([
            "encrypt",
            "tests/data/sample.txt",
            enc.to_str().unwrap(),
            "pw",
            "--sign-key",
            priv_key.to_str().unwrap(),
        ])
        .status()
        .unwrap();

    // flip last byte
    let mut data = fs::read(&enc).unwrap();
    let last = data.len() - 1;
    data[last] ^= 1;
    fs::write(&enc, data).unwrap();

    let status = Command::new(BIN)
        .args([
            "decrypt",
            enc.to_str().unwrap(),
            dec.to_str().unwrap(),
            "pw",
            "--verify-key",
            pub_key.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(!status.success());
}

#[test]
fn verify_fails_when_missing_signature() {
    let dir = tempfile::tempdir().unwrap();
    let (_, pub_key) = gen_keys(dir.path());
    let enc = dir.path().join("out.bin");
    let dec = dir.path().join("dec.txt");

    Command::new(BIN)
        .args([
            "encrypt",
            "tests/data/sample.txt",
            enc.to_str().unwrap(),
            "pw2",
        ])
        .status()
        .unwrap();

    let status = Command::new(BIN)
        .args([
            "decrypt",
            enc.to_str().unwrap(),
            dec.to_str().unwrap(),
            "pw2",
            "--verify-key",
            pub_key.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(!status.success());
}
