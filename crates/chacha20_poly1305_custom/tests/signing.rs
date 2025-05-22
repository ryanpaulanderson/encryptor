use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use rand::random;
use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

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

    let mut enc_cmd = Command::new(BIN)
        .args([
            "encrypt",
            "tests/data/sample.txt",
            enc.to_str().unwrap(),
            "--sign-key",
            priv_key.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("encrypt");
    enc_cmd
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"pass\n")
        .unwrap();
    assert!(enc_cmd.wait().expect("enc wait").success());

    let mut dec_cmd = Command::new(BIN)
        .args([
            "decrypt",
            enc.to_str().unwrap(),
            dec.to_str().unwrap(),
            "--verify-key",
            pub_key.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("decrypt");
    dec_cmd
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"pass\n")
        .unwrap();
    assert!(dec_cmd.wait().expect("dec wait").success());
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

    let mut enc_cmd = Command::new(BIN)
        .args([
            "encrypt",
            "tests/data/sample.txt",
            enc.to_str().unwrap(),
            "--sign-key",
            priv_key.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    enc_cmd.stdin.as_mut().unwrap().write_all(b"pw\n").unwrap();
    enc_cmd.wait().unwrap();

    // flip a byte in the embedded signature
    let mut data = fs::read(&enc).unwrap();
    data[chacha20_poly1305_custom::HEADER_LEN - 1] ^= 1;
    fs::write(&enc, data).unwrap();

    let mut dec_cmd = Command::new(BIN)
        .args([
            "decrypt",
            enc.to_str().unwrap(),
            dec.to_str().unwrap(),
            "--verify-key",
            pub_key.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    dec_cmd.stdin.as_mut().unwrap().write_all(b"pw\n").unwrap();
    let status = dec_cmd.wait().unwrap();
    assert!(!status.success());
}

#[test]
fn verify_fails_when_missing_signature() {
    let dir = tempfile::tempdir().unwrap();
    let (_, pub_key) = gen_keys(dir.path());
    let enc = dir.path().join("out.bin");
    let dec = dir.path().join("dec.txt");

    let mut enc_cmd = Command::new(BIN)
        .args(["encrypt", "tests/data/sample.txt", enc.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    enc_cmd.stdin.as_mut().unwrap().write_all(b"pw2\n").unwrap();
    enc_cmd.wait().unwrap();

    let mut dec_cmd = Command::new(BIN)
        .args([
            "decrypt",
            enc.to_str().unwrap(),
            dec.to_str().unwrap(),
            "--verify-key",
            pub_key.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    dec_cmd.stdin.as_mut().unwrap().write_all(b"pw2\n").unwrap();
    let status = dec_cmd.wait().unwrap();
    assert!(!status.success());
}

#[cfg(unix)]
#[test]
fn warn_on_permissive_sign_key() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let (priv_key, _pub_key) = gen_keys(dir.path());
    fs::set_permissions(&priv_key, fs::Permissions::from_mode(0o644)).unwrap();
    let enc = dir.path().join("out.bin");
    let output = {
        let mut child = Command::new(BIN)
            .args([
                "encrypt",
                "tests/data/sample.txt",
                enc.to_str().unwrap(),
                "--sign-key",
                priv_key.to_str().unwrap(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("encrypt");
        child.stdin.as_mut().unwrap().write_all(b"pw\n").unwrap();
        child.wait_with_output().expect("output")
    };
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Warning"));
}

proptest! {
    #[test]
    fn prop_sign_verify_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let sk_bytes: [u8; 32] = rand::random();
        let sk = SigningKey::from_bytes(&sk_bytes);
        let pk = sk.verifying_key();
        let sig = chacha20_poly1305_custom::sign(&data, &sk);
        prop_assert!(chacha20_poly1305_custom::verify(&data, &sig, &pk));
    }

    #[test]
    fn prop_verify_detects_modification(mut data in proptest::collection::vec(any::<u8>(), 1..512)) {
        let sk_bytes: [u8; 32] = rand::random();
        let sk = SigningKey::from_bytes(&sk_bytes);
        let pk = sk.verifying_key();
        let sig = chacha20_poly1305_custom::sign(&data, &sk);
        data[0] ^= 1;
        prop_assert!(!chacha20_poly1305_custom::verify(&data, &sig, &pk));
    }
}
