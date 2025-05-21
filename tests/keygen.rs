use std::fs;
use std::process::Command;

use encryptor::ENC_KEY_LEN;

const BIN: &str = env!("CARGO_BIN_EXE_chacha20_poly1305");

#[test]
fn generate_keys_creates_files() {
    let dir = tempfile::tempdir().unwrap();
    let status = Command::new(BIN)
        .args(["--generate-keys", dir.path().to_str().unwrap()])
        .status()
        .expect("run keygen");
    assert!(status.success());
    let priv_path = dir.path().join("priv.key");
    let pub_path = dir.path().join("pub.key");
    assert_eq!(fs::read(&priv_path).unwrap().len(), 32);
    assert_eq!(fs::read(&pub_path).unwrap().len(), 32);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&priv_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn generated_keys_sign_and_verify() {
    let dir = tempfile::tempdir().unwrap();
    Command::new(BIN)
        .args(["--generate-keys", dir.path().to_str().unwrap()])
        .status()
        .expect("run keygen");
    let priv_key = dir.path().join("priv.key");
    let pub_key = dir.path().join("pub.key");
    let enc = dir.path().join("out.bin");
    let dec = dir.path().join("out.txt");

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
fn encrypted_key_sign_and_verify() {
    let dir = tempfile::tempdir().unwrap();
    Command::new(BIN)
        .args([
            "--generate-keys",
            dir.path().to_str().unwrap(),
            "--key-password",
            "pw",
        ])
        .status()
        .expect("run keygen");
    let priv_key = dir.path().join("priv.ekey");
    let pub_key = dir.path().join("pub.key");
    assert_eq!(fs::read(&priv_key).unwrap().len(), ENC_KEY_LEN);

    let enc = dir.path().join("out.bin");
    let dec = dir.path().join("out.txt");

    let status = Command::new(BIN)
        .args([
            "encrypt",
            "tests/data/sample.txt",
            enc.to_str().unwrap(),
            "pw1",
            "--sign-key",
            priv_key.to_str().unwrap(),
            "--key-password",
            "pw",
        ])
        .status()
        .expect("encrypt");
    assert!(status.success());

    let status = Command::new(BIN)
        .args([
            "decrypt",
            enc.to_str().unwrap(),
            dec.to_str().unwrap(),
            "pw1",
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
fn encrypted_key_missing_password_fails() {
    let dir = tempfile::tempdir().unwrap();
    Command::new(BIN)
        .args([
            "--generate-keys",
            dir.path().to_str().unwrap(),
            "--key-password",
            "pw",
        ])
        .status()
        .expect("run keygen");
    let priv_key = dir.path().join("priv.ekey");
    let enc = dir.path().join("out.bin");

    let status = Command::new(BIN)
        .args([
            "encrypt",
            "tests/data/sample.txt",
            enc.to_str().unwrap(),
            "pw2",
            "--sign-key",
            priv_key.to_str().unwrap(),
        ])
        .status()
        .expect("encrypt");
    assert!(!status.success());
}
