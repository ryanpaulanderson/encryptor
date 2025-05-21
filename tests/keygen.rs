use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

use encryptor::ENC_KEY_LEN;

const BIN: &str = env!("CARGO_BIN_EXE_chacha20_poly1305");

#[test]
fn generate_keys_creates_files() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(BIN)
        .args(["--generate-keys", dir.path().to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("run keygen");
    child.stdin.as_mut().unwrap().write_all(b"\n").unwrap();
    assert!(child.wait().expect("keygen wait").success());
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
    let mut gen = Command::new(BIN)
        .args(["--generate-keys", dir.path().to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("run keygen");
    gen.stdin.as_mut().unwrap().write_all(b"\n").unwrap();
    assert!(gen.wait().expect("keygen wait").success());
    let priv_key = dir.path().join("priv.key");
    let pub_key = dir.path().join("pub.key");
    let enc = dir.path().join("out.bin");
    let dec = dir.path().join("out.txt");

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
fn encrypted_key_sign_and_verify() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(BIN)
        .args(["--generate-keys", dir.path().to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("run keygen");
    child.stdin.as_mut().unwrap().write_all(b"pw\n").unwrap();
    assert!(child.wait().expect("keygen wait").success());
    let priv_key = dir.path().join("priv.ekey");
    let pub_key = dir.path().join("pub.key");
    assert_eq!(fs::read(&priv_key).unwrap().len(), ENC_KEY_LEN);

    let enc = dir.path().join("out.bin");
    let dec = dir.path().join("out.txt");

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
        .write_all(b"pw\npw1\n")
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
    dec_cmd.stdin.as_mut().unwrap().write_all(b"pw1\n").unwrap();
    assert!(dec_cmd.wait().expect("dec wait").success());
    assert_eq!(
        fs::read("tests/data/sample.txt").unwrap(),
        fs::read(dec).unwrap()
    );
}

#[test]
fn encrypted_key_missing_password_fails() {
    let dir = tempfile::tempdir().unwrap();
    let mut gen = Command::new(BIN)
        .args(["--generate-keys", dir.path().to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("run keygen");
    gen.stdin.as_mut().unwrap().write_all(b"pw\n").unwrap();
    assert!(gen.wait().expect("wait keygen").success());
    let priv_key = dir.path().join("priv.ekey");
    let enc = dir.path().join("out.bin");

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
    enc_cmd.stdin.as_mut().unwrap().write_all(b"\n").unwrap();
    assert!(!enc_cmd.wait().expect("enc wait").success());
}
