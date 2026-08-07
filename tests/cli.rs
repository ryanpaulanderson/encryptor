use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_chacha20_poly1305");

fn run_with_input(arguments: &[&str], input: &[u8]) -> std::process::Output {
    let mut child = Command::new(BIN)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn CLI");
    child
        .stdin
        .as_mut()
        .expect("piped stdin")
        .write_all(input)
        .expect("password input");
    child.wait_with_output().expect("CLI output")
}

#[test]
fn version_help_and_removed_flags_match_v053_contract() {
    let version = Command::new(BIN)
        .arg("--version")
        .output()
        .expect("version");
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).contains("0.53.0"));

    let help = Command::new(BIN).arg("--help").output().expect("help");
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(text.contains("not independently audited"));
    assert!(text.contains("keygen"));
    assert!(text.contains("export-public"));
    assert!(!text.contains("--mem-size"));
    assert!(!text.contains("--verify-hash"));
}

#[test]
fn cli_round_trip_uses_confirmation_only_for_encryption() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let input = directory.path().join("plain");
    let encrypted = directory.path().join("encrypted");
    let decrypted = directory.path().join("decrypted");
    fs::write(&input, b"CLI authenticated round trip").expect("input");

    let encrypted_result = run_with_input(
        &[
            "encrypt",
            input.to_str().expect("input path"),
            encrypted.to_str().expect("encrypted path"),
        ],
        b"password\npassword\n",
    );
    assert!(
        encrypted_result.status.success(),
        "{}",
        String::from_utf8_lossy(&encrypted_result.stderr)
    );

    let decrypted_result = run_with_input(
        &[
            "decrypt",
            encrypted.to_str().expect("encrypted path"),
            decrypted.to_str().expect("decrypted path"),
        ],
        b"password\n",
    );
    assert!(
        decrypted_result.status.success(),
        "{}",
        String::from_utf8_lossy(&decrypted_result.stderr)
    );
    assert_eq!(
        fs::read(decrypted).expect("decrypted"),
        b"CLI authenticated round trip"
    );
}

#[test]
fn mismatched_confirmation_creates_no_output() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let input = directory.path().join("plain");
    let encrypted = directory.path().join("encrypted");
    fs::write(&input, b"data").expect("input");
    let result = run_with_input(
        &[
            "encrypt",
            input.to_str().expect("input path"),
            encrypted.to_str().expect("encrypted path"),
        ],
        b"password-one\npassword-two\n",
    );
    assert!(!result.status.success());
    assert!(!encrypted.exists());
}

#[test]
fn verbose_authentication_failure_does_not_echo_password_or_plaintext() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let input = directory.path().join("plain");
    let encrypted = directory.path().join("encrypted");
    let output = directory.path().join("output");
    let secret_plaintext = "plaintext-marker-that-must-not-appear";
    fs::write(&input, secret_plaintext).expect("input");
    let encrypted_result = run_with_input(
        &[
            "encrypt",
            input.to_str().expect("input path"),
            encrypted.to_str().expect("encrypted path"),
        ],
        b"right-password\nright-password\n",
    );
    assert!(encrypted_result.status.success());
    let failure = run_with_input(
        &[
            "--verbose",
            "decrypt",
            encrypted.to_str().expect("encrypted path"),
            output.to_str().expect("output path"),
        ],
        b"wrong-password\n",
    );
    assert!(!failure.status.success());
    let stderr = String::from_utf8_lossy(&failure.stderr);
    assert!(stderr.contains("authentication failure"));
    assert!(!stderr.contains("right-password"));
    assert!(!stderr.contains("wrong-password"));
    assert!(!stderr.contains(secret_plaintext));
    assert!(!output.exists());
}
