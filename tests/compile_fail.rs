use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn removed_unauthenticated_api_does_not_compile() {
    let directory = tempfile::tempdir().expect("temporary crate");
    fs::create_dir(directory.path().join("src")).expect("source directory");
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = format!(
        "[package]\nname='removed-api-check'\nversion='0.1.0'\nedition='2021'\n\n[dependencies]\nencryptor={{path='{}'}}\n",
        manifest_dir.display()
    );
    fs::write(directory.path().join("Cargo.toml"), manifest).expect("manifest");
    fs::write(
        directory.path().join("src/main.rs"),
        r#"use encryptor::{Argon2Config, derive_key, encrypt_decrypt, encrypt_decrypt_in_place};
fn main() {
    let _ = (Argon2Config::default(), derive_key, encrypt_decrypt, encrypt_decrypt_in_place);
}
"#,
    )
    .expect("source");
    let output = Command::new("cargo")
        .args(["check", "--offline"])
        .current_dir(directory.path())
        .output()
        .expect("cargo check");
    assert!(
        !output.status.success(),
        "removed unauthenticated API unexpectedly compiled:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unresolved imports") && stderr.contains("encrypt_decrypt"),
        "compile failed for an unrelated reason:\n{stderr}"
    );
}
