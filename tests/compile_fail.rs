use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn old_api_usage_fails_to_compile() {
    let dir = tempfile::tempdir().expect("temp dir");
    let crate_dir = dir.path();
    fs::create_dir_all(crate_dir.join("src")).unwrap();
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cargo_toml = format!(
        "[package]\nname = \"failcase\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nencryptor = {{ path = \"{}\" }}\n",
        manifest_dir.display()
    );
    fs::write(crate_dir.join("Cargo.toml"), cargo_toml).unwrap();
    fs::write(
        crate_dir.join("src/main.rs"),
        r#"use encryptor::encrypt_decrypt_in_place;
fn main() {
    let mut data = [0u8; 16];
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let mut counter = 0u32;
    encrypt_decrypt_in_place(&mut data, &key, &nonce, &mut counter);
}
"#,
    )
    .unwrap();
    let output = Command::new("cargo")
        .arg("check")
        .arg("--offline")
        .current_dir(crate_dir)
        .output()
        .expect("cargo check");
    assert!(
        !output.status.success(),
        "old API call unexpectedly compiled:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
