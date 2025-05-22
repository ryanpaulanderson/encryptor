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
        "[package]\nname = \"failcase\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nchacha20_poly1305_custom = {{ path = \"{}/crates/chacha20_poly1305_custom\" }}\n",
        manifest_dir.display()
    );
    fs::write(crate_dir.join("Cargo.toml"), cargo_toml).unwrap();
    fs::write(
        crate_dir.join("src/main.rs"),
        r#"use chacha20_poly1305_custom::encrypt_decrypt_in_place;
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

#[test]
fn derive_key_wrong_salt_fails() {
    let dir = tempfile::tempdir().expect("temp dir");
    let crate_dir = dir.path();
    fs::create_dir_all(crate_dir.join("src")).unwrap();
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cargo_toml = format!(
        "[package]\nname = \"failcase2\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nchacha20_poly1305_custom = {{ path = \"{}/crates/chacha20_poly1305_custom\" }}\n",
        manifest_dir.display()
    );
    fs::write(crate_dir.join("Cargo.toml"), cargo_toml).unwrap();
    fs::write(
        crate_dir.join("src/main.rs"),
        r#"use chacha20_poly1305_custom::{derive_key, Argon2Config};
fn main() {
    let cfg = Argon2Config::default();
    let _ = derive_key("pw", &[0u8; 15], &cfg);
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
        "derive_key call unexpectedly compiled:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
