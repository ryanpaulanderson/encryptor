use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_file = PathBuf::from(out_dir).join("built_info.rs");
    let status = Command::new("cargo")
        .args(["auditable", "generate", "--output"])
        .arg(&out_file)
        .status();
    match status {
        Ok(s) if s.success() => {}
        _ => {
            let _ = fs::write(
                &out_file,
                "#[used]\npub static AUDITABLE_METADATA: &[u8] = b\"\";\n",
            );
            println!("cargo:warning=cargo-auditable not found; using empty metadata");
        }
    }
    println!("cargo:rerun-if-changed=Cargo.lock");
}
