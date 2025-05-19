use std::fs;
use std::process::Command;

fn main() {
    let out_file = "src/built_info.rs";
    let status = Command::new("cargo")
        .args(["auditable", "generate", "--output", out_file])
        .status();
    match status {
        Ok(s) if s.success() => {}
        _ => {
            let _ = fs::write(
                out_file,
                "#[used]\npub static AUDITABLE_METADATA: &[u8] = b\"\";\n",
            );
            println!("cargo:warning=cargo-auditable not found; using empty metadata");
        }
    }
    println!("cargo:rerun-if-changed=Cargo.lock");
}
