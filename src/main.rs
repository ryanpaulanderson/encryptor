// src/main.rs
// Dependencies in Cargo.toml:
// clap = { version = "4", features = ["derive"] }
// rand = "0.8"
// anyhow = "1.0"
// argon2 = "0.4"
// zeroize = "1.5"
// sha2 = "0.10"
// hex = "0.4"

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use hex;
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroize;

use encryptor::{
    Argon2Config, HEADER_LEN, MAGIC, chacha20_block, ct_eq, derive_key, encrypt_decrypt,
    poly1305_tag, unlock,
};

#[derive(Parser)]
#[command(
    name = "chacha20_poly1305",
    about = "ChaCha20-Poly1305 AEAD with Argon2 KDF, file header, and optional hash check"
)]
struct Args {
    #[command(subcommand)]
    mode: Mode,
    #[arg(value_name = "INPUT", help = "Input file path")]
    input_file: PathBuf,
    #[arg(value_name = "OUTPUT", help = "Output file path")]
    output_file: PathBuf,
    #[arg(value_name = "PASSWORD", help = "Password for KDF")]
    password: String,
    #[arg(
        long,
        help = "Optional hex-encoded SHA256 hash of the encrypted file to verify before decrypt"
    )]
    verify_hash: Option<String>,
    #[arg(long, default_value_t = 64, help = "Argon2 memory size in MiB")]
    mem_size: u32,
    #[arg(long, default_value_t = 4, help = "Argon2 iterations/passes")]
    iterations: u32,
    #[arg(long, default_value_t = 1, help = "Argon2 parallelism")]
    parallelism: u32,
}

#[derive(Subcommand)]
enum Mode {
    Encrypt,
    Decrypt,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let cfg = Argon2Config {
        mem_cost_kib: args.mem_size * 1024,
        time_cost: args.iterations,
        parallelism: args.parallelism,
    };
    let mut data = fs::read(&args.input_file)?;
    match args.mode {
        Mode::Encrypt => {
            let mut header = Vec::with_capacity(HEADER_LEN);
            header.extend_from_slice(MAGIC);
            header.push(1);
            header.extend_from_slice(&[0; 3]);
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            header.extend_from_slice(&salt);
            let mut nonce = [0u8; 12];
            OsRng.fill_bytes(&mut nonce);
            header.extend_from_slice(&nonce);
            let mut key = derive_key(&args.password, &salt, &cfg)?;
            let mut block0 = chacha20_block(&key, 0, &nonce);
            let mut r_bytes = [0u8; 16];
            r_bytes.copy_from_slice(&block0[..16]);
            let mut s_bytes = [0u8; 16];
            s_bytes.copy_from_slice(&block0[16..32]);
            r_bytes[3] &= 15;
            r_bytes[7] &= 15;
            r_bytes[11] &= 15;
            r_bytes[15] &= 15;
            r_bytes[4] &= 252;
            r_bytes[8] &= 252;
            r_bytes[12] &= 252;
            let r = u128::from_le_bytes(r_bytes);
            let s = u128::from_le_bytes(s_bytes);
            block0.zeroize();
            r_bytes.zeroize();
            s_bytes.zeroize();
            let mut ciphertext = encrypt_decrypt(&data, &key, &nonce);
            data.zeroize();
            let tag = poly1305_tag(&r, &s, &header, &ciphertext);
            let mut out = Vec::with_capacity(header.len() + ciphertext.len() + 16);
            out.extend_from_slice(&header);
            out.extend_from_slice(&ciphertext);
            out.extend_from_slice(&tag);
            fs::write(&args.output_file, &out)?;
            key.zeroize();
            #[cfg(unix)]
            unlock(&key);
            salt.zeroize();
            out.zeroize();
            ciphertext.zeroize();
            nonce.zeroize();
            header.zeroize();
        }
        Mode::Decrypt => {
            if data.len() < HEADER_LEN + 16 {
                bail!("Input too short");
            }
            if let Some(expected_hex) = &args.verify_hash {
                let mut hasher = Sha256::new();
                hasher.update(&data);
                let actual_hex = hex::encode(hasher.finalize());
                if &actual_hex != expected_hex {
                    bail!(
                        "Hash mismatch: expected {} but got {}",
                        expected_hex,
                        actual_hex
                    );
                }
            }
            let header = &data[..HEADER_LEN];
            if &header[..4] != MAGIC {
                bail!("Invalid file format");
            }
            if header[4] != 1 {
                bail!("Unsupported version");
            }
            let mut salt: [u8; 16] = header[8..24].try_into().unwrap();
            let mut nonce: [u8; 12] = header[24..36].try_into().unwrap();
            let mut key = derive_key(&args.password, &salt, &cfg)?;
            let mut block0 = chacha20_block(&key, 0, &nonce);
            let mut r_bytes = [0u8; 16];
            r_bytes.copy_from_slice(&block0[..16]);
            let mut s_bytes = [0u8; 16];
            s_bytes.copy_from_slice(&block0[16..32]);
            r_bytes[3] &= 15;
            r_bytes[7] &= 15;
            r_bytes[11] &= 15;
            r_bytes[15] &= 15;
            r_bytes[4] &= 252;
            r_bytes[8] &= 252;
            r_bytes[12] &= 252;
            let r = u128::from_le_bytes(r_bytes);
            let s = u128::from_le_bytes(s_bytes);
            block0.zeroize();
            r_bytes.zeroize();
            s_bytes.zeroize();
            let ct_len = data.len() - HEADER_LEN - 16;
            let ciphertext = &data[HEADER_LEN..HEADER_LEN + ct_len];
            let tag = &data[HEADER_LEN + ct_len..];
            let expected = poly1305_tag(&r, &s, header, ciphertext);
            if !ct_eq(&expected, tag) {
                bail!("Authentication failure");
            }
            let mut plaintext = encrypt_decrypt(ciphertext, &key, &nonce);
            fs::write(&args.output_file, &plaintext)?;
            plaintext.zeroize();
            key.zeroize();
            #[cfg(unix)]
            unlock(&key);
            data.zeroize();
            nonce.zeroize();
            salt.zeroize();
        }
    }
    Ok(())
}
