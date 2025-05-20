// src/main.rs
// Dependencies in Cargo.toml:
// clap = { version = "4", features = ["derive"] }
// rand = "0.8"
// anyhow = "1.0"
// argon2 = "0.4"
// zeroize = "1.5"
// sha2 = "0.10"
// hex = "0.4"

use anyhow::{bail, Result};
use clap::{Args, Parser, Subcommand};
use rand::{rngs::OsRng, RngCore};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use zeroize::Zeroize;

use encryptor::{
    chacha20_block, ct_eq, derive_key, encrypt_decrypt_in_place, lock, unlock,
    Argon2Config, HEADER_LEN, MAGIC,
};
use poly1305::{
    universal_hash::{KeyInit, UniversalHash},
    Block, Key, Poly1305,
};

fn poly_update_stream(poly: &mut Poly1305, mut data: &[u8], leftover: &mut Vec<u8>) {
    if !leftover.is_empty() {
        let need = 16 - leftover.len();
        let take = need.min(data.len());
        leftover.extend_from_slice(&data[..take]);
        data = &data[take..];
        if leftover.len() == 16 {
            poly.update(&[Block::clone_from_slice(&leftover[..])]);
            leftover.clear();
        }
    }
    while data.len() >= 16 {
        let block = Block::clone_from_slice(&data[..16]);
        poly.update(&[block]);
        data = &data[16..];
    }
    if !data.is_empty() {
        leftover.extend_from_slice(data);
    }
}

fn sha256_file(path: &PathBuf) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut file = BufReader::new(File::open(path)?);
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[derive(Parser)]
#[command(
    name = "chacha20_poly1305",
    about = "ChaCha20-Poly1305 AEAD with Argon2 KDF, file header, and optional hash check"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Encrypt(ModeArgs),
    Decrypt(ModeArgs),
}

#[derive(Args)]
struct ModeArgs {
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    let (decrypting, args) = match cli.command {
        Command::Encrypt(a) => (false, a),
        Command::Decrypt(a) => (true, a),
    };

    let cfg = Argon2Config {
        mem_cost_kib: args.mem_size * 1024,
        time_cost: args.iterations,
        parallelism: args.parallelism,
    };
    if cfg.mem_cost_kib > 1024 * 1024 {
        bail!("--mem-size too large");
    }
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1) as u32;
    if cfg.parallelism > cpus {
        bail!("--parallelism too high");
    }

    if !decrypting {
        let mut reader = BufReader::new(File::open(&args.input_file)?);
        let mut out_opts = OpenOptions::new().write(true).create_new(true);
        #[cfg(unix)] out_opts.mode(0o600);
        let out_file = out_opts.open(&args.output_file)?;
        let mut writer = BufWriter::new(out_file);

        // build header
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.push(1);
        header.extend_from_slice(&[0;3]);
        let mut salt = [0u8;16]; OsRng.fill_bytes(&mut salt);
        let mut nonce = [0u8;12]; OsRng.fill_bytes(&mut nonce);
        header.extend_from_slice(&salt);
        header.extend_from_slice(&nonce);
        writer.write_all(&header)?;

        // derive key
        let key_sec = derive_key(&args.password, &salt, &cfg)?;
        let key = key_sec.expose_secret();

        // poly1305 one-time key
        let mut block0 = chacha20_block(key, 0, &nonce);
        let mut r_bytes = [0u8;16]; r_bytes.copy_from_slice(&block0[..16]);
        let mut s_bytes = [0u8;16]; s_bytes.copy_from_slice(&block0[16..32]);
        r_bytes[3] &= 15; r_bytes[7] &= 15; r_bytes[11] &= 15; r_bytes[15] &= 15;
        r_bytes[4] &= 252; r_bytes[8] &= 252; r_bytes[12] &= 252;
        let r = u128::from_le_bytes(r_bytes);
        let s = u128::from_le_bytes(s_bytes);
        block0.zeroize(); r_bytes.zeroize(); s_bytes.zeroize();

        let mut key_bytes = [0u8;32];
        key_bytes[..16].copy_from_slice(&r.to_le_bytes());
        key_bytes[16..].copy_from_slice(&s.to_le_bytes());
        lock(&key_bytes).ok();
        let mut poly = Poly1305::new(Key::from_slice(&key_bytes));
        unlock(&key_bytes).ok();

        poly.update_padded(&header);
        let mut buf = [0u8;65536];
        let mut leftover = Vec::new();
        let mut counter = 1u32;
        let mut total = 0usize;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 { break; }
            let chunk = &mut buf[..n];
            encrypt_decrypt_in_place(chunk, key, &nonce, &mut counter);
            poly_update_stream(&mut poly, chunk, &mut leftover);
            writer.write_all(chunk)?;
            total += n;
        }
        poly.update_padded(&leftover);
        let mut lenb = [0u8;16];
        lenb[..8].copy_from_slice(&(header.len() as u64).to_le_bytes());
        lenb[8..].copy_from_slice(&(total as u64).to_le_bytes());
        poly.update(&[Block::clone_from_slice(&lenb)]);
        let tag = poly.finalize(); writer.write_all(tag.as_slice())?;
        writer.flush()?;

        // secret zeroized on drop
        unlock(key).ok();
        salt.zeroize(); nonce.zeroize(); header.zeroize();
    } else {
        if let Some(expected) = &args.verify_hash {
            let got = sha256_file(&args.input_file)?;
            if !ct_eq(got.as_bytes(), expected.as_bytes()) {
                bail!("Hash mismatch");
            }
        }
        let len = fs::metadata(&args.input_file)?.len() as usize;
        if len < HEADER_LEN + 16 { bail!("Input too short"); }

        let mut reader = BufReader::new(File::open(&args.input_file)?);
        let mut header = [0u8; HEADER_LEN]; reader.read_exact(&mut header)?;
        if !ct_eq(&header[..4], MAGIC) || header[4] != 1 { bail!("Invalid header"); }
        let salt: [u8;16] = header[8..24].try_into().unwrap();
        let nonce: [u8;12] = header[24..36].try_into().unwrap();

        let key_sec = derive_key(&args.password, &salt, &cfg)?;
        let key = key_sec.expose_secret();
        let mut block0 = chacha20_block(key, 0, &nonce);
        let mut r_bytes = [0u8;16]; r_bytes.copy_from_slice(&block0[..16]);
        let mut s_bytes = [0u8;16]; s_bytes.copy_from_slice(&block0[16..32]);
        r_bytes[3] &= 15; r_bytes[7] &= 15; r_bytes[11] &= 15; r_bytes[15] &= 15;
        r_bytes[4] &= 252; r_bytes[8] &= 252; r_bytes[12] &= 252;
        let r = u128::from_le_bytes(r_bytes);
        let s = u128::from_le_bytes(s_bytes);
        block0.zeroize(); r_bytes.zeroize(); s_bytes.zeroize();

        let mut key_bytes = [0u8;32];
        key_bytes[..16].copy_from_slice(&r.to_le_bytes());
        key_bytes[16..].copy_from_slice(&s.to_le_bytes());
        lock(&key_bytes).ok();
        let mut poly = Poly1305::new(Key::from_slice(&key_bytes));
        unlock(&key_bytes).ok();
        poly.update_padded(&header);

        let cipher_len = len - HEADER_LEN - 16;
        let mut out_opts = OpenOptions::new().write(true).create_new(true);
        #[cfg(unix)] out_opts.mode(0o600);
        let mut writer = BufWriter::new(out_opts.open(&args.output_file)?);

        let mut buf = [0u8;65536];
        let mut leftover = Vec::new();
        let mut counter = 1u32;
        let mut rem = cipher_len;
        while rem > 0 {
            let rlen = rem.min(buf.len());
            let n = reader.read(&mut buf[..rlen])?;
            if n == 0 { break; }
            rem -= n;
            let chunk = &mut buf[..n];
            poly_update_stream(&mut poly, chunk, &mut leftover);
            encrypt_decrypt_in_place(chunk, key, &nonce, &mut counter);
            writer.write_all(chunk)?;
        }
        let mut tag_bytes = [0u8;16]; reader.read_exact(&mut tag_bytes)?;
        poly.update_padded(&leftover);
        let mut lenb = [0u8;16];
        lenb[..8].copy_from_slice(&(HEADER_LEN as u64).to_le_bytes());
        lenb[8..].copy_from_slice(&(cipher_len as u64).to_le_bytes());
        poly.update(&[Block::clone_from_slice(&lenb)]);
        let expected = poly.finalize().into_bytes();
        if !ct_eq(expected.as_slice(), &tag_bytes) {
            writer.flush()?; drop(writer);
            let _ = fs::remove_file(&args.output_file);
            bail!("Authentication failure");
        }
        writer.flush()?;

        unlock(key).ok(); salt.zeroize(); nonce.zeroize();
    }
    Ok(())
}
