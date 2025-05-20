//! Command line interface for the `encryptor` crate.
//!
//! This binary encrypts and decrypts files using ChaCha20-Poly1305 with an
//! Argon2 key derivation function.  Run `chacha20_poly1305 --help` to see the
//! available options.

use clap::{Args, Parser, Subcommand};
use encryptor::error::{set_verbose, Error, Result};
use rand::{rngs::OsRng, TryRngCore};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use zeroize::Zeroize;

use ed25519_dalek::{SigningKey, VerifyingKey};
use encryptor::{
    chacha20_block, ct_eq, derive_key, encrypt_decrypt_in_place, sign, verify, Argon2Config,
    HEADER_LEN, MAGIC, SIG_LEN,
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
        if n == 0 {
            break;
        }
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
    #[arg(long, help = "Enable verbose error messages", global = true)]
    verbose: bool,
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
    #[arg(
        long,
        value_name = "PRIVATE_KEY_PATH",
        help = "Ed25519 private key to sign output"
    )]
    sign_key: Option<PathBuf>,
    #[arg(
        long,
        value_name = "PUBLIC_KEY_PATH",
        help = "Ed25519 public key to verify input"
    )]
    verify_key: Option<PathBuf>,
}

fn main() {
    if let Err(e) = try_main() {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

fn try_main() -> Result<()> {
    let cli = Cli::parse();
    set_verbose(cli.verbose);
    let (decrypting, args) = match cli.command {
        Command::Encrypt(a) => (false, a),
        Command::Decrypt(a) => (true, a),
    };

    let sign_key = if !decrypting {
        if let Some(p) = &args.sign_key {
            let bytes = fs::read(p)?;
            if bytes.len() != 32 {
                return Err(Error::FormatError("Invalid key length"));
            }
            let mut sk = [0u8; 32];
            sk.copy_from_slice(&bytes);
            Some(SigningKey::from_bytes(&sk))
        } else {
            None
        }
    } else {
        None
    };

    let verify_key = if decrypting {
        if let Some(p) = &args.verify_key {
            let bytes = fs::read(p)?;
            if bytes.len() != 32 {
                return Err(Error::FormatError("Invalid key length"));
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&bytes);
            Some(VerifyingKey::from_bytes(&pk).map_err(|_| Error::FormatError("Invalid key"))?)
        } else {
            None
        }
    } else {
        None
    };

    let cfg = Argon2Config {
        mem_cost_kib: args.mem_size * 1024,
        time_cost: args.iterations,
        parallelism: args.parallelism,
    };
    let max_mem = 1024 * 1024;
    if cfg.mem_cost_kib > max_mem {
        return Err(Error::FormatError("--mem-size too large"));
    }
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1) as u32;
    if cfg.parallelism > cpus {
        return Err(Error::FormatError("--parallelism too high"));
    }

    const COUNTER_MAX_BYTES: u64 = (u32::MAX as u64) * 64;
    let file_size = fs::metadata(&args.input_file)?.len();
    let too_large = if decrypting {
        file_size.saturating_sub((HEADER_LEN + 16) as u64) >= COUNTER_MAX_BYTES
    } else {
        file_size >= COUNTER_MAX_BYTES
    };
    if too_large {
        return Err(Error::FormatError(
            "Input file too large for 32-bit counter",
        ));
    }

    if !decrypting {
        let mut reader = BufReader::new(File::open(&args.input_file)?);
        let mut out_opts = OpenOptions::new();
        out_opts.write(true).create_new(true);
        #[cfg(unix)]
        out_opts.mode(0o600);
        let out_file = out_opts.open(&args.output_file)?;
        let mut writer = BufWriter::new(out_file);

        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.push(1);
        header.extend_from_slice(&[0; 3]);
        let mut salt = [0u8; 16];
        OsRng.try_fill_bytes(&mut salt).unwrap();
        let mut nonce = [0u8; 12];
        OsRng.try_fill_bytes(&mut nonce).unwrap();
        header.extend_from_slice(&salt);
        header.extend_from_slice(&nonce);
        writer.write_all(&header)?;

        let key = derive_key(&args.password, &salt, &cfg)?;
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

        let mut key_bytes = [0u8; 32];
        key_bytes[..16].copy_from_slice(&r.to_le_bytes());
        key_bytes[16..].copy_from_slice(&s.to_le_bytes());
        let mut poly = Poly1305::new(Key::from_slice(&key_bytes));
        key_bytes.zeroize();
        poly.update_padded(&header);
        let mut sign_buf = if sign_key.is_some() {
            header.clone()
        } else {
            Vec::new()
        };

        let mut buf = [0u8; 65536];
        let mut leftover = Vec::new();
        let mut counter = 1u32;
        let mut total_len = 0usize;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            let mut chunk = &mut buf[..n];
            while !chunk.is_empty() {
                let take = chunk.len().min(64);
                let (block, rest) = chunk.split_at_mut(take);
                encrypt_decrypt_in_place(block, &key, &nonce, &mut counter);
                poly_update_stream(&mut poly, block, &mut leftover);
                writer.write_all(block)?;
                if sign_key.is_some() {
                    sign_buf.extend_from_slice(block);
                }
                total_len += block.len();
                chunk = rest;
            }
        }
        poly.update_padded(&leftover);
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&(header.len() as u64).to_le_bytes());
        len_block[8..].copy_from_slice(&(total_len as u64).to_le_bytes());
        poly.update(&[Block::clone_from_slice(&len_block)]);
        let tag = poly.finalize();
        writer.write_all(tag.as_slice())?;
        if sign_key.is_some() {
            sign_buf.extend_from_slice(tag.as_slice());
        }
        if let Some(key) = &sign_key {
            let sig = sign(&sign_buf, key);
            writer.write_all(&sig)?;
        }
        writer.flush()?;

        salt.zeroize();
        nonce.zeroize();
        header.zeroize();
    } else {
        if let Some(expected_hex) = &args.verify_hash {
            let actual_hex = sha256_file(&args.input_file)?;
            if !ct_eq(actual_hex.as_bytes(), expected_hex.as_bytes()) {
                return Err(Error::FormatError("Hash mismatch"));
            }
        }

        let file_len = fs::metadata(&args.input_file)?.len() as usize;
        let sig_len = if verify_key.is_some() { SIG_LEN } else { 0 };
        if file_len < HEADER_LEN + 16 + sig_len {
            return Err(Error::FormatError("Input too short"));
        }

        let mut reader = BufReader::new(File::open(&args.input_file)?);
        let mut header = [0u8; HEADER_LEN];
        reader.read_exact(&mut header)?;

        let magic_ok = ct_eq(&header[..4], MAGIC);
        let version_ok = ct_eq(&[header[4]], &[1]);
        if !magic_ok || !version_ok {
            return Err(Error::FormatError("Invalid header"));
        }
        let mut salt: [u8; 16] = header[8..24].try_into().unwrap();
        let mut nonce: [u8; 12] = header[24..36].try_into().unwrap();

        let key = derive_key(&args.password, &salt, &cfg)?;
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

        let mut key_bytes = [0u8; 32];
        key_bytes[..16].copy_from_slice(&r.to_le_bytes());
        key_bytes[16..].copy_from_slice(&s.to_le_bytes());
        let mut poly = Poly1305::new(Key::from_slice(&key_bytes));
        key_bytes.zeroize();
        poly.update_padded(&header);

        let cipher_len = file_len - HEADER_LEN - 16 - sig_len;
        let mut cipher = vec![0u8; cipher_len];
        reader.read_exact(&mut cipher)?;
        let mut tag_bytes = [0u8; 16];
        reader.read_exact(&mut tag_bytes)?;
        if let Some(key) = &verify_key {
            let mut sig_bytes = [0u8; SIG_LEN];
            reader.read_exact(&mut sig_bytes)?;
            let mut verify_buf = Vec::with_capacity(header.len() + cipher_len + 16);
            verify_buf.extend_from_slice(&header);
            verify_buf.extend_from_slice(&cipher);
            verify_buf.extend_from_slice(&tag_bytes);
            if !verify(&verify_buf, &sig_bytes, key) {
                return Err(Error::FormatError("Signature mismatch"));
            }
        }

        let mut out_opts = OpenOptions::new();
        out_opts.write(true).create_new(true);
        #[cfg(unix)]
        out_opts.mode(0o600);
        let out_file = out_opts.open(&args.output_file)?;
        let mut writer = BufWriter::new(out_file);

        let mut buf = &mut cipher[..];
        let mut leftover = Vec::new();
        let mut counter = 1u32;
        while !buf.is_empty() {
            let take = buf.len().min(64);
            let (block, rest) = buf.split_at_mut(take);
            poly_update_stream(&mut poly, block, &mut leftover);
            encrypt_decrypt_in_place(block, &key, &nonce, &mut counter);
            writer.write_all(block)?;
            buf = rest;
        }
        poly.update_padded(&leftover);
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&(header.len() as u64).to_le_bytes());
        len_block[8..].copy_from_slice(&(cipher_len as u64).to_le_bytes());
        poly.update(&[Block::clone_from_slice(&len_block)]);
        let expected = poly.finalize();
        if !ct_eq(expected.as_slice(), &tag_bytes) {
            writer.flush()?; // ensure drop
            drop(writer);
            let _ = fs::remove_file(&args.output_file);
            return Err(Error::AuthFailure);
        }
        writer.flush()?;

        nonce.zeroize();
        salt.zeroize();
    }
    Ok(())
}
