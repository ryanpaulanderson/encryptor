// src/main.rs
// Dependencies in Cargo.toml:
// clap = { version = "4", features = ["derive"] }
// rand = "0.8"
// anyhow = "1.0"
// argon2 = "0.4"
// zeroize = "1.5"
// sha2 = "0.10"
// hex = "0.4"

use std::fs;
use std::path::PathBuf;
use clap::{Parser, Subcommand};
use rand::{rngs::OsRng, RngCore};
use argon2::Argon2;
use anyhow::{Result, bail, anyhow};
use zeroize::Zeroize;
use sha2::{Sha256, Digest};
use hex;

const MAGIC: &[u8;4] = b"CPV1"; // ChaChaPoly AEAD v1
const HEADER_LEN: usize = 36;

#[derive(Parser)]
#[command(name = "chacha20_poly1305", about = "ChaCha20-Poly1305 AEAD with Argon2 KDF, file header, and optional hash check")]
struct Args {
    #[command(subcommand)]
    mode: Mode,
    #[arg(value_name = "INPUT", help = "Input file path")]
    input_file: PathBuf,
    #[arg(value_name = "OUTPUT", help = "Output file path")]
    output_file: PathBuf,
    #[arg(value_name = "PASSWORD", help = "Password for KDF")]
    password: String,
    #[arg(long, help = "Optional hex-encoded SHA256 hash of the encrypted file to verify before decrypt")]
    verify_hash: Option<String>,
}

#[derive(Subcommand)]
enum Mode {
    Encrypt,
    Decrypt,
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!(e))?;
    Ok(key)
}

fn rotl(v: u32, c: u32) -> u32 { v.rotate_left(c) }

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = rotl(state[d] ^ state[a], 16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = rotl(state[b] ^ state[c], 12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = rotl(state[d] ^ state[a], 8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = rotl(state[b] ^ state[c], 7);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let constants: [u8; 16] = *b"expand 32-byte k";
    let mut state = [0u32; 16];
    for i in 0..4 { state[i] = u32::from_le_bytes(constants[4*i..4*i+4].try_into().unwrap()); }
    for i in 0..8 { state[4+i] = u32::from_le_bytes(key[4*i..4*i+4].try_into().unwrap()); }
    state[12] = counter;
    for i in 0..3 { state[13+i] = u32::from_le_bytes(nonce[4*i..4*i+4].try_into().unwrap()); }
    let mut working = state;
    for _ in 0..10 {
        quarter_round(&mut working, 0,4,8,12);
        quarter_round(&mut working, 1,5,9,13);
        quarter_round(&mut working, 2,6,10,14);
        quarter_round(&mut working, 3,7,11,15);
        quarter_round(&mut working, 0,5,10,15);
        quarter_round(&mut working, 1,6,11,12);
        quarter_round(&mut working, 2,7,8,13);
        quarter_round(&mut working, 3,4,9,14);
    }
    for i in 0..16 { working[i] = working[i].wrapping_add(state[i]); }
    let mut block = [0u8; 64];
    for i in 0..16 { block[4*i..4*i+4].copy_from_slice(&working[i].to_le_bytes()); }
    working.zeroize();
    block
}

fn poly1305_tag(r: &u128, s: &u128, aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    const P: u128 = (1 << 130) - 5;
    let mut acc = 0u128;
    let mut process = |data: &[u8]| {
        let mut i = 0;
        while i < data.len() {
            let chunk = &data[i..usize::min(i + 16, data.len())];
            let mut n = 0u128;
            for (j, &b) in chunk.iter().enumerate() { n |= (b as u128) << (8*j); }
            n |= 1u128 << (8 * chunk.len());
            acc = (acc.wrapping_add(n).wrapping_mul(*r)) % P;
            i += 16;
        }
    };
    process(aad);
    process(ciphertext);
    let mut len_block = [0u8; 16];
    len_block[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    len_block[8..16].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    process(&len_block);
    let tag = (acc.wrapping_add(*s)) & ((1<<128)-1);
    tag.to_le_bytes()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).map(|(&x,&y)| x^y).fold(0, |acc,z| acc|z) == 0
}

fn encrypt_decrypt(data: &[u8], key: &[u8;32], nonce: &[u8;12]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut counter = 1u32;
    for chunk in data.chunks(64) {
        let ks = chacha20_block(key, counter, nonce);
        counter = counter.wrapping_add(1);
        out.extend(chunk.iter().enumerate().map(|(i,&b)| b ^ ks[i]));
    }
    out
}

fn main() -> Result<()> {
    let args = Args::parse();
    let data = fs::read(&args.input_file)?;
    match args.mode {
        Mode::Encrypt => {
            let mut header = Vec::with_capacity(HEADER_LEN);
            header.extend_from_slice(MAGIC);
            header.push(1);
            header.extend_from_slice(&[0;3]);
            let mut salt = [0u8;16]; OsRng.fill_bytes(&mut salt);
            header.extend_from_slice(&salt);
            let mut nonce = [0u8;12]; OsRng.fill_bytes(&mut nonce);
            header.extend_from_slice(&nonce);
            let mut key = derive_key(&args.password, &salt)?;
            let block0 = chacha20_block(&key, 0, &nonce);
            let mut r_bytes = [0u8;16]; r_bytes.copy_from_slice(&block0[..16]);
            let mut s_bytes = [0u8;16]; s_bytes.copy_from_slice(&block0[16..32]);
            r_bytes[3] &= 15; r_bytes[7] &= 15; r_bytes[11] &= 15; r_bytes[15] &= 15;
            r_bytes[4] &= 252; r_bytes[8] &= 252; r_bytes[12] &= 252;
            let r = u128::from_le_bytes(r_bytes);
            let s = u128::from_le_bytes(s_bytes);
            let ciphertext = encrypt_decrypt(&data, &key, &nonce);
            let tag = poly1305_tag(&r, &s, &header, &ciphertext);
            let mut out = Vec::with_capacity(header.len() + ciphertext.len() + 16);
            out.extend(header);
            out.extend(ciphertext);
            out.extend(tag);
            fs::write(&args.output_file, &out)?;
            key.zeroize(); salt.zeroize();
        }
        Mode::Decrypt => {
            if data.len() < HEADER_LEN + 16 { bail!("Input too short"); }
            if let Some(expected_hex) = &args.verify_hash {
                let mut hasher = Sha256::new();
                hasher.update(&data);
                let actual_hex = hex::encode(hasher.finalize());
                if &actual_hex != expected_hex {
                    bail!("Hash mismatch: expected {} but got {}", expected_hex, actual_hex);
                }
            }
            let header = &data[..HEADER_LEN];
            if &header[..4] != MAGIC { bail!("Invalid file format"); }
            if header[4] != 1 { bail!("Unsupported version"); }
            let salt: [u8;16] = header[8..24].try_into().unwrap();
            let nonce: [u8;12] = header[24..36].try_into().unwrap();
            let mut key = derive_key(&args.password, &salt)?;
            let block0 = chacha20_block(&key, 0, &nonce);
            let mut r_bytes = [0u8;16]; r_bytes.copy_from_slice(&block0[..16]);
            let mut s_bytes = [0u8;16]; s_bytes.copy_from_slice(&block0[16..32]);
            r_bytes[3] &= 15; r_bytes[7] &= 15; r_bytes[11] &= 15; r_bytes[15] &= 15;
            r_bytes[4] &= 252; r_bytes[8] &= 252; r_bytes[12] &= 252;
            let r = u128::from_le_bytes(r_bytes);
            let s = u128::from_le_bytes(s_bytes);
            let ct_len = data.len() - HEADER_LEN - 16;
            let ciphertext = &data[HEADER_LEN..HEADER_LEN+ct_len];
            let tag = &data[HEADER_LEN+ct_len..];
            let expected = poly1305_tag(&r, &s, header, ciphertext);
            if !ct_eq(&expected, tag) { bail!("Authentication failure"); }
            let plaintext = encrypt_decrypt(ciphertext, &key, &nonce);
            fs::write(&args.output_file, plaintext)?;
            key.zeroize();
        }
    }
    Ok(())
}

