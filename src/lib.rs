pub mod error;
use crate::error::{Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};
#[cfg(unix)]
use libc::{mlock, munlock};
use secrecy::{ExposeSecret, Secret};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use zeroize::Zeroize;

pub const MAGIC: &[u8; 4] = b"CPV1"; // ChaChaPoly AEAD v1
pub const HEADER_LEN: usize = 36;

pub struct Argon2Config {
    pub mem_cost_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            mem_cost_kib: 64 * 1024,
            time_cost: 4,
            parallelism: 1,
        }
    }
}

#[cfg(unix)]
pub fn unlock(buf: &[u8]) -> std::io::Result<()> {
    let ret = unsafe { munlock(buf.as_ptr() as *const _, buf.len()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
pub fn lock(buf: &[u8]) -> std::io::Result<()> {
    let ret = unsafe { mlock(buf.as_ptr() as *const _, buf.len()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
pub fn lock(_buf: &[u8]) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
pub fn unlock(_buf: &[u8]) -> std::io::Result<()> {
    Ok(())
}

pub fn derive_key(password: &str, salt: &[u8; 16], cfg: &Argon2Config) -> Result<Secret<[u8; 32]>> {
    let params =
        Params::new(cfg.mem_cost_kib, cfg.time_cost, cfg.parallelism, None).map_err(Error::from)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key_bytes = [0u8; 32];
    lock(&key_bytes).map_err(Error::from)?;
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key_bytes)
        .map_err(Error::from)?;
    unlock(&key_bytes).map_err(Error::from)?;
    Ok(Secret::new(key_bytes))
}

fn rotl(v: u32, c: u32) -> u32 {
    v.rotate_left(c)
}

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

fn chacha20_block_bytes(key_bytes: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let constants: [u8; 16] = *b"expand 32-byte k";
    let mut state = [0u32; 16];
    for i in 0..4 {
        state[i] = u32::from_le_bytes(constants[4 * i..4 * i + 4].try_into().unwrap());
    }
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key_bytes[4 * i..4 * i + 4].try_into().unwrap());
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes(nonce[4 * i..4 * i + 4].try_into().unwrap());
    }
    let mut working = state;
    for _ in 0..10 {
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }
    for i in 0..16 {
        working[i] = working[i].wrapping_add(state[i]);
    }
    let mut block = [0u8; 64];
    for i in 0..16 {
        block[4 * i..4 * i + 4].copy_from_slice(&working[i].to_le_bytes());
    }
    working.zeroize();
    block
}

pub fn chacha20_block(key: &Secret<[u8; 32]>, counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    chacha20_block_bytes(key.expose_secret(), counter, nonce)
}

pub fn poly1305_tag(r: &u128, s: &u128, aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    use poly1305::{
        universal_hash::{KeyInit, UniversalHash},
        Block, Key, Poly1305,
    };

    let mut key_bytes = [0u8; 32];
    key_bytes[..16].copy_from_slice(&r.to_le_bytes());
    key_bytes[16..].copy_from_slice(&s.to_le_bytes());
    lock(&key_bytes).ok();
    let mut poly = Poly1305::new(Key::from_slice(&key_bytes));

    poly.update_padded(aad);
    poly.update_padded(ciphertext);

    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    len_block[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    poly.update(&[Block::clone_from_slice(&len_block)]);

    let tag = poly.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_slice());
    unlock(&key_bytes).ok();
    key_bytes.zeroize();
    len_block.zeroize();
    out
}

use subtle::ConstantTimeEq;

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Read an entire file while using the same code path on success or failure.
pub fn read_file_ct(path: &Path) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let dummy = [0u8; 1];
    match File::open(path) {
        Ok(mut f) => {
            f.read_to_end(&mut buf).map_err(Error::from)?;
        }
        Err(e) => {
            let mut empty = &dummy[..];
            let _ = empty.read_to_end(&mut buf);
            return Err(Error::from(e));
        }
    }
    Ok(buf)
}

pub fn encrypt_decrypt(data: &[u8], key: &Secret<[u8; 32]>, nonce: &[u8; 12]) -> Vec<u8> {
    let key_bytes = key.expose_secret();
    let mut out = Vec::with_capacity(data.len());
    let mut counter = 1u32;
    for chunk in data.chunks(64) {
        let mut ks = chacha20_block_bytes(key_bytes, counter, nonce);
        counter = counter.wrapping_add(1);
        out.extend(chunk.iter().enumerate().map(|(i, &b)| b ^ ks[i]));
        ks.zeroize();
    }
    out
}

pub fn encrypt_decrypt_in_place(
    data: &mut [u8],
    key: &Secret<[u8; 32]>,
    nonce: &[u8; 12],
    counter: &mut u32,
) {
    let key_bytes = key.expose_secret();
    for chunk in data.chunks_mut(64) {
        let mut ks = chacha20_block_bytes(key_bytes, *counter, nonce);
        *counter = counter.wrapping_add(1);
        for (i, b) in chunk.iter_mut().enumerate() {
            *b ^= ks[i];
        }
        ks.zeroize();
    }
}
