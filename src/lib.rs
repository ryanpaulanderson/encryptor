use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use secrecy::{Secret, ExposeSecret};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use zeroize::Zeroize;
#[cfg(unix)]
use libc::{mlock, munlock};

/// File header constants
pub const MAGIC: &[u8; 4] = b"CPV1"; // ChaChaPoly AEAD v1
pub const HEADER_LEN: usize = 36;

/// Argon2 KDF parameters
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

/// Lock memory pages into RAM
#[cfg(unix)]
pub fn lock(buf: &[u8]) -> std::io::Result<()> {
    let ret = unsafe { mlock(buf.as_ptr() as *const _, buf.len()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Unlock memory pages
#[cfg(unix)]
pub fn unlock(buf: &[u8]) -> std::io::Result<()> {
    let ret = unsafe { munlock(buf.as_ptr() as *const _, buf.len()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
pub fn lock(_buf: &[u8]) -> std::io::Result<()> { Ok(()) }
#[cfg(not(unix))]
pub fn unlock(_buf: &[u8]) -> std::io::Result<()> { Ok(()) }

/// Derive a 256-bit key via Argon2, returning a zeroizing Secret
pub fn derive_key(password: &str, salt: &[u8], cfg: &Argon2Config) -> Result<Secret<[u8; 32]>> {
    let params = Params::new(cfg.mem_cost_kib, cfg.time_cost, cfg.parallelism, None)
        .map_err(|e| anyhow!(e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];

    // Lock in RAM
    lock(&key)?;
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!(e))?;
    // Unlock pages
    unlock(&key)?;

    Ok(Secret::new(key))
}

/// Rotate-left helper
#[inline]
fn rotl(v: u32, c: u32) -> u32 { v.rotate_left(c) }

/// ChaCha20 quarter-round
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

/// Generate a 64-byte ChaCha20 block
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let constants: [u8; 16] = *b"expand 32-byte k";
    let mut state = [0u32; 16];
    for i in 0..4 {
        state[i] = u32::from_le_bytes(constants[4*i..4*i+4].try_into().unwrap());
    }
    for i in 0..8 {
        state[4+i] = u32::from_le_bytes(key[4*i..4*i+4].try_into().unwrap());
    }
    state[12] = counter;
    for i in 0..3 {
        state[13+i] = u32::from_le_bytes(nonce[4*i..4*i+4].try_into().unwrap());
    }
    let mut w = state;
    for _ in 0..10 {
        quarter_round(&mut w, 0,4,8,12);
        quarter_round(&mut w, 1,5,9,13);
        quarter_round(&mut w, 2,6,10,14);
        quarter_round(&mut w, 3,7,11,15);
        quarter_round(&mut w, 0,5,10,15);
        quarter_round(&mut w, 1,6,11,12);
        quarter_round(&mut w, 2,7,8,13);
        quarter_round(&mut w, 3,4,9,14);
    }
    for i in 0..16 { w[i] = w[i].wrapping_add(state[i]); }
    let mut block = [0u8;64];
    for i in 0..16 {
        block[4*i..4*i+4].copy_from_slice(&w[i].to_le_bytes());
    }
    block
}

/// Compute Poly1305 tag over AAD and ciphertext
pub fn poly1305_tag(r: &u128, s: &u128, aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    use poly1305::{universal_hash::{KeyInit, UniversalHash}, Block, Key, Poly1305};

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
    unlock(&key_bytes).ok();
    key_bytes.zeroize();
    len_block.zeroize();

    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_slice());
    out
}

/// Constant-time equality
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).map(|(&x,&y)| x^y).fold(0, |acc,z| acc|z) == 0
}

/// Read file with constant code path
pub fn read_file_ct(path: &Path) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let dummy = [0u8; 1];
    match File::open(path) {
        Ok(mut f) => { f.read_to_end(&mut buf)?; }
        Err(e) => { let _ = (&dummy[..]).read_to_end(&mut buf); return Err(anyhow!(e)); }
    }
    Ok(buf)
}

/// One-shot encryption/decryption
pub fn encrypt_decrypt(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut counter = 1u32;
    for chunk in data.chunks(64) {
        let mut ks = chacha20_block(key, counter, nonce);
        counter = counter.wrapping_add(1);
        out.extend(chunk.iter().enumerate().map(|(i,&b)| b ^ ks[i]));
        ks.zeroize();
    }
    out
}

/// In-place streaming XOR
pub fn encrypt_decrypt_in_place(
    data: &mut [u8], key: &[u8; 32], nonce: &[u8; 12], counter: &mut u32
) {
    for chunk in data.chunks_mut(64) {
        let mut ks = chacha20_block(key, *counter, nonce);
        *counter = counter.wrapping_add(1);
        for (i, b) in chunk.iter_mut().enumerate() { *b ^= ks[i]; }
        ks.zeroize();
    }
}
