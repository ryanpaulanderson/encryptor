#![deny(missing_docs)]
//! ChaCha20-Poly1305 encryption utilities with an Argon2 key derivation.
//!
//! This crate provides simple helper functions for deriving encryption keys
//! using Argon2 and performing in-place or buffer-to-buffer encryption with
//! the ChaCha20 stream cipher.  The implementation is intentionally minimal and
//! suitable for experimentation rather than production use.
//!
//! # Examples
//!
//! Encrypt and decrypt a short message:
//!
//! ```
//! use encryptor::{Argon2Config, derive_key, encrypt_decrypt};
//!
//! let cfg = Argon2Config::default();
//! let key = derive_key("password", b"0123456789abcdef", &cfg).unwrap();
//! let nonce = [0u8; 12];
//! let cipher = encrypt_decrypt(b"hello", &key, &nonce);
//! let plain = encrypt_decrypt(&cipher, &key, &nonce);
//! assert_eq!(plain, b"hello");
//! ```

pub mod error;
use crate::error::{Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};
#[cfg(unix)]
use libc::{mlock, munlock};
use rayon::prelude::*;
use secrecy::{ExposeSecret, Secret};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use zeroize::Zeroize;

/// File header magic bytes identifying the ChaCha20-Poly1305 format.
pub const MAGIC: &[u8; 4] = b"CPV1"; // ChaChaPoly AEAD v1
/// Number of bytes in the file header.
///
/// The header stores a 64 byte Ed25519 signature in addition to the
/// previous fields (magic, version, salt and nonce).
pub const HEADER_LEN: usize = 36 + ed25519_dalek::SIGNATURE_LENGTH;

/// Configuration parameters for [`derive_key`].
#[derive(Clone, Copy, Debug)]
pub struct Argon2Config {
    /// Memory cost in kibibytes used by the KDF.
    pub mem_cost_kib: u32,
    /// Number of hashing passes.
    pub time_cost: u32,
    /// Degree of parallelism.
    pub parallelism: u32,
}

impl Default for Argon2Config {
    /// Provide conservative default parameters.
    fn default() -> Self {
        Self {
            mem_cost_kib: 64 * 1024,
            time_cost: 4,
            parallelism: 1,
        }
    }
}

#[cfg(unix)]
/// Unlock memory previously protected with [`lock`].
///
/// # Errors
///
/// Returns an [`std::io::Error`] if the `munlock` syscall fails.
pub fn unlock(buf: &[u8]) -> std::io::Result<()> {
    let ret = unsafe { munlock(buf.as_ptr() as *const _, buf.len()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
/// Lock memory to prevent swapping it to disk.
///
/// # Errors
///
/// Returns an [`std::io::Error`] if the `mlock` syscall fails.
pub fn lock(buf: &[u8]) -> std::io::Result<()> {
    let ret = unsafe { mlock(buf.as_ptr() as *const _, buf.len()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
/// Stub on non-Unix systems that always succeeds.
pub fn lock(_buf: &[u8]) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
/// Stub on non-Unix systems that always succeeds.
pub fn unlock(_buf: &[u8]) -> std::io::Result<()> {
    Ok(())
}

/// Derive a ChaCha20 key from `password` and `salt` using Argon2id.
///
/// # Errors
///
/// Returns [`Error`] if the Argon2 computation fails or if locking the output
/// buffer is not possible.
///
/// # Examples
///
/// ```
/// use encryptor::{derive_key, Argon2Config};
/// use secrecy::ExposeSecret;
/// let cfg = Argon2Config::default();
/// let key = derive_key("pw", b"0123456789abcdef", &cfg).unwrap();
/// assert_eq!(key.expose_secret().len(), 32);
/// ```
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

/// Rotate `v` left by `c` bits.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(encryptor::rotl(0x0123_4567, 8), 0x23_4567_01);
/// ```
fn rotl(v: u32, c: u32) -> u32 {
    v.rotate_left(c)
}

/// Perform a single ChaCha quarter round on `state`.
///
/// # Examples
///
/// ```ignore
/// let mut s = [0u32; 16];
/// encryptor::quarter_round(&mut s, 0, 1, 2, 3);
/// ```
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

macro_rules! double_round {
    ($state:expr) => {
        quarter_round($state, 0, 4, 8, 12);
        quarter_round($state, 1, 5, 9, 13);
        quarter_round($state, 2, 6, 10, 14);
        quarter_round($state, 3, 7, 11, 15);
        quarter_round($state, 0, 5, 10, 15);
        quarter_round($state, 1, 6, 11, 12);
        quarter_round($state, 2, 7, 8, 13);
        quarter_round($state, 3, 4, 9, 14);
    };
}

#[inline(always)]
/// XOR `src` into `dst` in place.
///
/// # Safety
///
/// This function is unsafe because it performs unchecked pointer arithmetic.
///
/// # Examples
///
/// ```ignore
/// let mut data = [0u8; 4];
/// let mask = [1u8; 4];
/// unsafe { encryptor::xor_in_place(&mut data, &mask) };
/// assert_eq!(data, mask);
/// ```
unsafe fn xor_in_place(dst: &mut [u8], src: &[u8]) {
    let n = dst.len().min(src.len());
    let d = dst.as_mut_ptr();
    let s = src.as_ptr();
    for i in 0..n {
        // SAFETY: i < dst.len() and i < src.len()
        *d.add(i) ^= *s.add(i);
    }
}

#[inline(always)]
/// Generate a ChaCha20 keystream block.
///
/// # Examples
///
/// ```ignore
/// let key = [0u8; 32];
/// let block = encryptor::chacha20_block_bytes(&key, 0, &[0u8; 12]);
/// assert_eq!(block.len(), 64);
/// ```
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
    // 20 rounds
    for _ in 0..10 {
        double_round!(&mut working);
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

/// Compute the ChaCha20 block keystream for the given counter and nonce.
///
/// # Examples
/// ```
/// use encryptor::{chacha20_block, derive_key, Argon2Config};
/// let cfg = Argon2Config::default();
/// let key = derive_key("pw", b"0123456789abcdef", &cfg).unwrap();
/// let block = chacha20_block(&key, 0, &[0u8; 12]);
/// assert_eq!(block.len(), 64);
/// ```
pub fn chacha20_block(key: &Secret<[u8; 32]>, counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    chacha20_block_bytes(key.expose_secret(), counter, nonce)
}

use subtle::ConstantTimeEq;

/// Perform a constant-time equality check.
///
/// # Examples
///
/// ```
/// use encryptor::ct_eq;
/// assert!(ct_eq(b"a", b"a"));
/// assert!(!ct_eq(b"a", b"b"));
/// ```
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Read an entire file while using the same code path on success or failure.
///
/// This aims to keep timing similar for error and success cases but it is not a
/// strong constant-time guarantee. True constant-time I/O would require
/// operating system support and is outside the scope of this crate.
///
/// # Errors
///
/// Returns [`Error`] if the file cannot be read.
///
/// # Examples
///
/// ```
/// use encryptor::read_file_ct;
/// use std::io::Write;
/// let mut tmp = tempfile::NamedTempFile::new().unwrap();
/// writeln!(tmp, "hello").unwrap();
/// let data = read_file_ct(tmp.path()).unwrap();
/// assert!(data.starts_with(b"hello"));
/// ```
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

/// Encrypt or decrypt `data` returning a new `Vec<u8>`.
///
/// # Examples
///
/// ```
/// use encryptor::{encrypt_decrypt, derive_key, Argon2Config};
/// let cfg = Argon2Config::default();
/// let key = derive_key("pw", b"0123456789abcdef", &cfg).unwrap();
/// let nonce = [0u8; 12];
/// let cipher = encrypt_decrypt(b"hello", &key, &nonce);
/// let plain = encrypt_decrypt(&cipher, &key, &nonce);
/// assert_eq!(plain, b"hello");
/// ```
pub fn encrypt_decrypt(data: &[u8], key: &Secret<[u8; 32]>, nonce: &[u8; 12]) -> Vec<u8> {
    let mut out = data.to_vec();
    let mut counter = 1u32;
    encrypt_decrypt_in_place(&mut out, key, nonce, &mut counter);
    out
}

/// Encrypt or decrypt `data` in place advancing `counter` as blocks are
/// processed.
///
/// `counter` should start at `1` when encrypting/decrypting whole messages.
///
/// # Examples
///
/// ```
/// use encryptor::{encrypt_decrypt_in_place, derive_key, Argon2Config};
/// let cfg = Argon2Config::default();
/// let key = derive_key("pw", b"0123456789abcdef", &cfg).unwrap();
/// let nonce = [0u8; 12];
/// let mut data = b"hello".to_vec();
/// let mut enc_ctr = 1u32;
/// encrypt_decrypt_in_place(&mut data, &key, &nonce, &mut enc_ctr);
/// let mut dec_ctr = 1u32;
/// encrypt_decrypt_in_place(&mut data, &key, &nonce, &mut dec_ctr);
/// assert_eq!(data, b"hello");
/// ```
pub fn encrypt_decrypt_in_place(
    data: &mut [u8],
    key: &Secret<[u8; 32]>,
    nonce: &[u8; 12],
    counter: &mut u32,
) {
    let key_bytes = key.expose_secret();
    let base = *counter;
    let blocks = data.len().div_ceil(64);
    data.par_chunks_mut(64).enumerate().for_each(|(i, chunk)| {
        let ctr = base.wrapping_add(i as u32);
        let mut ks = chacha20_block_bytes(key_bytes, ctr, nonce);
        unsafe {
            xor_in_place(chunk, &ks);
        }
        ks.zeroize();
    });
    *counter = base.wrapping_add(blocks as u32);
}

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

/// Ed25519 private key type.
pub type Ed25519PrivKey = SigningKey;
/// Ed25519 public key type.
pub type Ed25519PubKey = VerifyingKey;

/// Length in bytes of an Ed25519 signature produced by [`sign`].
///
/// This is equivalent to [`ed25519_dalek::SIGNATURE_LENGTH`].
pub const SIG_LEN: usize = ed25519_dalek::SIGNATURE_LENGTH;

/// Sign `data` with `key` and return the detached signature bytes.
///
/// The returned byte array always has length [`SIG_LEN`].
///
/// # Examples
///
/// ```
/// use encryptor::{sign, verify, SIG_LEN, Ed25519PrivKey};
/// use ed25519_dalek::SigningKey;
/// use rand::random;
///
/// let key_bytes: [u8; 32] = random();
/// let key = SigningKey::from_bytes(&key_bytes);
/// let msg = b"hello";
/// let sig = sign(msg, &key);
/// assert_eq!(sig.len(), SIG_LEN);
/// assert!(verify(msg, &sig, &key.verifying_key()));
/// ```
pub fn sign(data: &[u8], priv_key: &Ed25519PrivKey) -> [u8; SIG_LEN] {
    let sig = priv_key.sign(data);
    sig.to_bytes()
}

/// Verify that `sig` is a valid Ed25519 signature on `data`.
///
/// Returns `true` if the signature is valid and `false` otherwise.
///
/// # Examples
///
/// ```
/// use ed25519_dalek::SigningKey;
/// use encryptor::{sign, verify};
/// use rand::random;
///
/// let key_bytes: [u8; 32] = random();
/// let key = SigningKey::from_bytes(&key_bytes);
/// let msg = b"data";
/// let sig = sign(msg, &key);
/// assert!(verify(msg, &sig, &key.verifying_key()));
/// ```
pub fn verify(data: &[u8], sig: &[u8], pub_key: &Ed25519PubKey) -> bool {
    if let Ok(sig) = ed25519_dalek::Signature::from_slice(sig) {
        pub_key.verify_strict(data, &sig).is_ok()
    } else {
        false
    }
}

/// Magic bytes identifying an encrypted Ed25519 private key file.
pub const KEY_MAGIC: &[u8; 6] = b"EDEKV1";

/// Length in bytes of an encrypted private key created by [`encrypt_priv_key`].
pub const ENC_KEY_LEN: usize = KEY_MAGIC.len() + 4 + 4 + 4 + 16 + 12 + 32 + 16;

/// Encrypt an Ed25519 seed using ChaCha20-Poly1305 with an Argon2 key.
///
/// # Examples
///
/// ```
/// use encryptor::{encrypt_priv_key, decrypt_priv_key, Argon2Config};
/// let seed = [0u8; 32];
/// let cfg = Argon2Config::default();
/// let enc = encrypt_priv_key(&seed, "pw", &cfg).unwrap();
/// let dec = decrypt_priv_key(&enc, "pw").unwrap();
/// assert_eq!(seed, dec);
/// ```
pub fn encrypt_priv_key(seed: &[u8; 32], password: &str, cfg: &Argon2Config) -> Result<Vec<u8>> {
    use poly1305::{
        universal_hash::{KeyInit, UniversalHash},
        Block, Key, Poly1305,
    };
    use rand_core::{OsRng, RngCore};

    let mut salt = [0u8; 16];
    OsRng.try_fill_bytes(&mut salt).unwrap();
    let mut nonce = [0u8; 12];
    OsRng.try_fill_bytes(&mut nonce).unwrap();
    let key = derive_key(password, &salt, cfg)?;

    let mut counter = 1u32;
    let mut cipher = seed.to_vec();
    encrypt_decrypt_in_place(&mut cipher, &key, &nonce, &mut counter);

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
    poly.update_padded(&[]);
    poly.update_padded(&cipher);
    let mut len_block = [0u8; 16];
    len_block[8..].copy_from_slice(&(cipher.len() as u64).to_le_bytes());
    poly.update(&[Block::clone_from_slice(&len_block)]);
    let tag = poly.finalize();

    let mut out = Vec::with_capacity(ENC_KEY_LEN);
    out.extend_from_slice(KEY_MAGIC);
    out.extend_from_slice(&cfg.mem_cost_kib.to_le_bytes());
    out.extend_from_slice(&cfg.time_cost.to_le_bytes());
    out.extend_from_slice(&cfg.parallelism.to_le_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&cipher);
    out.extend_from_slice(tag.as_slice());

    cipher.zeroize();
    salt.zeroize();
    nonce.zeroize();

    Ok(out)
}

/// Decrypt an encrypted Ed25519 seed.
///
/// # Examples
///
/// ```
/// use encryptor::{encrypt_priv_key, decrypt_priv_key, Argon2Config};
/// let seed = [0u8; 32];
/// let cfg = Argon2Config::default();
/// let enc = encrypt_priv_key(&seed, "pw", &cfg).unwrap();
/// let dec = decrypt_priv_key(&enc, "pw").unwrap();
/// assert_eq!(seed, dec);
/// ```
pub fn decrypt_priv_key(data: &[u8], password: &str) -> Result<[u8; 32]> {
    use poly1305::{
        universal_hash::{KeyInit, UniversalHash},
        Block, Key, Poly1305,
    };

    if data.len() != ENC_KEY_LEN {
        return Err(Error::FormatError("Invalid key file length"));
    }
    if !ct_eq(&data[..KEY_MAGIC.len()], KEY_MAGIC) {
        return Err(Error::FormatError("Invalid key file"));
    }

    let mem_cost = u32::from_le_bytes(
        data[KEY_MAGIC.len()..KEY_MAGIC.len() + 4]
            .try_into()
            .unwrap(),
    );
    let time_cost = u32::from_le_bytes(
        data[KEY_MAGIC.len() + 4..KEY_MAGIC.len() + 8]
            .try_into()
            .unwrap(),
    );
    let parallelism = u32::from_le_bytes(
        data[KEY_MAGIC.len() + 8..KEY_MAGIC.len() + 12]
            .try_into()
            .unwrap(),
    );
    let mut salt: [u8; 16] = data[KEY_MAGIC.len() + 12..KEY_MAGIC.len() + 28]
        .try_into()
        .unwrap();
    let mut nonce: [u8; 12] = data[KEY_MAGIC.len() + 28..KEY_MAGIC.len() + 40]
        .try_into()
        .unwrap();
    let mut cipher: [u8; 32] = data[KEY_MAGIC.len() + 40..KEY_MAGIC.len() + 72]
        .try_into()
        .unwrap();
    let tag_bytes: [u8; 16] = data[KEY_MAGIC.len() + 72..KEY_MAGIC.len() + 88]
        .try_into()
        .unwrap();

    let cfg = Argon2Config {
        mem_cost_kib: mem_cost,
        time_cost,
        parallelism,
    };
    let key = derive_key(password, &salt, &cfg)?;

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
    poly.update_padded(&[]);
    poly.update_padded(&cipher);
    let mut len_block = [0u8; 16];
    len_block[8..].copy_from_slice(&(cipher.len() as u64).to_le_bytes());
    poly.update(&[Block::clone_from_slice(&len_block)]);
    let expected = poly.finalize();
    if !ct_eq(expected.as_slice(), &tag_bytes) {
        salt.zeroize();
        nonce.zeroize();
        cipher.zeroize();
        return Err(Error::AuthFailure);
    }

    let mut counter = 1u32;
    encrypt_decrypt_in_place(&mut cipher, &key, &nonce, &mut counter);

    salt.zeroize();
    nonce.zeroize();

    Ok(cipher)
}
