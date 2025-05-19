use argon2::Argon2;
use anyhow::{Result, anyhow};
use zeroize::Zeroize;

pub const MAGIC: &[u8;4] = b"CPV1"; // ChaChaPoly AEAD v1
pub const HEADER_LEN: usize = 36;

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
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

pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let constants: [u8; 16] = *b"expand 32-byte k";
    let mut state = [0u32; 16];
    for i in 0..4 {
        state[i] = u32::from_le_bytes(constants[4 * i..4 * i + 4].try_into().unwrap());
    }
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
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

pub fn poly1305_tag(r: &u128, s: &u128, aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    use poly1305::{universal_hash::{KeyInit, UniversalHash}, Poly1305, Key, Block};

    let mut key_bytes = [0u8; 32];
    key_bytes[..16].copy_from_slice(&r.to_le_bytes());
    key_bytes[16..].copy_from_slice(&s.to_le_bytes());
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
    out
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).map(|(&x, &y)| x ^ y).fold(0, |acc, z| acc | z) == 0
}

pub fn encrypt_decrypt(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut counter = 1u32;
    for chunk in data.chunks(64) {
        let ks = chacha20_block(key, counter, nonce);
        counter = counter.wrapping_add(1);
        out.extend(chunk.iter().enumerate().map(|(i, &b)| b ^ ks[i]));
    }
    out
}

