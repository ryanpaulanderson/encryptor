use zeroize::Zeroize;

use argon2::Argon2;
use anyhow::{Result, anyhow};

/// Derive a 256-bit key using Argon2 from the provided password and salt.
pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!(e))?;
    Ok(key)
}

pub(crate) fn rotl(v: u32, c: u32) -> u32 { v.rotate_left(c) }

pub(crate) fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = rotl(state[d] ^ state[a], 16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = rotl(state[b] ^ state[c], 12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = rotl(state[d] ^ state[a], 8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = rotl(state[b] ^ state[c], 7);
}

/// Produce one ChaCha20 block of keystream.
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
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

/// Encrypt or decrypt data using the provided key and nonce.
pub fn encrypt_decrypt(data: &[u8], key: &[u8;32], nonce: &[u8;12]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut counter = 1u32;
    for chunk in data.chunks(64) {
        let ks = chacha20_block(key, counter, nonce);
        counter = counter.wrapping_add(1);
        out.extend(chunk.iter().enumerate().map(|(i,&b)| b ^ ks[i]));
    }
    out
}

/// Compute a Poly1305 tag over the provided associated data and ciphertext.
pub fn poly1305_tag(r: &u128, s: &u128, aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
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

/// Constant-time equality check for byte slices.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).map(|(&x,&y)| x^y).fold(0, |acc,z| acc|z) == 0
}
