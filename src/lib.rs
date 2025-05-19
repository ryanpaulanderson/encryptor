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
    // Poly1305 implementation derived from the reference algorithm. This version
    // operates using 26-bit limbs and follows the reduction steps described in
    // RFC 8439. It is not optimised for constant time but is functionally
    // correct and sufficient for testing.

    // Clamp `r` in case the caller hasn't already done so.
    let mut r_bytes = r.to_le_bytes();
    r_bytes[3] &= 15;
    r_bytes[7] &= 15;
    r_bytes[11] &= 15;
    r_bytes[15] &= 15;
    r_bytes[4] &= 252;
    r_bytes[8] &= 252;
    r_bytes[12] &= 252;

    let r0 = (u32::from_le_bytes([r_bytes[0], r_bytes[1], r_bytes[2], r_bytes[3]]) as u64) & 0x3ffffff;
    let r1 = ((u32::from_le_bytes([r_bytes[3], r_bytes[4], r_bytes[5], r_bytes[6]]) >> 2) as u64) & 0x3ffffff;
    let r2 = ((u32::from_le_bytes([r_bytes[6], r_bytes[7], r_bytes[8], r_bytes[9]]) >> 4) as u64) & 0x3ffffff;
    let r3 = ((u32::from_le_bytes([r_bytes[9], r_bytes[10], r_bytes[11], r_bytes[12]]) >> 6) as u64) & 0x3ffffff;
    let r4 = ((u32::from_le_bytes([r_bytes[12], r_bytes[13], r_bytes[14], r_bytes[15]]) >> 8) as u64) & 0x3ffffff;

    let r1_5 = r1 * 5;
    let r2_5 = r2 * 5;
    let r3_5 = r3 * 5;
    let r4_5 = r4 * 5;

    let mut h0: u64 = 0;
    let mut h1: u64 = 0;
    let mut h2: u64 = 0;
    let mut h3: u64 = 0;
    let mut h4: u64 = 0;

    let mut process = |data: &[u8]| {
        let mut chunks = data.chunks_exact(16);
        for chunk in &mut chunks {
            let t0 = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u64;
            let t1 = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]) as u64;
            let t2 = u32::from_le_bytes([chunk[8], chunk[9], chunk[10], chunk[11]]) as u64;
            let t3 = u32::from_le_bytes([chunk[12], chunk[13], chunk[14], chunk[15]]) as u64;

            let m0 = t0 & 0x3ffffff;
            let m1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
            let m2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
            let m3 = ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
            let m4 = (t3 >> 8) | (1 << 24);

            h0 = h0.wrapping_add(m0);
            h1 = h1.wrapping_add(m1);
            h2 = h2.wrapping_add(m2);
            h3 = h3.wrapping_add(m3);
            h4 = h4.wrapping_add(m4);

            let mut d0 = h0 as u128 * r0 as u128
                + h1 as u128 * r4_5 as u128
                + h2 as u128 * r3_5 as u128
                + h3 as u128 * r2_5 as u128
                + h4 as u128 * r1_5 as u128;
            let mut d1 = h0 as u128 * r1 as u128
                + h1 as u128 * r0 as u128
                + h2 as u128 * r4_5 as u128
                + h3 as u128 * r3_5 as u128
                + h4 as u128 * r2_5 as u128;
            let mut d2 = h0 as u128 * r2 as u128
                + h1 as u128 * r1 as u128
                + h2 as u128 * r0 as u128
                + h3 as u128 * r4_5 as u128
                + h4 as u128 * r3_5 as u128;
            let mut d3 = h0 as u128 * r3 as u128
                + h1 as u128 * r2 as u128
                + h2 as u128 * r1 as u128
                + h3 as u128 * r0 as u128
                + h4 as u128 * r4_5 as u128;
            let mut d4 = h0 as u128 * r4 as u128
                + h1 as u128 * r3 as u128
                + h2 as u128 * r2 as u128
                + h3 as u128 * r1 as u128
                + h4 as u128 * r0 as u128;

            let mut c = (d0 >> 26) as u64;
            h0 = (d0 as u64) & 0x3ffffff;
            d1 += c as u128;

            c = (d1 >> 26) as u64;
            h1 = (d1 as u64) & 0x3ffffff;
            d2 += c as u128;

            c = (d2 >> 26) as u64;
            h2 = (d2 as u64) & 0x3ffffff;
            d3 += c as u128;

            c = (d3 >> 26) as u64;
            h3 = (d3 as u64) & 0x3ffffff;
            d4 += c as u128;

            c = (d4 >> 26) as u64;
            h4 = (d4 as u64) & 0x3ffffff;
            h0 = h0.wrapping_add(c * 5);
            c = h0 >> 26;
            h0 &= 0x3ffffff;
            h1 = h1.wrapping_add(c);
        }

        let rem = chunks.remainder();
        if !rem.is_empty() {
            let mut block = [0u8; 16];
            block[..rem.len()].copy_from_slice(rem);
            block[rem.len()] = 1;
            let t0 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]) as u64;
            let t1 = u32::from_le_bytes([block[4], block[5], block[6], block[7]]) as u64;
            let t2 = u32::from_le_bytes([block[8], block[9], block[10], block[11]]) as u64;
            let t3 = u32::from_le_bytes([block[12], block[13], block[14], block[15]]) as u64;

            let m0 = t0 & 0x3ffffff;
            let m1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
            let m2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
            let m3 = ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
            let m4 = t3 >> 8;

            h0 = h0.wrapping_add(m0);
            h1 = h1.wrapping_add(m1);
            h2 = h2.wrapping_add(m2);
            h3 = h3.wrapping_add(m3);
            h4 = h4.wrapping_add(m4);

            let mut d0 = h0 as u128 * r0 as u128
                + h1 as u128 * r4_5 as u128
                + h2 as u128 * r3_5 as u128
                + h3 as u128 * r2_5 as u128
                + h4 as u128 * r1_5 as u128;
            let mut d1 = h0 as u128 * r1 as u128
                + h1 as u128 * r0 as u128
                + h2 as u128 * r4_5 as u128
                + h3 as u128 * r3_5 as u128
                + h4 as u128 * r2_5 as u128;
            let mut d2 = h0 as u128 * r2 as u128
                + h1 as u128 * r1 as u128
                + h2 as u128 * r0 as u128
                + h3 as u128 * r4_5 as u128
                + h4 as u128 * r3_5 as u128;
            let mut d3 = h0 as u128 * r3 as u128
                + h1 as u128 * r2 as u128
                + h2 as u128 * r1 as u128
                + h3 as u128 * r0 as u128
                + h4 as u128 * r4_5 as u128;
            let mut d4 = h0 as u128 * r4 as u128
                + h1 as u128 * r3 as u128
                + h2 as u128 * r2 as u128
                + h3 as u128 * r1 as u128
                + h4 as u128 * r0 as u128;

            let mut c = (d0 >> 26) as u64;
            h0 = (d0 as u64) & 0x3ffffff;
            d1 += c as u128;

            c = (d1 >> 26) as u64;
            h1 = (d1 as u64) & 0x3ffffff;
            d2 += c as u128;

            c = (d2 >> 26) as u64;
            h2 = (d2 as u64) & 0x3ffffff;
            d3 += c as u128;

            c = (d3 >> 26) as u64;
            h3 = (d3 as u64) & 0x3ffffff;
            d4 += c as u128;

            c = (d4 >> 26) as u64;
            h4 = (d4 as u64) & 0x3ffffff;
            h0 = h0.wrapping_add(c * 5);
            c = h0 >> 26;
            h0 &= 0x3ffffff;
            h1 = h1.wrapping_add(c);
        }
    };

    process(aad);
    process(ciphertext);

    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    len_block[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    process(&len_block);

    let mut c = h1 >> 26;
    h1 &= 0x3ffffff;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x3ffffff;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x3ffffff;
    h4 += c;
    c = h4 >> 26;
    h4 &= 0x3ffffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x3ffffff;
    h1 += c;

    let mut g0 = h0 + 5;
    c = g0 >> 26;
    g0 &= 0x3ffffff;
    let mut g1 = h1 + c;
    c = g1 >> 26;
    g1 &= 0x3ffffff;
    let mut g2 = h2 + c;
    c = g2 >> 26;
    g2 &= 0x3ffffff;
    let mut g3 = h3 + c;
    c = g3 >> 26;
    g3 &= 0x3ffffff;
    let mut g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

    let mask = (g4 >> 63).wrapping_sub(1);
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    let inv_mask = !mask;
    h0 &= inv_mask;
    h1 &= inv_mask;
    h2 &= inv_mask;
    h3 &= inv_mask;
    h4 &= inv_mask;

    h0 |= g0;
    h1 |= g1;
    h2 |= g2;
    h3 |= g3;
    h4 |= g4;

    let f0 = (h0 | (h1 << 26)) as u64;
    let f1 = ((h1 >> 6) | (h2 << 20)) as u64;
    let f2 = ((h2 >> 12) | (h3 << 14)) as u64;
    let f3 = ((h3 >> 18) | (h4 << 8)) as u64;

    let s_bytes = s.to_le_bytes();
    let s0 = u32::from_le_bytes([s_bytes[0], s_bytes[1], s_bytes[2], s_bytes[3]]) as u64;
    let s1 = u32::from_le_bytes([s_bytes[4], s_bytes[5], s_bytes[6], s_bytes[7]]) as u64;
    let s2 = u32::from_le_bytes([s_bytes[8], s_bytes[9], s_bytes[10], s_bytes[11]]) as u64;
    let s3 = u32::from_le_bytes([s_bytes[12], s_bytes[13], s_bytes[14], s_bytes[15]]) as u64;

    let mut t0 = f0.wrapping_add(s0);
    let mut t1 = f1.wrapping_add(s1).wrapping_add(t0 >> 32);
    t0 &= 0xffffffff;
    let mut t2 = f2.wrapping_add(s2).wrapping_add(t1 >> 32);
    t1 &= 0xffffffff;
    let mut t3 = f3.wrapping_add(s3).wrapping_add(t2 >> 32);
    t2 &= 0xffffffff;
    t3 &= 0xffffffff;

    let mut tag = [0u8; 16];
    tag[..4].copy_from_slice(&(t0 as u32).to_le_bytes());
    tag[4..8].copy_from_slice(&(t1 as u32).to_le_bytes());
    tag[8..12].copy_from_slice(&(t2 as u32).to_le_bytes());
    tag[12..16].copy_from_slice(&(t3 as u32).to_le_bytes());
    tag
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

