//! Private custom RFC 8439 ChaCha20-Poly1305 implementation.
//!
//! This module intentionally remains hand written for the educational purpose
//! of this crate. It is not an independently audited cryptographic module.

use crate::error::{Error, Result};
use poly1305::{
    universal_hash::{KeyInit, UniversalHash},
    Block, Key, Poly1305,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub(crate) const KEY_LEN: usize = 32;
pub(crate) const NONCE_LEN: usize = 12;
pub(crate) const TAG_LEN: usize = 16;

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

fn double_round(state: &mut [u32; 16]) {
    quarter_round(state, 0, 4, 8, 12);
    quarter_round(state, 1, 5, 9, 13);
    quarter_round(state, 2, 6, 10, 14);
    quarter_round(state, 3, 7, 11, 15);
    quarter_round(state, 0, 5, 10, 15);
    quarter_round(state, 1, 6, 11, 12);
    quarter_round(state, 2, 7, 8, 13);
    quarter_round(state, 3, 4, 9, 14);
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn chacha20_block(key: &[u8; KEY_LEN], counter: u32, nonce: &[u8; NONCE_LEN]) -> [u8; 64] {
    let constants = *b"expand 32-byte k";
    let mut state = [0u32; 16];
    for (index, slot) in state[..4].iter_mut().enumerate() {
        *slot = word(&constants, index * 4);
    }
    for (index, slot) in state[4..12].iter_mut().enumerate() {
        *slot = word(key, index * 4);
    }
    state[12] = counter;
    for (index, slot) in state[13..16].iter_mut().enumerate() {
        *slot = word(nonce, index * 4);
    }

    let mut working = state;
    for _ in 0..10 {
        double_round(&mut working);
    }
    for (value, original) in working.iter_mut().zip(state) {
        *value = value.wrapping_add(original);
    }

    let mut block = [0u8; 64];
    for (index, value) in working.iter().enumerate() {
        block[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    state.zeroize();
    working.zeroize();
    block
}

fn payload_blocks(length: usize) -> Result<u32> {
    let blocks = length.div_ceil(64);
    u32::try_from(blocks).map_err(|_| Error::LimitExceeded("ChaCha20 counter would wrap"))
}

fn apply_keystream(data: &mut [u8], key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN]) -> Result<()> {
    let _ = payload_blocks(data.len())?;

    for (block_index, chunk) in data.chunks_mut(64).enumerate() {
        let offset = u32::try_from(block_index)
            .map_err(|_| Error::LimitExceeded("ChaCha20 block index does not fit u32"))?;
        let counter = 1u32
            .checked_add(offset)
            .ok_or(Error::LimitExceeded("ChaCha20 counter would wrap"))?;
        let mut stream = chacha20_block(key, counter, nonce);
        for (byte, mask) in chunk.iter_mut().zip(stream.iter()) {
            *byte ^= mask;
        }
        stream.zeroize();
    }
    Ok(())
}

fn compute_tag(
    ciphertext: &[u8],
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
) -> Result<[u8; TAG_LEN]> {
    let aad_len = u64::try_from(aad.len())
        .map_err(|_| Error::LimitExceeded("associated data length does not fit u64"))?;
    let ciphertext_len = u64::try_from(ciphertext.len())
        .map_err(|_| Error::LimitExceeded("ciphertext length does not fit u64"))?;

    let mut block_zero = chacha20_block(key, 0, nonce);
    let mut one_time_key = [0u8; KEY_LEN];
    one_time_key.copy_from_slice(&block_zero[..KEY_LEN]);
    block_zero.zeroize();

    let poly1305_key: &Key = (&one_time_key).into();
    let mut poly1305 = Poly1305::new(poly1305_key);
    one_time_key.zeroize();
    poly1305.update_padded(aad);
    poly1305.update_padded(ciphertext);
    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&aad_len.to_le_bytes());
    lengths[8..].copy_from_slice(&ciphertext_len.to_le_bytes());
    let length_block = Block::from(lengths);
    poly1305.update(&[length_block]);
    lengths.zeroize();
    Ok(poly1305.finalize().into())
}

pub(crate) fn seal_record(
    plaintext: &mut [u8],
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
) -> Result<[u8; TAG_LEN]> {
    apply_keystream(plaintext, key, nonce)?;
    compute_tag(plaintext, key, nonce, aad)
}

pub(crate) fn open_record(
    ciphertext: &mut [u8],
    tag: &[u8; TAG_LEN],
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
) -> Result<()> {
    let mut expected = compute_tag(ciphertext, key, nonce, aad)?;
    let valid: bool = expected.ct_eq(tag).into();
    expected.zeroize();
    if !valid {
        ciphertext.zeroize();
        return Err(Error::AuthenticationFailure);
    }
    apply_keystream(ciphertext, key, nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::{
        aead::{AeadInOut, KeyInit},
        ChaCha20Poly1305, Nonce,
    };

    fn decode_hex(input: &str) -> Vec<u8> {
        let compact: Vec<u8> = input
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        assert_eq!(compact.len() % 2, 0);
        compact
            .chunks_exact(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).expect("valid test hex");
                let low = (pair[1] as char).to_digit(16).expect("valid test hex");
                ((high << 4) | low) as u8
            })
            .collect()
    }

    #[test]
    fn rfc8439_block_vector() {
        let key: [u8; 32] = core::array::from_fn(|index| index as u8);
        let nonce = [0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0, 0, 0, 0];
        let expected = decode_hex(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
        );
        assert_eq!(chacha20_block(&key, 1, &nonce).as_slice(), expected);
    }

    #[test]
    fn rfc8439_complete_aead_vector() {
        let key: [u8; 32] = decode_hex(
            "808182838485868788898a8b8c8d8e8f
             909192939495969798999a9b9c9d9e9f",
        )
        .try_into()
        .expect("32-byte test key");
        let nonce: [u8; 12] = decode_hex("070000004041424344454647")
            .try_into()
            .expect("12-byte test nonce");
        let aad = decode_hex("50515253c0c1c2c3c4c5c6c7");
        let mut plaintext = decode_hex(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173
             73206f66202739393a204966204920636f756c64206f6666657220796f75206f
             6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73
             637265656e20776f756c642062652069742e",
        );
        let expected_ciphertext = decode_hex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc
             3ff4def08e4b7a9de576d26586cec64b6116",
        );
        let expected_tag = decode_hex("1ae10b594f09e26a7e902ecbd0600691");

        let tag = seal_record(&mut plaintext, &key, &nonce, &aad).expect("custom seal");
        assert_eq!(plaintext, expected_ciphertext);
        assert_eq!(tag.as_slice(), expected_tag);
    }

    #[test]
    fn payload_counter_limit_is_exact() {
        if usize::BITS >= 64 {
            let maximum = usize::try_from(u64::from(u32::MAX) * 64)
                .expect("64-bit usize holds the RFC limit");
            assert_eq!(payload_blocks(maximum).expect("exact limit"), u32::MAX);
            assert!(matches!(
                payload_blocks(maximum + 1),
                Err(Error::LimitExceeded(_))
            ));
        }
    }

    #[test]
    fn matches_independent_rustcrypto_implementation() {
        let key = [0x42; 32];
        let nonce = [0x24; 12];
        let lengths = [
            0usize, 1, 15, 16, 17, 63, 64, 65, 1024, 4096, 1_048_575, 1_048_576,
        ];
        let aad_lengths = [0usize, 1, 15, 16, 17, 76];
        let oracle = ChaCha20Poly1305::new_from_slice(&key).expect("fixed-size oracle key");
        let oracle_nonce = Nonce::try_from(nonce.as_slice()).expect("fixed-size oracle nonce");

        for plaintext_len in lengths {
            for aad_len in aad_lengths {
                let aad = vec![0xa5; aad_len];
                let plaintext: Vec<u8> = (0..plaintext_len)
                    .map(|index| (index as u8).wrapping_mul(31))
                    .collect();
                let mut ours = plaintext.clone();
                let ours_tag = seal_record(&mut ours, &key, &nonce, &aad).expect("custom seal");

                let mut expected = plaintext.clone();
                let oracle_tag = oracle
                    .encrypt_inout_detached(&oracle_nonce, &aad, expected.as_mut_slice().into())
                    .expect("oracle seal");
                assert_eq!(ours, expected);
                assert_eq!(ours_tag.as_slice(), oracle_tag.as_slice());

                open_record(&mut ours, &ours_tag, &key, &nonce, &aad).expect("custom open");
                assert_eq!(ours, plaintext);
            }
        }
    }

    #[test]
    fn authentication_failure_releases_no_plaintext() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let aad = b"metadata";
        let mut ciphertext = b"top secret".to_vec();
        let tag = seal_record(&mut ciphertext, &key, &nonce, aad).expect("seal");

        let mut cases = Vec::new();
        let mut wrong_tag = tag;
        wrong_tag[0] ^= 1;
        cases.push((ciphertext.clone(), wrong_tag, key, nonce, aad.as_slice()));

        let mut wrong_key = key;
        wrong_key[0] ^= 1;
        cases.push((ciphertext.clone(), tag, wrong_key, nonce, aad.as_slice()));

        let mut wrong_nonce = nonce;
        wrong_nonce[0] ^= 1;
        cases.push((ciphertext.clone(), tag, key, wrong_nonce, aad.as_slice()));

        for (mut data, candidate_tag, candidate_key, candidate_nonce, candidate_aad) in cases {
            assert!(matches!(
                open_record(
                    &mut data,
                    &candidate_tag,
                    &candidate_key,
                    &candidate_nonce,
                    candidate_aad,
                ),
                Err(Error::AuthenticationFailure)
            ));
            assert!(data.iter().all(|byte| *byte == 0));
        }

        let mut data = ciphertext;
        assert!(matches!(
            open_record(&mut data, &tag, &key, &nonce, b"changed metadata"),
            Err(Error::AuthenticationFailure)
        ));
        assert!(data.iter().all(|byte| *byte == 0));
    }
}
