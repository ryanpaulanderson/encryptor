use encryptor::{derive_key, chacha20_block, encrypt_decrypt, poly1305_tag, ct_eq};

#[test]
fn encrypt_decrypt_roundtrip() {
    let password = "test-password";
    let salt = [0u8; 16];
    let nonce = [0u8; 12];
    let key = derive_key(password, &salt).expect("derive key");
    let plaintext = b"hello world";
    let ciphertext = encrypt_decrypt(plaintext, &key, &nonce);
    let decrypted = encrypt_decrypt(&ciphertext, &key, &nonce);
    assert_eq!(plaintext.to_vec(), decrypted);
}

#[test]
fn poly1305_tag_detects_modification() {
    let password = "pass";
    let salt = [1u8; 16];
    let nonce = [2u8; 12];
    let key = derive_key(password, &salt).unwrap();
    let block0 = chacha20_block(&key, 0, &nonce);
    let mut r_bytes = [0u8;16];
    r_bytes.copy_from_slice(&block0[..16]);
    let mut s_bytes = [0u8;16];
    s_bytes.copy_from_slice(&block0[16..32]);
    r_bytes[3] &= 15; r_bytes[7] &= 15; r_bytes[11] &= 15; r_bytes[15] &= 15;
    r_bytes[4] &= 252; r_bytes[8] &= 252; r_bytes[12] &= 252;
    let r = u128::from_le_bytes(r_bytes);
    let s = u128::from_le_bytes(s_bytes);
    let header = b"header";
    let plaintext = b"message";
    let mut ciphertext = encrypt_decrypt(plaintext, &key, &nonce);
    let tag = poly1305_tag(&r, &s, header, &ciphertext);
    // flip a byte in ciphertext
    ciphertext[0] ^= 1;
    let wrong_tag = poly1305_tag(&r, &s, header, &ciphertext);
    assert!(!ct_eq(&tag, &wrong_tag));
}
