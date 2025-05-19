use encryptor::{chacha20_block, encrypt_decrypt};

#[test]
fn test_chacha20_block_known_vector() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let block = chacha20_block(&key, 0, &nonce);
    let expected_hex = "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586";
    assert_eq!(hex::encode(block), expected_hex);
}

#[test]
fn test_encrypt_decrypt_round_trip() {
    let key = [7u8; 32];
    let nonce = [9u8; 12];
    let plaintext = b"hello world";
    let ciphertext = encrypt_decrypt(plaintext, &key, &nonce);
    let decrypted = encrypt_decrypt(&ciphertext, &key, &nonce);
    assert_eq!(decrypted, plaintext);
}
