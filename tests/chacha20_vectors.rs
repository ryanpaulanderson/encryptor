#[test]
fn rfc8439_block0() {
    // Test vector from RFC 8439 \u00a72.3.2
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let block = encryptor::chacha20_block(&secrecy::Secret::new(key), 1, &nonce);
    let expected = hex::decode(
        "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed\
         29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f",
    )
    .unwrap();
    assert_eq!(&block[..], &expected[..]);
}
