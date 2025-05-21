use encryptor::chacha20_block;
use secrecy::SecretBox;

#[test]
fn rfc8439_block0() {
    // Test vector from RFC 8439 \u00a72.3.2
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let block = chacha20_block(&SecretBox::new(Box::new(key)), 1, &nonce);
    let expected = hex::decode(
        "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed\
         29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f",
    )
    .unwrap();
    assert_eq!(&block[..], &expected[..]);
}

#[test]
fn rfc8439_block1() {
    // RFC 8439 \u00a72.3.2 test vector: counter=1, key=0..31
    let key = SecretBox::new(Box::new([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ]));
    let nonce = [
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ];
    let block = chacha20_block(&key, 1, &nonce);
    let expected = hex::decode(
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
         d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
    )
    .unwrap();
    assert_eq!(&block[..], &expected[..]);
}
