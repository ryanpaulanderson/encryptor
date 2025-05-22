use chacha20_poly1305_custom::chacha20_block;
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

#[test]
fn appendix_a_block1() {
    // RFC 7539 Appendix A.1 Test Vector #1: counter=0, key=all zeros
    let key = SecretBox::new(Box::new([0u8; 32]));
    let nonce = [0u8; 12];
    let block = chacha20_block(&key, 0, &nonce);
    let expected = hex::decode(
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7\
         da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
    )
    .unwrap();
    assert_eq!(&block[..], &expected[..]);
}

#[test]
fn appendix_a_block3() {
    // RFC 7539 Appendix A.1 Test Vector #3: key with last byte = 1
    let mut key_bytes = [0u8; 32];
    key_bytes[31] = 1;
    let key = SecretBox::new(Box::new(key_bytes));
    let nonce = [0u8; 12];
    let block = chacha20_block(&key, 1, &nonce);
    let expected = hex::decode(
        "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a\
         8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0",
    )
    .unwrap();
    assert_eq!(&block[..], &expected[..]);
}

#[test]
fn appendix_a_block4() {
    // RFC 7539 Appendix A.1 Test Vector #4: second byte of key = 0xff, counter=2
    let mut key_bytes = [0u8; 32];
    key_bytes[1] = 0xff;
    let key = SecretBox::new(Box::new(key_bytes));
    let nonce = [0u8; 12];
    let block = chacha20_block(&key, 2, &nonce);
    let expected = hex::decode(
        "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca\
         13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096",
    )
    .unwrap();
    assert_eq!(&block[..], &expected[..]);
}

#[test]
fn appendix_a_block5() {
    // RFC 7539 Appendix A.1 Test Vector #5: nonce incremented
    let key = SecretBox::new(Box::new([0u8; 32]));
    let nonce = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let block = chacha20_block(&key, 0, &nonce);
    let expected = hex::decode(
        "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c7\
         8a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d",
    )
    .unwrap();
    assert_eq!(&block[..], &expected[..]);
}
