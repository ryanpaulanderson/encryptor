use encryptor::{
    Argon2Config, chacha20_block, ct_eq, derive_key, encrypt_decrypt, poly1305_tag, read_file_ct,
};

#[test]
fn encrypt_decrypt_roundtrip() {
    let password = "test-password";
    let salt = [0u8; 16];
    let nonce = [0u8; 12];
    let cfg = Argon2Config::default();
    let key = derive_key(password, &salt, &cfg).expect("derive key");
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
    let cfg = Argon2Config::default();
    let key = derive_key(password, &salt, &cfg).unwrap();
    let block0 = chacha20_block(&key, 0, &nonce);
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
    let header = b"header";
    let plaintext = b"message";
    let mut ciphertext = encrypt_decrypt(plaintext, &key, &nonce);
    let tag = poly1305_tag(&r, &s, header, &ciphertext);
    // flip a byte in ciphertext
    ciphertext[0] ^= 1;
    let wrong_tag = poly1305_tag(&r, &s, header, &ciphertext);
    assert!(!ct_eq(&tag, &wrong_tag));
}

#[test]
fn tampered_ciphertext_fails_to_authenticate() {
    let password = "pw";
    let salt = [3u8; 16];
    let nonce = [4u8; 12];
    let cfg = Argon2Config::default();
    let key = derive_key(password, &salt, &cfg).unwrap();
    let block0 = chacha20_block(&key, 0, &nonce);
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
    let header = b"hdr";
    let plaintext = b"secret";
    let ciphertext = encrypt_decrypt(plaintext, &key, &nonce);
    let tag = poly1305_tag(&r, &s, header, &ciphertext);

    let mut tampered = ciphertext.clone();
    tampered[1] ^= 0x80;
    let expected = poly1305_tag(&r, &s, header, &tampered);
    assert!(!ct_eq(&tag, &expected));
    let decrypted = encrypt_decrypt(&tampered, &key, &nonce);
    assert_ne!(plaintext.to_vec(), decrypted);
}

#[test]
fn tampered_tag_fails_to_authenticate() {
    let password = "pw2";
    let salt = [5u8; 16];
    let nonce = [6u8; 12];
    let cfg = Argon2Config::default();
    let key = derive_key(password, &salt, &cfg).unwrap();
    let block0 = chacha20_block(&key, 0, &nonce);
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
    let header = b"hdr2";
    let plaintext = b"data";
    let ciphertext = encrypt_decrypt(plaintext, &key, &nonce);
    let mut tag = poly1305_tag(&r, &s, header, &ciphertext);
    tag[0] ^= 0x01;
    let expected = poly1305_tag(&r, &s, header, &ciphertext);
    assert!(!ct_eq(&tag, &expected));
}

#[test]
fn derive_key_custom_params() {
    let password = "custom";
    let salt = [7u8; 16];
    let cfg = Argon2Config {
        mem_cost_kib: 32 * 1024,
        time_cost: 2,
        parallelism: 2,
    };
    let key = derive_key(password, &salt, &cfg).unwrap();

    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(cfg.mem_cost_kib, cfg.time_cost, cfg.parallelism, None).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut expected = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut expected)
        .unwrap();
    assert_eq!(key.to_vec(), expected.to_vec());
}

#[test]
fn cli_argon2_flags_parse() {
    use clap::{Parser, Subcommand};
    #[derive(Parser)]
    struct Args {
        #[command(subcommand)]
        mode: Mode,
        input_file: std::path::PathBuf,
        output_file: std::path::PathBuf,
        password: String,
        #[arg(long)]
        verify_hash: Option<String>,
        #[arg(long, default_value_t = 64)]
        mem_size: u32,
        #[arg(long, default_value_t = 4)]
        iterations: u32,
        #[arg(long, default_value_t = 1)]
        parallelism: u32,
    }

    #[derive(Subcommand)]
    enum Mode {
        Encrypt,
        Decrypt,
    }

    let args = Args::parse_from([
        "test",
        "--mem-size",
        "128",
        "--iterations",
        "5",
        "--parallelism",
        "3",
        "in",
        "out",
        "pw",
        "encrypt",
    ]);

    assert_eq!(args.mem_size, 128);
    assert_eq!(args.iterations, 5);
    assert_eq!(args.parallelism, 3);
}

#[test]
fn read_file_ct_matches_std() {
    use std::fs::{self, File};
    use std::io::Write;
    let path = "test_read_ct.tmp";
    let mut f = File::create(path).unwrap();
    f.write_all(b"data").unwrap();
    let expected = fs::read(path).unwrap();
    let actual = read_file_ct(&std::path::PathBuf::from(path)).unwrap();
    assert_eq!(expected, actual);
    fs::remove_file(path).unwrap();
}

#[test]
fn read_file_ct_error() {
    let result = read_file_ct(&std::path::PathBuf::from("does_not_exist"));
    assert!(result.is_err());
}
