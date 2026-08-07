//! Experimental authenticated file encryption using a custom RFC 8439
//! ChaCha20-Poly1305 composition.
//!
//! # Security status
//!
//! This crate is an educational custom cryptography implementation. It has not
//! been independently audited and must not be used to protect important data.
//! Its public API deliberately exposes only complete authenticated file and key
//! workflows; nonce, counter, raw stream-cipher, and unauthenticated plaintext
//! operations are private.

#![cfg_attr(not(unix), allow(unused))]

#[cfg(not(unix))]
compile_error!("encryptor currently supports Unix platforms only");

mod atomic_output;
mod crypto;
mod format;

pub mod error;

pub use atomic_output::PublicationOutcome;
pub use error::{Error, Result};
pub use format::{EnvelopeMetadata, KeyBundleMetadata};

use argon2::{Algorithm, Argon2, Params, Version};
use atomic_output::{open_regular_nofollow, AtomicOutput};
use crypto::{open_record, seal_record, KEY_LEN, TAG_LEN};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use format::{
    encoded_file_len, record_count, FileHeader, KeyHeader, RecordHeader, FILE_HEADER_LEN,
    KDF_MEMORY_KIB, KDF_PARALLELISM, KDF_TIME, KEY_BUNDLE_LEN, KEY_HEADER_LEN, SIGNATURE_CONTEXT,
    SIGNATURE_DOMAIN, SIGNATURE_PREFIX,
};
use rand_core::{OsRng, TryRngCore};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretString};
use sha2::{Digest, Sha512};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const PASSWORD_MAX_BYTES: usize = 1024;
const PRIVATE_OUTPUT_MODE: u32 = 0o600;
const PUBLIC_OUTPUT_MODE: u32 = 0o644;

/// A validated UTF-8 password which zeroizes its owned storage on drop.
///
/// Password bytes are used exactly as provided, without trimming or Unicode
/// normalization. Empty passwords and passwords longer than 1024 bytes are
/// rejected.
pub struct Password {
    secret: SecretString,
}

impl Password {
    /// Validate and own a password.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPassword`] for an empty password or one longer
    /// than 1024 UTF-8 bytes.
    pub fn new(mut value: String) -> Result<Self> {
        if value.is_empty() {
            value.zeroize();
            return Err(Error::InvalidPassword("password must not be empty"));
        }
        if value.len() > PASSWORD_MAX_BYTES {
            value.zeroize();
            return Err(Error::InvalidPassword("password exceeds 1024 UTF-8 bytes"));
        }
        Ok(Self {
            secret: SecretString::from(value),
        })
    }

    /// Compare two validated passwords without early exit on differing bytes.
    pub fn matches(&self, other: &Self) -> bool {
        let mut left = Zeroizing::new([0u8; PASSWORD_MAX_BYTES]);
        let mut right = Zeroizing::new([0u8; PASSWORD_MAX_BYTES]);
        let left_bytes = self.as_bytes();
        let right_bytes = other.as_bytes();
        left[..left_bytes.len()].copy_from_slice(left_bytes);
        right[..right_bytes.len()].copy_from_slice(right_bytes);
        let same_content = left.as_slice().ct_eq(right.as_slice());
        let left_len = match u16::try_from(left_bytes.len()) {
            Ok(length) => length,
            Err(_) => return false,
        };
        let right_len = match u16::try_from(right_bytes.len()) {
            Ok(length) => length,
            Err(_) => return false,
        };
        bool::from(same_content & left_len.to_le_bytes().ct_eq(&right_len.to_le_bytes()))
    }

    fn as_bytes(&self) -> &[u8] {
        self.secret.expose_secret().as_bytes()
    }
}

/// An encrypted-file signing identity.
///
/// The private seed is never exposed by the public API and is zeroized on drop.
pub struct SigningIdentity {
    seed: SecretBox<[u8; 32]>,
}

/// A strict Ed25519 verification key.
pub struct VerificationKey {
    key: VerifyingKey,
}

/// Options for file encryption.
pub struct EncryptOptions<'a> {
    signing_identity: Option<&'a SigningIdentity>,
}

impl<'a> EncryptOptions<'a> {
    /// Encrypt without an external Ed25519 signature.
    pub fn unsigned() -> Self {
        Self {
            signing_identity: None,
        }
    }

    /// Encrypt and append an Ed25519ph signature.
    pub fn signed(identity: &'a SigningIdentity) -> Self {
        Self {
            signing_identity: Some(identity),
        }
    }
}

/// Options for file decryption.
pub struct DecryptOptions<'a> {
    verification_key: Option<&'a VerificationKey>,
}

impl<'a> DecryptOptions<'a> {
    /// Decrypt an unsigned envelope.
    pub fn unsigned() -> Self {
        Self {
            verification_key: None,
        }
    }

    /// Require and verify the envelope's Ed25519ph signature.
    pub fn require_signature(key: &'a VerificationKey) -> Self {
        Self {
            verification_key: Some(key),
        }
    }
}

fn fill_random(output: &mut [u8]) -> Result<()> {
    OsRng
        .try_fill_bytes(output)
        .map_err(|_| Error::EntropyFailure)
}

fn derive_key(password: &Password, salt: &[u8; 16]) -> Result<SecretBox<[u8; KEY_LEN]>> {
    let params = Params::new(KDF_MEMORY_KIB, KDF_TIME, KDF_PARALLELISM, Some(KEY_LEN))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = SecretBox::new(Box::new([0u8; KEY_LEN]));
    argon2.hash_password_into(password.as_bytes(), salt, output.expose_secret_mut())?;
    Ok(output)
}

fn read_exact<R: Read>(reader: &mut R, output: &mut [u8], operation: &'static str) -> Result<()> {
    reader
        .read_exact(output)
        .map_err(|source| Error::io(operation, source))
}

fn write_all<W: Write>(writer: &mut W, input: &[u8], operation: &'static str) -> Result<()> {
    writer
        .write_all(input)
        .map_err(|source| Error::io(operation, source))
}

fn ensure_eof(file: &mut File) -> Result<()> {
    let mut extra = [0u8; 1];
    let read = file
        .read(&mut extra)
        .map_err(|source| Error::io("checking input finality", source))?;
    if read != 0 {
        return Err(Error::InvalidFormat("unexpected trailing data"));
    }
    Ok(())
}

fn signature_digest(header: &FileHeader) -> Sha512 {
    let mut digest = Sha512::new();
    digest.update(SIGNATURE_DOMAIN);
    digest.update(header.bytes());
    digest
}

/// Inspect and preflight a CPV2 envelope without running Argon2 or decrypting.
///
/// # Errors
///
/// Returns an error if the input is not a regular non-symlink file, the header
/// is noncanonical, or its declared encoded size does not match the open file.
pub fn inspect_envelope(input: &Path) -> Result<EnvelopeMetadata> {
    let mut file = open_regular_nofollow(input)?;
    let file_len = file
        .metadata()
        .map_err(|source| Error::io("reading encrypted input metadata", source))?
        .len();
    let mut bytes = [0u8; FILE_HEADER_LEN];
    read_exact(&mut file, &mut bytes, "reading CPV2 header")?;
    let metadata = EnvelopeMetadata::parse_header(&bytes)?;
    if metadata.encoded_len()? != file_len {
        return Err(Error::InvalidFormat(
            "encoded length does not match CPV2 header",
        ));
    }
    Ok(metadata)
}

/// Validate the complete canonical CPV2 framing of an in-memory byte slice.
///
/// This read-only operation does not allocate based on encoded lengths, run
/// Argon2, authenticate ciphertext, or release plaintext. It exists for format
/// inspection and high-throughput parser fuzzing.
///
/// # Errors
///
/// Returns an error for noncanonical headers or records, length mismatch,
/// missing finality, an invalid signature-trailer prefix, or trailing data.
pub fn validate_envelope_structure(input: &[u8]) -> Result<EnvelopeMetadata> {
    format::validate_structure(input)
}

/// Encrypt a regular file into a canonical CPV2 envelope.
///
/// The destination is atomically published without overwrite only after the
/// complete envelope and optional signature have been generated and synced.
///
/// # Errors
///
/// Returns an error for invalid paths, excessive file size, entropy or KDF
/// failure, short or changing input, I/O failure, or an existing destination.
pub fn encrypt_file(
    input: &Path,
    output: &Path,
    password: &Password,
    options: EncryptOptions<'_>,
) -> Result<PublicationOutcome> {
    let mut input_file = open_regular_nofollow(input)?;
    let plaintext_len = input_file
        .metadata()
        .map_err(|source| Error::io("reading plaintext metadata", source))?
        .len();
    format::validate_plaintext_len(plaintext_len)?;

    let mut salt = [0u8; 16];
    let mut nonce_prefix = [0u8; 8];
    fill_random(&mut salt)?;
    fill_random(&mut nonce_prefix)?;
    let header = FileHeader::new(
        options.signing_identity.is_some(),
        plaintext_len,
        salt,
        nonce_prefix,
    )?;
    salt.zeroize();
    nonce_prefix.zeroize();
    let key = derive_key(password, &header.salt)?;
    let count = record_count(plaintext_len)?;
    let mut digest = options.signing_identity.map(|_| signature_digest(&header));
    let mut atomic_output: Option<AtomicOutput> = None;

    for index_u64 in 0..count {
        let index = u32::try_from(index_u64)
            .map_err(|_| Error::LimitExceeded("record index does not fit u32"))?;
        let record = RecordHeader::expected(index, plaintext_len)?;
        let length = usize::try_from(record.length)
            .map_err(|_| Error::LimitExceeded("record length does not fit usize"))?;
        let mut buffer = Zeroizing::new(vec![0u8; length]);
        read_exact(&mut input_file, &mut buffer, "reading plaintext record")?;
        let nonce = header.nonce(index);
        let aad = record.aad(&header);
        let tag = seal_record(&mut buffer, key.expose_secret(), &nonce, &aad)?;

        if atomic_output.is_none() {
            let mut created = AtomicOutput::new(output, PRIVATE_OUTPUT_MODE)?;
            write_all(&mut created, header.bytes(), "writing CPV2 header")?;
            atomic_output = Some(created);
        }
        let writer = atomic_output
            .as_mut()
            .ok_or(Error::InvalidFormat("output state was not initialized"))?;
        write_all(writer, record.bytes(), "writing record header")?;
        write_all(writer, &buffer, "writing ciphertext record")?;
        write_all(writer, &tag, "writing record tag")?;
        if let Some(signature) = digest.as_mut() {
            signature.update(record.bytes());
            signature.update(&buffer);
            signature.update(tag);
        }
        buffer.zeroize();
    }

    ensure_eof(&mut input_file)?;
    let writer = atomic_output
        .as_mut()
        .ok_or(Error::InvalidFormat("CPV2 requires at least one record"))?;
    if let (Some(identity), Some(mut signature_digest)) = (options.signing_identity, digest.take())
    {
        signature_digest.update(SIGNATURE_PREFIX);
        let signing_key = SigningKey::from_bytes(identity.seed.expose_secret());
        let signature = signing_key
            .sign_prehashed(signature_digest, Some(SIGNATURE_CONTEXT))
            .map_err(|_| Error::AuthenticationFailure)?;
        write_all(writer, &SIGNATURE_PREFIX, "writing signature trailer")?;
        write_all(writer, &signature.to_bytes(), "writing signature")?;
    }
    atomic_output
        .take()
        .ok_or(Error::InvalidFormat("output state was not initialized"))?
        .commit()
}

/// Decrypt a canonical CPV2 envelope with bounded memory.
///
/// Each record is authenticated before plaintext is written to the private
/// temporary output. The requested destination is published only after finality,
/// exact structure, and any required Ed25519ph signature have been verified.
///
/// # Errors
///
/// Returns an error for malformed input, policy mismatch, authentication or
/// signature failure, an existing destination, or any I/O/durability failure.
pub fn decrypt_file(
    input: &Path,
    output: &Path,
    password: &Password,
    options: DecryptOptions<'_>,
) -> Result<PublicationOutcome> {
    let mut input_file = open_regular_nofollow(input)?;
    let file_len = input_file
        .metadata()
        .map_err(|source| Error::io("reading encrypted input metadata", source))?
        .len();
    let mut header_bytes = [0u8; FILE_HEADER_LEN];
    read_exact(&mut input_file, &mut header_bytes, "reading CPV2 header")?;
    let header = FileHeader::parse(&header_bytes)?;
    let expected_len = encoded_file_len(header.plaintext_len, header.signed)?;
    if expected_len != file_len {
        return Err(Error::InvalidFormat(
            "encoded length does not match CPV2 header",
        ));
    }
    match (header.signed, options.verification_key) {
        (true, None) => {
            return Err(Error::InvalidFormat(
                "signed envelope requires a verification key",
            ));
        }
        (false, Some(_)) => {
            return Err(Error::InvalidFormat(
                "verification key supplied for an unsigned envelope",
            ));
        }
        _ => {}
    }

    let key = derive_key(password, &header.salt)?;
    let count = record_count(header.plaintext_len)?;
    let mut digest = header.signed.then(|| signature_digest(&header));
    let mut atomic_output: Option<AtomicOutput> = None;

    for index_u64 in 0..count {
        let index = u32::try_from(index_u64)
            .map_err(|_| Error::LimitExceeded("record index does not fit u32"))?;
        let mut encoded_record_header = [0u8; format::RECORD_HEADER_LEN];
        read_exact(
            &mut input_file,
            &mut encoded_record_header,
            "reading record header",
        )?;
        let record =
            RecordHeader::parse_expected(&encoded_record_header, index, header.plaintext_len)
                .map_err(|_| Error::AuthenticationFailure)?;
        let length = usize::try_from(record.length)
            .map_err(|_| Error::LimitExceeded("record length does not fit usize"))?;
        let mut buffer = Zeroizing::new(vec![0u8; length]);
        let mut tag = [0u8; TAG_LEN];
        read_exact(&mut input_file, &mut buffer, "reading ciphertext record")?;
        read_exact(&mut input_file, &mut tag, "reading record tag")?;
        if let Some(signature) = digest.as_mut() {
            signature.update(encoded_record_header);
            signature.update(&buffer);
            signature.update(tag);
        }
        let nonce = header.nonce(index);
        let aad = record.aad(&header);
        open_record(&mut buffer, &tag, key.expose_secret(), &nonce, &aad)?;

        if atomic_output.is_none() {
            atomic_output = Some(AtomicOutput::new(output, PRIVATE_OUTPUT_MODE)?);
        }
        let writer = atomic_output
            .as_mut()
            .ok_or(Error::InvalidFormat("output state was not initialized"))?;
        write_all(writer, &buffer, "writing authenticated plaintext record")?;
        buffer.zeroize();
        tag.zeroize();
    }

    if let (Some(key), Some(mut signature_digest)) = (options.verification_key, digest.take()) {
        let mut prefix = [0u8; SIGNATURE_PREFIX.len()];
        let mut signature_bytes = [0u8; 64];
        read_exact(&mut input_file, &mut prefix, "reading signature trailer")?;
        read_exact(&mut input_file, &mut signature_bytes, "reading signature")?;
        if prefix != SIGNATURE_PREFIX {
            return Err(Error::AuthenticationFailure);
        }
        signature_digest.update(SIGNATURE_PREFIX);
        let signature = Signature::from_bytes(&signature_bytes);
        key.key
            .verify_prehashed_strict(signature_digest, Some(SIGNATURE_CONTEXT), &signature)
            .map_err(|_| Error::AuthenticationFailure)?;
    }
    ensure_eof(&mut input_file)?;
    atomic_output
        .take()
        .ok_or(Error::InvalidFormat("CPV2 requires at least one record"))?
        .commit()
}

/// Generate one encrypted EDEKV2 Ed25519 key bundle.
///
/// The bundle contains the public key in its authenticated header and an
/// encrypted 32-byte private seed. Existing files and symlinks are never
/// replaced.
///
/// # Errors
///
/// Returns an error for entropy, KDF, I/O, or publication failure.
pub fn generate_key_bundle(output: &Path, password: &Password) -> Result<PublicationOutcome> {
    let mut seed = Zeroizing::new([0u8; 32]);
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    fill_random(&mut seed[..])?;
    fill_random(&mut salt)?;
    fill_random(&mut nonce)?;

    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let header = KeyHeader::new(salt, nonce, public_key);
    salt.zeroize();
    nonce.zeroize();
    let key = derive_key(password, &header.salt)?;
    let mut encrypted_seed = Zeroizing::new(*seed);
    seed.zeroize();
    let tag = seal_record(
        &mut encrypted_seed[..],
        key.expose_secret(),
        &header.nonce,
        &header.aad(),
    )?;

    let mut writer = AtomicOutput::new(output, PRIVATE_OUTPUT_MODE)?;
    write_all(&mut writer, header.bytes(), "writing EDEKV2 header")?;
    write_all(
        &mut writer,
        &encrypted_seed[..],
        "writing encrypted private seed",
    )?;
    write_all(&mut writer, &tag, "writing key-bundle tag")?;
    encrypted_seed.zeroize();
    writer.commit()
}

fn read_key_bundle(path: &Path) -> Result<(KeyHeader, [u8; 32], [u8; TAG_LEN])> {
    let mut file = open_regular_nofollow(path)?;
    let len = file
        .metadata()
        .map_err(|source| Error::io("reading key-bundle metadata", source))?
        .len();
    if len != KEY_BUNDLE_LEN as u64 {
        return Err(Error::InvalidFormat(
            "EDEKV2 bundle length is not 144 bytes",
        ));
    }
    let mut header_bytes = [0u8; KEY_HEADER_LEN];
    let mut encrypted_seed = [0u8; 32];
    let mut tag = [0u8; TAG_LEN];
    read_exact(&mut file, &mut header_bytes, "reading EDEKV2 header")?;
    read_exact(
        &mut file,
        &mut encrypted_seed,
        "reading encrypted private seed",
    )?;
    read_exact(&mut file, &mut tag, "reading key-bundle tag")?;
    ensure_eof(&mut file)?;
    Ok((KeyHeader::parse(&header_bytes)?, encrypted_seed, tag))
}

/// Load and authenticate an encrypted EDEKV2 signing identity.
///
/// # Errors
///
/// Returns an authentication error for a wrong password, changed bundle, or a
/// private seed that does not match the authenticated public key.
pub fn load_signing_identity(path: &Path, password: &Password) -> Result<SigningIdentity> {
    let (header, seed, mut tag) = read_key_bundle(path)?;
    let mut seed = Zeroizing::new(seed);
    let key = derive_key(password, &header.salt)?;
    open_record(
        &mut seed[..],
        &tag,
        key.expose_secret(),
        &header.nonce,
        &header.aad(),
    )?;
    tag.zeroize();
    let reconstructed = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    if !bool::from(reconstructed.ct_eq(&header.public_key)) {
        seed.zeroize();
        return Err(Error::AuthenticationFailure);
    }
    Ok(SigningIdentity {
        seed: SecretBox::new(Box::new(*seed)),
    })
}

/// Export the public key embedded in a canonical EDEKV2 bundle.
///
/// Public-key authenticity still depends on how the bundle itself was
/// obtained. Exporting does not require or expose the private-key password.
///
/// # Errors
///
/// Returns an error for a malformed bundle, I/O failure, or existing output.
pub fn export_public_key(bundle: &Path, output: &Path) -> Result<PublicationOutcome> {
    let (header, mut encrypted_seed, mut tag) = read_key_bundle(bundle)?;
    encrypted_seed.zeroize();
    tag.zeroize();
    VerifyingKey::from_bytes(&header.public_key)
        .map_err(|_| Error::InvalidFormat("invalid Ed25519 public key in key bundle"))?;
    let mut writer = AtomicOutput::new(output, PUBLIC_OUTPUT_MODE)?;
    write_all(&mut writer, &header.public_key, "writing public key")?;
    writer.commit()
}

/// Load an exact 32-byte Ed25519 verification key without following a symlink.
///
/// # Errors
///
/// Returns an error for an invalid file type, length, encoding, or I/O failure.
pub fn load_verification_key(path: &Path) -> Result<VerificationKey> {
    let mut file = open_regular_nofollow(path)?;
    let len = file
        .metadata()
        .map_err(|source| Error::io("reading public-key metadata", source))?
        .len();
    if len != 32 {
        return Err(Error::InvalidFormat("public key length is not 32 bytes"));
    }
    let mut bytes = [0u8; 32];
    read_exact(&mut file, &mut bytes, "reading public key")?;
    ensure_eof(&mut file)?;
    let key = VerifyingKey::from_bytes(&bytes)
        .map_err(|_| Error::InvalidFormat("invalid Ed25519 public key"))?;
    Ok(VerificationKey { key })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io;

    fn password() -> Password {
        Password::new("correct horse battery staple".to_owned()).expect("valid password")
    }

    fn encode_hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
        }
        encoded
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        let bytes = input.trim().as_bytes();
        assert_eq!(bytes.len() % 2, 0, "fixture hex must have byte pairs");
        bytes
            .chunks_exact(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).expect("fixture hex");
                let low = (pair[1] as char).to_digit(16).expect("fixture hex");
                ((high << 4) | low) as u8
            })
            .collect()
    }

    fn deterministic_v2_fixtures() -> (Vec<u8>, Vec<u8>, Vec<u8>, [u8; 32]) {
        let fixture_password = Password::new("fixture password".to_owned()).expect("password");
        let signing_seed = [0x44; 32];
        let signing_key = SigningKey::from_bytes(&signing_seed);
        let public_key = signing_key.verifying_key().to_bytes();

        let plaintext = b"golden CPV2 plaintext".to_vec();
        let file_header = FileHeader::new(true, plaintext.len() as u64, [0x11; 16], [0x22; 8])
            .expect("fixture file header");
        let file_key = derive_key(&fixture_password, &file_header.salt).expect("fixture file key");
        let record = RecordHeader::expected(0, plaintext.len() as u64).expect("fixture record");
        let mut ciphertext = plaintext.clone();
        let tag = seal_record(
            &mut ciphertext,
            file_key.expose_secret(),
            &file_header.nonce(0),
            &record.aad(&file_header),
        )
        .expect("fixture record seal");
        let mut digest = signature_digest(&file_header);
        digest.update(record.bytes());
        digest.update(&ciphertext);
        digest.update(tag);
        digest.update(SIGNATURE_PREFIX);
        let signature = signing_key
            .sign_prehashed(digest, Some(SIGNATURE_CONTEXT))
            .expect("fixture signature");
        let mut envelope = Vec::new();
        envelope.extend_from_slice(file_header.bytes());
        envelope.extend_from_slice(record.bytes());
        envelope.extend_from_slice(&ciphertext);
        envelope.extend_from_slice(&tag);
        envelope.extend_from_slice(&SIGNATURE_PREFIX);
        envelope.extend_from_slice(&signature.to_bytes());

        let key_header = KeyHeader::new([0x33; 16], [0x55; 12], public_key);
        let bundle_key =
            derive_key(&fixture_password, &key_header.salt).expect("fixture bundle key");
        let mut encrypted_seed = signing_seed;
        let bundle_tag = seal_record(
            &mut encrypted_seed,
            bundle_key.expose_secret(),
            &key_header.nonce,
            &key_header.aad(),
        )
        .expect("fixture bundle seal");
        let mut bundle = Vec::new();
        bundle.extend_from_slice(key_header.bytes());
        bundle.extend_from_slice(&encrypted_seed);
        bundle.extend_from_slice(&bundle_tag);

        (envelope, bundle, plaintext, public_key)
    }

    #[test]
    fn golden_v2_fixtures_are_stable_and_usable() {
        let (generated_envelope, generated_bundle, plaintext, public_key) =
            deterministic_v2_fixtures();
        let envelope = decode_hex(include_str!("../tests/fixtures/cpv2-signed-v2.hex"));
        let bundle = decode_hex(include_str!("../tests/fixtures/edekv2-v2.hex"));
        assert_eq!(encode_hex(&generated_envelope), encode_hex(&envelope));
        assert_eq!(encode_hex(&generated_bundle), encode_hex(&bundle));

        let metadata = validate_envelope_structure(&envelope).expect("golden envelope structure");
        assert!(metadata.is_signed());
        assert_eq!(metadata.plaintext_len(), plaintext.len() as u64);

        let directory = tempfile::tempdir().expect("fixture directory");
        let envelope_path = directory.path().join("fixture.cpv2");
        let bundle_path = directory.path().join("fixture.ekey");
        let output_path = directory.path().join("fixture.out");
        fs::write(&envelope_path, envelope).expect("golden envelope");
        fs::write(&bundle_path, bundle).expect("golden bundle");
        let verification_key = VerificationKey {
            key: VerifyingKey::from_bytes(&public_key).expect("golden public key"),
        };
        let _ = decrypt_file(
            &envelope_path,
            &output_path,
            &Password::new("fixture password".to_owned()).expect("fixture password"),
            DecryptOptions::require_signature(&verification_key),
        )
        .expect("decrypt golden envelope");
        assert_eq!(fs::read(output_path).expect("golden plaintext"), plaintext);
        let identity = load_signing_identity(
            &bundle_path,
            &Password::new("fixture password".to_owned()).expect("fixture password"),
        )
        .expect("load golden signing identity");
        assert_eq!(identity.seed.expose_secret(), &[0x44; 32]);
    }

    #[test]
    fn password_policy_is_exact() {
        assert!(Password::new(String::new()).is_err());
        assert!(Password::new("x".repeat(1024)).is_ok());
        assert!(Password::new("x".repeat(1025)).is_err());
        let composed = Password::new("é".to_owned()).expect("composed");
        let decomposed = Password::new("e\u{301}".to_owned()).expect("decomposed");
        assert!(!composed.matches(&decomposed));
    }

    #[test]
    fn exact_io_helpers_handle_fragmentation_and_propagate_failure() {
        struct FragmentedReader<'a>(&'a [u8]);
        impl Read for FragmentedReader<'_> {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                if output.is_empty() || self.0.is_empty() {
                    return Ok(0);
                }
                output[0] = self.0[0];
                self.0 = &self.0[1..];
                Ok(1)
            }
        }

        #[derive(Default)]
        struct FragmentedWriter(Vec<u8>);
        impl Write for FragmentedWriter {
            fn write(&mut self, input: &[u8]) -> io::Result<usize> {
                if input.is_empty() {
                    return Ok(0);
                }
                self.0.push(input[0]);
                Ok(1)
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _output: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("injected read failure"))
            }
        }

        let mut read = [0u8; 4];
        read_exact(&mut FragmentedReader(b"data"), &mut read, "fragmented read")
            .expect("short reads are retried");
        assert_eq!(&read, b"data");

        let mut writer = FragmentedWriter::default();
        write_all(&mut writer, b"data", "fragmented write").expect("short writes are retried");
        assert_eq!(writer.0, b"data");

        assert!(matches!(
            read_exact(&mut FailingReader, &mut read, "injected read"),
            Err(Error::Io {
                operation: "injected read",
                ..
            })
        ));
    }

    #[test]
    fn unsigned_file_round_trip_and_no_overwrite() {
        let directory = tempfile::tempdir().expect("temp directory");
        let input = directory.path().join("input");
        let encrypted = directory.path().join("encrypted");
        let decrypted = directory.path().join("decrypted");
        fs::write(&input, b"hello CPV2").expect("input");
        let _ = encrypt_file(&input, &encrypted, &password(), EncryptOptions::unsigned())
            .expect("encrypt");
        let _ = decrypt_file(
            &encrypted,
            &decrypted,
            &password(),
            DecryptOptions::unsigned(),
        )
        .expect("decrypt");
        assert_eq!(fs::read(&decrypted).expect("plaintext"), b"hello CPV2");
        assert!(
            encrypt_file(&input, &encrypted, &password(), EncryptOptions::unsigned(),).is_err()
        );
    }
}
