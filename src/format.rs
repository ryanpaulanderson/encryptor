//! Canonical CPV2 and EDEKV2 parsing and serialization.

use crate::crypto::{NONCE_LEN, TAG_LEN};
use crate::error::{Error, Result};
use zeroize::Zeroize;

pub(crate) const FILE_MAGIC: &[u8; 4] = b"CPV2";
pub(crate) const FILE_HEADER_LEN: usize = 64;
pub(crate) const RECORD_HEADER_LEN: usize = 12;
pub(crate) const RECORD_SIZE: u32 = 1_048_576;
pub(crate) const RECORD_OVERHEAD: u64 = (RECORD_HEADER_LEN + TAG_LEN) as u64;
pub(crate) const SIGNATURE_TRAILER_LEN: u64 = 72;
pub(crate) const SIGNATURE_PREFIX: [u8; 8] = [b'S', b'I', b'G', b'2', 1, 0, 0, 0];
pub(crate) const RECORD_DOMAIN: &[u8] = b"encryptor/cpv2/record/v1";
pub(crate) const SIGNATURE_DOMAIN: &[u8] = b"encryptor/cpv2/signature/v1";
pub(crate) const SIGNATURE_CONTEXT: &[u8] = b"encryptor/cpv2/signature";
pub(crate) const MAX_PLAINTEXT_LEN: u64 = 1u64 << 52;

pub(crate) const KDF_MEMORY_KIB: u32 = 65_536;
pub(crate) const KDF_TIME: u32 = 3;
pub(crate) const KDF_PARALLELISM: u32 = 4;
pub(crate) const KDF_VERSION: u8 = 0x13;

pub(crate) const KEY_MAGIC: &[u8; 6] = b"EDEKV2";
pub(crate) const KEY_HEADER_LEN: usize = 96;
pub(crate) const KEY_BUNDLE_LEN: usize = KEY_HEADER_LEN + 32 + TAG_LEN;
pub(crate) const KEY_DOMAIN: &[u8] = b"encryptor/edekv2/key/v1";

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    let input = bytes
        .get(offset..offset + 4)
        .ok_or(Error::InvalidFormat("truncated 32-bit field"))?;
    Ok(u32::from_le_bytes([input[0], input[1], input[2], input[3]]))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    let input = bytes
        .get(offset..offset + 8)
        .ok_or(Error::InvalidFormat("truncated 64-bit field"))?;
    Ok(u64::from_le_bytes([
        input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7],
    ]))
}

fn fixed<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    let input = bytes
        .get(offset..offset + N)
        .ok_or(Error::InvalidFormat("truncated fixed-size field"))?;
    let mut output = [0u8; N];
    output.copy_from_slice(input);
    Ok(output)
}

fn require_zero(bytes: &[u8], start: usize, end: usize) -> Result<()> {
    let reserved = bytes
        .get(start..end)
        .ok_or(Error::InvalidFormat("truncated reserved field"))?;
    if reserved.iter().any(|byte| *byte != 0) {
        return Err(Error::InvalidFormat("reserved bytes are nonzero"));
    }
    Ok(())
}

/// Public, non-secret metadata extracted from a canonical CPV2 header.
pub struct EnvelopeMetadata {
    signed: bool,
    plaintext_len: u64,
}

/// Public, non-secret metadata extracted from an EDEKV2 key-bundle header.
pub struct KeyBundleMetadata {
    public_key: [u8; 32],
}

impl KeyBundleMetadata {
    /// Parse and validate a complete 96-byte EDEKV2 header without running the KDF.
    pub fn parse_header(bytes: &[u8]) -> Result<Self> {
        let header = KeyHeader::parse(bytes)?;
        Ok(Self {
            public_key: header.public_key,
        })
    }

    /// Return the raw Ed25519 public key embedded in the bundle header.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
}

impl EnvelopeMetadata {
    /// Parse and validate a complete 64-byte CPV2 header.
    ///
    /// This operation performs no allocation proportional to input and does not
    /// invoke the password KDF.
    pub fn parse_header(bytes: &[u8]) -> Result<Self> {
        let header = FileHeader::parse(bytes)?;
        Ok(Self {
            signed: header.signed,
            plaintext_len: header.plaintext_len,
        })
    }

    /// Whether the envelope requires an Ed25519ph verification key.
    pub fn is_signed(&self) -> bool {
        self.signed
    }

    /// Plaintext length declared by the canonical header.
    ///
    /// Record authentication binds this value during decryption; structural
    /// inspection alone does not authenticate it.
    pub fn plaintext_len(&self) -> u64 {
        self.plaintext_len
    }

    /// Canonical CPV2 encoded length calculated with checked arithmetic.
    pub fn encoded_len(&self) -> Result<u64> {
        encoded_file_len(self.plaintext_len, self.signed)
    }
}

pub(crate) struct FileHeader {
    bytes: [u8; FILE_HEADER_LEN],
    pub(crate) signed: bool,
    pub(crate) plaintext_len: u64,
    pub(crate) salt: [u8; 16],
    nonce_prefix: [u8; 8],
}

impl FileHeader {
    pub(crate) fn new(
        signed: bool,
        plaintext_len: u64,
        salt: [u8; 16],
        nonce_prefix: [u8; 8],
    ) -> Result<Self> {
        validate_plaintext_len(plaintext_len)?;
        let mut bytes = [0u8; FILE_HEADER_LEN];
        bytes[..4].copy_from_slice(FILE_MAGIC);
        bytes[4] = 2;
        bytes[5] = u8::from(signed);
        bytes[6] = 1;
        bytes[7] = 1;
        bytes[8] = KDF_VERSION;
        bytes[9] = 32;
        bytes[12..16].copy_from_slice(&KDF_MEMORY_KIB.to_le_bytes());
        bytes[16..20].copy_from_slice(&KDF_TIME.to_le_bytes());
        bytes[20..24].copy_from_slice(&KDF_PARALLELISM.to_le_bytes());
        bytes[24..28].copy_from_slice(&RECORD_SIZE.to_le_bytes());
        bytes[28..36].copy_from_slice(&plaintext_len.to_le_bytes());
        bytes[36..52].copy_from_slice(&salt);
        bytes[52..60].copy_from_slice(&nonce_prefix);
        Ok(Self {
            bytes,
            signed,
            plaintext_len,
            salt,
            nonce_prefix,
        })
    }

    pub(crate) fn parse(input: &[u8]) -> Result<Self> {
        if input.len() != FILE_HEADER_LEN {
            return Err(Error::InvalidFormat("CPV2 header length is not 64 bytes"));
        }
        let bytes = fixed::<FILE_HEADER_LEN>(input, 0)?;
        if bytes.get(..4) != Some(FILE_MAGIC.as_slice()) || bytes[4] != 2 {
            return Err(Error::InvalidFormat("unsupported file magic or version"));
        }
        if bytes[5] & !1 != 0 {
            return Err(Error::InvalidFormat("unknown file flags"));
        }
        if bytes[6] != 1 || bytes[7] != 1 || bytes[8] != KDF_VERSION || bytes[9] != 32 {
            return Err(Error::InvalidFormat("unsupported cryptographic profile"));
        }
        require_zero(&bytes, 10, 12)?;
        require_zero(&bytes, 60, 64)?;
        if u32_at(&bytes, 12)? != KDF_MEMORY_KIB
            || u32_at(&bytes, 16)? != KDF_TIME
            || u32_at(&bytes, 20)? != KDF_PARALLELISM
            || u32_at(&bytes, 24)? != RECORD_SIZE
        {
            return Err(Error::InvalidFormat("noncanonical KDF or record profile"));
        }
        let plaintext_len = u64_at(&bytes, 28)?;
        validate_plaintext_len(plaintext_len)?;
        Ok(Self {
            bytes,
            signed: bytes[5] == 1,
            plaintext_len,
            salt: fixed::<16>(&bytes, 36)?,
            nonce_prefix: fixed::<8>(&bytes, 52)?,
        })
    }

    pub(crate) fn bytes(&self) -> &[u8; FILE_HEADER_LEN] {
        &self.bytes
    }

    pub(crate) fn nonce(&self, index: u32) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..8].copy_from_slice(&self.nonce_prefix);
        nonce[8..].copy_from_slice(&index.to_le_bytes());
        nonce
    }
}

impl Drop for FileHeader {
    fn drop(&mut self) {
        self.salt.zeroize();
        self.nonce_prefix.zeroize();
    }
}

pub(crate) struct RecordHeader {
    bytes: [u8; RECORD_HEADER_LEN],
    pub(crate) length: u32,
}

impl RecordHeader {
    pub(crate) fn expected(index: u32, plaintext_len: u64) -> Result<Self> {
        let count = record_count(plaintext_len)?;
        let final_record = u64::from(index) + 1 == count;
        let consumed = u64::from(index)
            .checked_mul(u64::from(RECORD_SIZE))
            .ok_or(Error::LimitExceeded("record offset overflow"))?;
        let remaining = plaintext_len
            .checked_sub(consumed)
            .ok_or(Error::InvalidFormat(
                "record index exceeds plaintext length",
            ))?;
        let length_u64 = remaining.min(u64::from(RECORD_SIZE));
        let length = u32::try_from(length_u64)
            .map_err(|_| Error::LimitExceeded("record length does not fit u32"))?;
        let mut bytes = [0u8; RECORD_HEADER_LEN];
        bytes[..4].copy_from_slice(&index.to_le_bytes());
        bytes[4..8].copy_from_slice(&length.to_le_bytes());
        bytes[8] = u8::from(final_record);
        Ok(Self { bytes, length })
    }

    pub(crate) fn parse_expected(
        input: &[u8; RECORD_HEADER_LEN],
        expected_index: u32,
        plaintext_len: u64,
    ) -> Result<Self> {
        require_zero(input, 9, 12)?;
        if input[8] & !1 != 0 {
            return Err(Error::InvalidFormat("unknown record flags"));
        }
        let expected = Self::expected(expected_index, plaintext_len)?;
        if input != &expected.bytes {
            return Err(Error::InvalidFormat("noncanonical record header"));
        }
        Ok(expected)
    }

    pub(crate) fn bytes(&self) -> &[u8; RECORD_HEADER_LEN] {
        &self.bytes
    }

    pub(crate) fn aad(&self, file_header: &FileHeader) -> Vec<u8> {
        let mut aad = Vec::with_capacity(RECORD_DOMAIN.len() + FILE_HEADER_LEN + RECORD_HEADER_LEN);
        aad.extend_from_slice(RECORD_DOMAIN);
        aad.extend_from_slice(file_header.bytes());
        aad.extend_from_slice(&self.bytes);
        aad
    }
}

pub(crate) fn validate_plaintext_len(plaintext_len: u64) -> Result<()> {
    if plaintext_len > MAX_PLAINTEXT_LEN {
        return Err(Error::LimitExceeded(
            "plaintext exceeds the CPV2 file limit",
        ));
    }
    record_count(plaintext_len).map(|_| ())
}

pub(crate) fn record_count(plaintext_len: u64) -> Result<u64> {
    if plaintext_len > MAX_PLAINTEXT_LEN {
        return Err(Error::LimitExceeded(
            "plaintext exceeds the CPV2 file limit",
        ));
    }
    let count = if plaintext_len == 0 {
        1
    } else {
        plaintext_len
            .checked_sub(1)
            .and_then(|value| value.checked_div(u64::from(RECORD_SIZE)))
            .and_then(|value| value.checked_add(1))
            .ok_or(Error::LimitExceeded("record count overflow"))?
    };
    if count > u64::from(u32::MAX) + 1 {
        return Err(Error::LimitExceeded("CPV2 record index space exhausted"));
    }
    Ok(count)
}

pub(crate) fn encoded_file_len(plaintext_len: u64, signed: bool) -> Result<u64> {
    let count = record_count(plaintext_len)?;
    let records_overhead = count
        .checked_mul(RECORD_OVERHEAD)
        .ok_or(Error::LimitExceeded("record overhead overflow"))?;
    let signature_len = if signed { SIGNATURE_TRAILER_LEN } else { 0 };
    (FILE_HEADER_LEN as u64)
        .checked_add(plaintext_len)
        .and_then(|value| value.checked_add(records_overhead))
        .and_then(|value| value.checked_add(signature_len))
        .ok_or(Error::LimitExceeded("encoded file length overflow"))
}

pub(crate) fn validate_structure(input: &[u8]) -> Result<EnvelopeMetadata> {
    let header_bytes = input
        .get(..FILE_HEADER_LEN)
        .ok_or(Error::InvalidFormat("truncated CPV2 header"))?;
    let header = FileHeader::parse(header_bytes)?;
    let encoded_len = encoded_file_len(header.plaintext_len, header.signed)?;
    let actual_len = u64::try_from(input.len())
        .map_err(|_| Error::LimitExceeded("input length does not fit u64"))?;
    if encoded_len != actual_len {
        return Err(Error::InvalidFormat(
            "encoded length does not match CPV2 header",
        ));
    }

    let mut offset = FILE_HEADER_LEN;
    let count = record_count(header.plaintext_len)?;
    for index_u64 in 0..count {
        let index = u32::try_from(index_u64)
            .map_err(|_| Error::LimitExceeded("record index does not fit u32"))?;
        let end = offset
            .checked_add(RECORD_HEADER_LEN)
            .ok_or(Error::LimitExceeded("record-header offset overflow"))?;
        let encoded_header = input
            .get(offset..end)
            .ok_or(Error::InvalidFormat("truncated record header"))?;
        let mut record_bytes = [0u8; RECORD_HEADER_LEN];
        record_bytes.copy_from_slice(encoded_header);
        let record = RecordHeader::parse_expected(&record_bytes, index, header.plaintext_len)?;
        let record_body = usize::try_from(record.length)
            .map_err(|_| Error::LimitExceeded("record length does not fit usize"))?
            .checked_add(TAG_LEN)
            .ok_or(Error::LimitExceeded("record-body length overflow"))?;
        offset = end
            .checked_add(record_body)
            .ok_or(Error::LimitExceeded("record-body offset overflow"))?;
        if offset > input.len() {
            return Err(Error::InvalidFormat("truncated record body"));
        }
    }

    if header.signed {
        let prefix_end = offset
            .checked_add(SIGNATURE_PREFIX.len())
            .ok_or(Error::LimitExceeded("signature offset overflow"))?;
        if input.get(offset..prefix_end) != Some(SIGNATURE_PREFIX.as_slice()) {
            return Err(Error::InvalidFormat("invalid signature trailer prefix"));
        }
        offset = offset
            .checked_add(SIGNATURE_TRAILER_LEN as usize)
            .ok_or(Error::LimitExceeded("signature-trailer offset overflow"))?;
    }
    if offset != input.len() {
        return Err(Error::InvalidFormat("unexpected trailing data"));
    }
    Ok(EnvelopeMetadata {
        signed: header.signed,
        plaintext_len: header.plaintext_len,
    })
}

pub(crate) struct KeyHeader {
    bytes: [u8; KEY_HEADER_LEN],
    pub(crate) salt: [u8; 16],
    pub(crate) nonce: [u8; NONCE_LEN],
    pub(crate) public_key: [u8; 32],
}

impl KeyHeader {
    pub(crate) fn new(salt: [u8; 16], nonce: [u8; NONCE_LEN], public_key: [u8; 32]) -> Self {
        let mut bytes = [0u8; KEY_HEADER_LEN];
        bytes[..6].copy_from_slice(KEY_MAGIC);
        bytes[6] = 2;
        bytes[8] = 1;
        bytes[9] = 1;
        bytes[10] = KDF_VERSION;
        bytes[11] = 32;
        bytes[12..16].copy_from_slice(&KDF_MEMORY_KIB.to_le_bytes());
        bytes[16..20].copy_from_slice(&KDF_TIME.to_le_bytes());
        bytes[20..24].copy_from_slice(&KDF_PARALLELISM.to_le_bytes());
        bytes[24..40].copy_from_slice(&salt);
        bytes[40..52].copy_from_slice(&nonce);
        bytes[52..84].copy_from_slice(&public_key);
        Self {
            bytes,
            salt,
            nonce,
            public_key,
        }
    }

    pub(crate) fn parse(input: &[u8]) -> Result<Self> {
        if input.len() != KEY_HEADER_LEN {
            return Err(Error::InvalidFormat("EDEKV2 header length is not 96 bytes"));
        }
        let bytes = fixed::<KEY_HEADER_LEN>(input, 0)?;
        if bytes.get(..6) != Some(KEY_MAGIC.as_slice()) || bytes[6] != 2 {
            return Err(Error::InvalidFormat(
                "unsupported key-bundle magic or version",
            ));
        }
        if bytes[7] != 0
            || bytes[8] != 1
            || bytes[9] != 1
            || bytes[10] != KDF_VERSION
            || bytes[11] != 32
        {
            return Err(Error::InvalidFormat("unsupported key-bundle profile"));
        }
        if u32_at(&bytes, 12)? != KDF_MEMORY_KIB
            || u32_at(&bytes, 16)? != KDF_TIME
            || u32_at(&bytes, 20)? != KDF_PARALLELISM
        {
            return Err(Error::InvalidFormat("noncanonical key-bundle KDF profile"));
        }
        require_zero(&bytes, 84, 96)?;
        Ok(Self {
            bytes,
            salt: fixed::<16>(&bytes, 24)?,
            nonce: fixed::<NONCE_LEN>(&bytes, 40)?,
            public_key: fixed::<32>(&bytes, 52)?,
        })
    }

    pub(crate) fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(KEY_DOMAIN.len() + KEY_HEADER_LEN);
        aad.extend_from_slice(KEY_DOMAIN);
        aad.extend_from_slice(&self.bytes);
        aad
    }

    pub(crate) fn bytes(&self) -> &[u8; KEY_HEADER_LEN] {
        &self.bytes
    }
}

impl Drop for KeyHeader {
    fn drop(&mut self) {
        self.salt.zeroize();
        self.nonce.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_file_lengths_are_checked() {
        assert_eq!(record_count(0).expect("empty count"), 1);
        assert_eq!(record_count(1).expect("one-byte count"), 1);
        assert_eq!(
            record_count(u64::from(RECORD_SIZE)).expect("exact count"),
            1
        );
        assert_eq!(
            record_count(u64::from(RECORD_SIZE) + 1).expect("two records"),
            2
        );
        assert_eq!(
            encoded_file_len(0, false).expect("empty encoded size"),
            (FILE_HEADER_LEN + RECORD_HEADER_LEN + TAG_LEN) as u64
        );
        assert!(validate_plaintext_len(MAX_PLAINTEXT_LEN + 1).is_err());
    }

    #[test]
    fn reserved_file_header_bytes_are_rejected() {
        let header = FileHeader::new(false, 0, [1; 16], [2; 8]).expect("header");
        let mut encoded = *header.bytes();
        encoded[63] = 1;
        assert!(FileHeader::parse(&encoded).is_err());
    }

    #[test]
    fn every_key_bundle_profile_field_class_is_canonical() {
        let header = KeyHeader::new([1; 16], [2; 12], [3; 32]);
        for offset in [0usize, 6, 7, 8, 9, 10, 11, 12, 16, 20, 84] {
            let mut encoded = *header.bytes();
            encoded[offset] ^= 0x80;
            assert!(
                KeyHeader::parse(&encoded).is_err(),
                "key-bundle profile field at byte {offset} was accepted"
            );
        }
    }

    #[test]
    fn canonical_v2_headers_are_stable() {
        let file = FileHeader::new(false, 0x000f_0304_0506_0708, [0x11; 16], [0x22; 8])
            .expect("file header");
        let mut expected_file = [0u8; FILE_HEADER_LEN];
        expected_file[..4].copy_from_slice(b"CPV2");
        expected_file[4] = 2;
        expected_file[6] = 1;
        expected_file[7] = 1;
        expected_file[8] = 0x13;
        expected_file[9] = 32;
        expected_file[12..16].copy_from_slice(&65_536u32.to_le_bytes());
        expected_file[16..20].copy_from_slice(&3u32.to_le_bytes());
        expected_file[20..24].copy_from_slice(&4u32.to_le_bytes());
        expected_file[24..28].copy_from_slice(&1_048_576u32.to_le_bytes());
        expected_file[28..36].copy_from_slice(&0x000f_0304_0506_0708u64.to_le_bytes());
        expected_file[36..52].fill(0x11);
        expected_file[52..60].fill(0x22);
        assert_eq!(file.bytes(), &expected_file);

        let key = KeyHeader::new([0x33; 16], [0x44; 12], [0x55; 32]);
        let mut expected_key = [0u8; KEY_HEADER_LEN];
        expected_key[..6].copy_from_slice(b"EDEKV2");
        expected_key[6] = 2;
        expected_key[8] = 1;
        expected_key[9] = 1;
        expected_key[10] = 0x13;
        expected_key[11] = 32;
        expected_key[12..16].copy_from_slice(&65_536u32.to_le_bytes());
        expected_key[16..20].copy_from_slice(&3u32.to_le_bytes());
        expected_key[20..24].copy_from_slice(&4u32.to_le_bytes());
        expected_key[24..40].fill(0x33);
        expected_key[40..52].fill(0x44);
        expected_key[52..84].fill(0x55);
        assert_eq!(key.bytes(), &expected_key);
    }
}
