use encryptor::{validate_envelope_structure, EnvelopeMetadata, KeyBundleMetadata};
use proptest::prelude::*;

proptest! {
    #[test]
    fn arbitrary_headers_never_panic_or_allocate_from_declared_length(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let _ = EnvelopeMetadata::parse_header(&bytes);
        let _ = KeyBundleMetadata::parse_header(&bytes);
    }

    #[test]
    fn arbitrary_record_state_inputs_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = validate_envelope_structure(&bytes);
    }
}

#[test]
fn exact_canonical_empty_header_is_accepted() {
    let mut header = [0u8; 64];
    header[..4].copy_from_slice(b"CPV2");
    header[4] = 2;
    header[6] = 1;
    header[7] = 1;
    header[8] = 0x13;
    header[9] = 32;
    header[12..16].copy_from_slice(&65_536u32.to_le_bytes());
    header[16..20].copy_from_slice(&3u32.to_le_bytes());
    header[20..24].copy_from_slice(&4u32.to_le_bytes());
    header[24..28].copy_from_slice(&1_048_576u32.to_le_bytes());
    let metadata = EnvelopeMetadata::parse_header(&header).expect("canonical header");
    assert_eq!(metadata.plaintext_len(), 0);
    assert_eq!(metadata.encoded_len().expect("encoded length"), 92);
}
