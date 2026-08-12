use afl::fuzz;
use encryptor::{EnvelopeMetadata, KeyBundleMetadata};
use encryptor_fuzz::decode_corpus_seed;

fn main() {
    fuzz!(|data: &[u8]| {
        let decoded = decode_corpus_seed(data);
        let data = decoded.as_deref().unwrap_or(data);
        if let Some(header) = data.get(..64) {
            let _ = EnvelopeMetadata::parse_header(header);
        }
        if let Some(header) = data.get(..96) {
            let _ = KeyBundleMetadata::parse_header(header);
        }
    });
}
