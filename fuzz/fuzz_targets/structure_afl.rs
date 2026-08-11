use afl::fuzz;
use encryptor::validate_envelope_structure;
use encryptor_fuzz::decode_corpus_seed;

fn main() {
    fuzz!(|data: &[u8]| {
        let decoded = decode_corpus_seed(data);
        let data = decoded.as_deref().unwrap_or(data);
        let _ = validate_envelope_structure(data);
    });
}
