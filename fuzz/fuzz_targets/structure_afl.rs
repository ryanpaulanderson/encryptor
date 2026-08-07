use afl::fuzz;
use encryptor::validate_envelope_structure;

fn decode_corpus_seed(input: &[u8]) -> Option<Vec<u8>> {
    let encoded = input.strip_prefix(b"hex:")?;
    if encoded.len() % 2 != 0 {
        return None;
    }
    encoded
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            u8::try_from((high << 4) | low).ok()
        })
        .collect()
}

fn main() {
    fuzz!(|data: &[u8]| {
        let decoded = decode_corpus_seed(data);
        let data = decoded.as_deref().unwrap_or(data);
        let _ = validate_envelope_structure(data);
    });
}
