//! Shared support for the AFL fuzz targets.

/// Decodes a reviewable `hex:` corpus seed into the bytes fed to a fuzz target.
///
/// A single trailing LF or CRLF is accepted because text corpus files normally
/// end with a line terminator. Inputs without the prefix, with an odd number of
/// digits, or with non-hex digits return `None` so the harness can fuzz the
/// original bytes instead.
pub fn decode_corpus_seed(input: &[u8]) -> Option<Vec<u8>> {
    let encoded = input.strip_prefix(b"hex:")?;
    let encoded = encoded
        .strip_suffix(b"\r\n")
        .or_else(|| encoded.strip_suffix(b"\n"))
        .unwrap_or(encoded);
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

#[cfg(test)]
mod tests {
    use super::decode_corpus_seed;

    #[test]
    fn decodes_newline_terminated_seed() {
        assert_eq!(
            decode_corpus_seed(b"hex:43505632\n"),
            Some(b"CPV2".to_vec())
        );
    }

    #[test]
    fn decodes_crlf_terminated_seed() {
        assert_eq!(
            decode_corpus_seed(b"hex:4544454b5632\r\n"),
            Some(b"EDEKV2".to_vec())
        );
    }

    #[test]
    fn committed_corpus_seeds_decode_to_expected_magic() {
        let cpv2_header = decode_corpus_seed(include_bytes!("../corpus/header/cpv2-signed-v2"))
            .expect("the committed CPV2 header seed must be canonical hex");
        let edekv2_header = decode_corpus_seed(include_bytes!("../corpus/header/edekv2-v2"))
            .expect("the committed EDEKV2 header seed must be canonical hex");
        let cpv2_structure =
            decode_corpus_seed(include_bytes!("../corpus/structure/cpv2-signed-v2"))
                .expect("the committed CPV2 structure seed must be canonical hex");

        assert!(cpv2_header.starts_with(b"CPV2"));
        assert!(edekv2_header.starts_with(b"EDEKV2"));
        assert!(cpv2_structure.starts_with(b"CPV2"));
    }

    #[test]
    fn rejects_noncanonical_encoded_seeds() {
        assert_eq!(decode_corpus_seed(b"raw"), None);
        assert_eq!(decode_corpus_seed(b"hex:0"), None);
        assert_eq!(decode_corpus_seed(b"hex:gg"), None);
        assert_eq!(decode_corpus_seed(b"hex:43\n50"), None);
    }
}
