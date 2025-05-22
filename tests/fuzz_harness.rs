mod harness {
    #![allow(dead_code)]
    include!("../fuzz/fuzz_targets/encryptor_fuzz.rs");

    #[cfg(test)]
    mod tests {
        use super::*;
        use arbitrary::{Arbitrary, Unstructured};
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(8))]
            #[test]
            fn fuzz_harness_property(raw in proptest::collection::vec(any::<u8>(), 0..512)) {
                let mut u = Unstructured::new(&raw);
                if let Ok(input) = FuzzInput::arbitrary(&mut u) {
                    process_input(input);
                }
            }
        }
    }
}
