# AFL format fuzzing

The separate `encryptor-fuzz` package contains the real AFL targets used by CI:

- `header_afl` exercises canonical CPV2 and EDEKV2 header parsing.
- `structure_afl` exercises complete CPV2 record framing, checked offsets,
  finality, signature-trailer shape, and trailing-data rejection.

Neither target runs Argon2 or exposes/decrypts secret material, so malformed
input can be exercised at high throughput with bounded memory. Custom AEAD
correctness is covered separately by RFC vectors and an independent
development-time differential oracle.

Use exact locked dependencies:

```sh
cargo install cargo-afl --locked --version '=0.18.2'
cargo afl build \
  --manifest-path fuzz/Cargo.toml \
  --locked \
  --features afl \
  --bin header_afl \
  --bin structure_afl
```

Run the targets with separate output directories:

```sh
cargo afl fuzz -i fuzz/corpus/header -o fuzz/out/header -V 600 -- \
  fuzz/target/debug/header_afl
cargo afl fuzz -i fuzz/corpus/structure -o fuzz/out/structure -V 600 -- \
  fuzz/target/debug/structure_afl
```

CI tests the corpus decoder, compiles both targets on relevant changes, and runs
each target for ten minutes weekly. The release lane runs a bounded smoke test.
Corpus files beginning with `hex:` are decoded by the harness so canonical
NUL-containing CPV2/EDEKV2 seeds remain reviewable as newline-terminated text.
Every crash, timeout, or excessive-allocation input must be minimized and
committed as an ordinary regression test before it is considered resolved.
