# Fuzzing the encryptor crate

This directory contains the fuzzing harness for the `encryptor` project. The target
`encryptor_fuzz` exercises both the streaming and non‑streaming encryption APIs
with random inputs.

## Prerequisites

1. Install the Rust toolchain and dependencies using the provided setup script:
   ```bash
   ./setup.sh
   ```
   This installs `cargo-fuzz` and vendors all crate dependencies so the fuzzer
   can run without network access.

2. Ensure `cargo-fuzz` is available in your `PATH` (the setup script installs it
   automatically). If you already have Rust installed you may simply run:
   ```bash
   cargo install cargo-fuzz
   ```

## Running

1. If this is the first time running the fuzzer, initialise the fuzz project:
   ```bash
   cargo fuzz init
   ```
   This command creates `fuzz/Cargo.toml` and supporting directories.

2. Start fuzzing with libFuzzer:
   ```bash
   cargo fuzz run encryptor_fuzz
   ```
   Crashing inputs are stored under `fuzz/artifacts/encryptor_fuzz/`.

3. To run entirely offline after dependencies have been fetched, set
   `CARGO_NET_OFFLINE=true`:
   ```bash
   CARGO_NET_OFFLINE=true cargo fuzz run encryptor_fuzz
   ```

4. The harness also supports AFL. Build and run using the `afl` feature:
   ```bash
   cargo install afl
   cargo afl fuzz -i afl_inputs -o afl_outputs -- \
       cargo run --features afl --bin encryptor_fuzz
   ```

## What does it test?

The fuzzer generates random passwords, salts, nonces and plaintext data. It
uses these values to derive a key with Argon2id and then encrypts and decrypts
the data using both `encrypt_decrypt_in_place` and `encrypt_decrypt`.
Assertions verify that the round trip restores the original bytes, ensuring the
two APIs behave identically across many edge cases.
