# encryptor

Various encryption algorithms for my own playground.

## Available Implementations

- **chacha20_poly1305**: Command line tool implemented in Rust that performs encryption and decryption using ChaCha20-Poly1305 with an Argon2 key derivation function and optional file hash verification.

## Installation

Run the provided setup script to install all build dependencies and the Rust toolchain:

```bash
sudo ./setup.sh
```

The script installs required system packages, sets up `rustup` if `rustc` is not present and fetches all crate dependencies.
If you already have Rust installed you can skip it and simply run `cargo fetch`.

## Building

```bash
cargo build --release
```

The resulting binary will be located at `target/release/chacha20_poly1305`.

## Usage

```
chacha20_poly1305 <encrypt|decrypt> <INPUT> <OUTPUT> <PASSWORD> \
    [--verify-hash <HEX>] [--mem-size <MiB>] [--iterations <N>] [--parallelism <N>]
```

Arguments:

- `INPUT` – path to the file to read.
- `OUTPUT` – path of the file to write.
- `PASSWORD` – password used for the Argon2 key derivation.
- `--verify-hash` – optional hex-encoded SHA256 hash of the encrypted file to verify before decryption.
- `--mem-size` – Argon2 memory usage in MiB (default: 64).
- `--iterations` – Argon2 iterations/passes (default: 4).
- `--parallelism` – Argon2 parallelism degree (default: 1).

Example encrypt:

```bash
chacha20_poly1305 encrypt plain.txt secret.bin mypassword
```

Example decrypt with integrity check:

```bash
chacha20_poly1305 decrypt secret.bin plain.txt mypassword --verify-hash <hash>
```

## Security Notes

This tool reads input files using a constant-time routine and performs all tag
comparisons using constant-time equality checks to reduce timing side channels.

## Running Tests

To run tests without a network connection you must prefetch the dependencies
first:

```bash
cargo fetch
cargo test --offline
```

This will compile the project and execute the tests found in the `tests/` directory entirely offline once the dependencies have been fetched.

## Attack Vectors and Known Issues

- **Nonce reuse**: nonces are now deterministically derived from each encryption's random salt, ensuring a unique nonce whenever the salt is unique.
- **Home-grown ChaCha20 implementation**: the `chacha20_block` routine in `src/lib.rs` implements the cipher manually and has not been audited for constant-time behavior or correctness.
- **Low Argon2 parameters**: default KDF parameters are set to 64 MiB memory and 4 iterations which may not be sufficient against determined attackers. Adjust `--mem-size`, `--iterations` and `--parallelism` as needed.
