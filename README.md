# encryptor

A set of encryption experiments. Currently it includes only the `chacha20_poly1305` tool.

## Available Implementations

- **chacha20_poly1305**: Command line tool implemented in Rust that performs encryption and decryption using ChaCha20-Poly1305 with an Argon2 key derivation function and optional file hash verification.

## Installation

Run the provided setup script to install all build dependencies and the Rust toolchain:

```bash
sudo ./setup.sh
```

The script installs required system packages, sets up `rustup` if `rustc` is not present and fetches all crate dependencies.
If you already have Rust installed you can skip it and simply run `cargo fetch`.

After installing the toolchain you can vendor the dependencies and compile the binary in one step using the `build.sh` helper script:

```bash
./build.sh
```

## Getting started

The library can also be used directly from Rust code. The full API
documentation can be generated locally using `cargo doc --no-deps` and is
included in the repository under the `docs/` directory.

```rust
use chacha20_poly1305_custom::{Argon2Config, derive_key, encrypt_decrypt};

let cfg = Argon2Config::default();
let key = derive_key("secret", b"0123456789abcdef", &cfg).unwrap();
let nonce = [0u8; 12];
let cipher = encrypt_decrypt(b"hello", &key, &nonce);
let plain = encrypt_decrypt(&cipher, &key, &nonce);
assert_eq!(plain, b"hello");
```

## Library API Overview

This crate exposes several small utilities used by the command line tool and
tests:

- `Argon2Config` lets you tune the memory cost, number of passes and
  parallelism used by the Argon2id key derivation.
- `derive_key(password, salt, cfg)` produces a 32 byte ChaCha20 key wrapped in
  [`SecretBox<[u8; 32]>`](https://docs.rs/secrecy/latest/secrecy/struct.SecretBox.html).
- `encrypt_decrypt` processes a byte slice and returns the encrypted or
  decrypted output.
- `encrypt_decrypt_in_place` operates on a buffer in place while updating an
  external counter to support streaming.
- `chacha20_block` exposes the raw ChaCha20 block function which is verified
  against RFC&nbsp;8439 test vectors.
- `ct_eq` performs constant-time equality comparisons.
- `read_file_ct` reads files using the same code path for success and error
  cases to reduce leakage via timing.
- `sign` and `verify` create or validate detached Ed25519 signatures.
- `lock` and `unlock` wrap the platform `mlock` and `munlock` calls so secrets
  can be kept out of swap.

## Building

```bash
cargo build --release
```

The resulting binary will be located at `target/release/chacha20_poly1305`.

## Docker

A `Dockerfile` is provided for building a container image with the release binary.
Build and run it with:

```bash
docker build -t encryptor .
docker run --rm encryptor --help
```

## Usage

```
chacha20_poly1305 <encrypt|decrypt> <INPUT> <OUTPUT> \
    [--verify-hash <HEX>] [--mem-size <MiB>] [--iterations <N>] [--parallelism <N>] \
    [--sign-key <FILE>] [--verify-key <FILE>] [--verbose]
chacha20_poly1305 --generate-keys <DIR>
```

Arguments:

- `INPUT` – path to the file to read.
- `OUTPUT` – path of the file to write.
- `--verify-hash` – optional hex-encoded SHA256 hash of the encrypted file to verify before decryption.
- `--mem-size` – Argon2 memory usage in MiB (default: 64).
- `--iterations` – Argon2 iterations/passes (default: 4).
- `--parallelism` – Argon2 parallelism degree (default: 1).
- `--sign-key` – path to an Ed25519 private key to sign the encrypted output.
- `--verify-key` – path to an Ed25519 public key used to verify the signature.
- `--verbose` – print detailed error messages for debugging.
- `--generate-keys` – generate a new Ed25519 key pair in the given directory and exit.

Example encrypt:

```bash
chacha20_poly1305 encrypt plain.txt secret.bin
```

Example decrypt with integrity check:

```bash
chacha20_poly1305 decrypt secret.bin plain.txt --verify-hash <hash>
```

Example encrypt with a signature:

```bash
chacha20_poly1305 encrypt plain.txt secret.bin \
    --sign-key priv.key
```

Using an encrypted key:

```bash
chacha20_poly1305 encrypt plain.txt secret.bin \
    --sign-key priv.ekey
```

Example decrypt verifying the signature:

```bash
chacha20_poly1305 decrypt secret.bin plain.txt \
    --verify-key pub.key
```

Example key generation:

```bash
chacha20_poly1305 --generate-keys mykeys
```

We **recommend** generating keys with this command. It creates a new Ed25519
key pair using the correct format, encrypts the private key when a password is
supplied and stores the files with secure permissions. You will be prompted for
a password protecting the private key. Leaving the password empty stores the key
unencrypted and a warning is printed.

Private keys must be 32-byte raw Ed25519 seeds and the public key is the
corresponding 32-byte verifying key. When a seed is loaded, the program expands
it into the full 64 byte keypair internally so both halves are available for
signing and verification.

Keys can also be generated manually using `openssl rand -out priv.key 32` and
deriving the public key with a tool such as
[`ed25519-dalek`](https://docs.rs/ed25519-dalek/), but using our program is
preferred because it performs the encryption and sets the permissions
correctly.

## File Format

Files created by `chacha20_poly1305` start with a fixed size header:

1. 4 byte magic identifier `CPV1`.
2. 1 byte version field.
3. 3 reserved bytes set to zero.
4. 16 byte Argon2 salt.
5. 12 byte ChaCha20 nonce.

6. 64 byte Ed25519 signature (all zeros when the file is not signed).

The ciphertext is written next followed by a 16 byte Poly1305 tag.  The
signature covers the header with the signature field zeroed, the ciphertext and
the tag.

### Error Handling

The program exits with a non-zero status on failure. Errors are sanitized and
classified as I/O issues, Argon2 failures, format problems or authentication
errors to aid troubleshooting without leaking sensitive details. Pass
`--verbose` to print the underlying OS error for debugging.

## Security Notes

This tool reads input files using a constant-time routine and performs all tag
comparisons using constant-time equality checks to reduce timing side channels.
The Argon2 salt length is fixed at 16 bytes and enforced at compile time to
avoid accidentally using weaker parameters.

## Why Sign Files?

Signing adds an additional layer of integrity checking. When a signing key is
provided, the tool embeds an Ed25519 signature over the header, ciphertext and
authentication tag. Verification with the matching public key allows you to
detect tampering before decrypting the data.

## Running Tests

To run tests without a network connection you must prefetch the dependencies
first:

```bash
cargo fetch
cargo test --offline
```

This will compile the project and execute the tests found in the `tests/` directory entirely offline once the dependencies have been fetched.
The suite includes integration tests that drive the command line tool as well
as compile‑fail cases ensuring certain API misuses fail to build.

Criterion benchmarks can be executed with:

```bash
cargo bench --bench encryptor_benchmarks --offline
```

Running `cargo bench` also requires the dependencies to be vendored beforehand.

## Continuous Deployment

Merges to the `main` branch trigger a GitHub Actions workflow that
formats the code, lints with Clippy, runs the test suite, performs a
`cargo audit` vulnerability scan and builds a release binary. The
resulting executables are published as a GitHub release using the crate
version from `Cargo.toml`. Linux, macOS x86 and macOS arm64 binaries are
uploaded. Releases run the same audit before publishing artifacts.

An additional verification workflow executes the [Prusti](https://github.com/viperproject/prusti-dev)
tool to prove selected invariants in the cipher implementation.

## Attack Vectors and Known Issues

- **Home-grown ChaCha20 implementation**: the `chacha20_block` routine in `src/lib.rs` implements the cipher manually and has not been audited for constant-time behavior or correctness.
- **Low Argon2 parameters**: default KDF parameters are set to 64 MiB memory and 4 iterations which may not be sufficient against determined attackers. Adjust `--mem-size`, `--iterations` and `--parallelism` as needed.

## Reporting Vulnerabilities

Please see [SECURITY.md](SECURITY.md) for instructions on how to privately
report security issues.
