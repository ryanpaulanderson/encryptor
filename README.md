# encryptor

> [!WARNING]
> This is an educational custom cryptography experiment. Its hand-written
> ChaCha20-Poly1305 composition and file format have not been independently
> audited. It is a sole-maintainer hobby project. Do not use it to protect
> important, sensitive, or irreplaceable data.

`encryptor` provides the `chacha20_poly1305` Unix command-line tool. Version
0.53.0 uses the clean-break CPV2 streaming format, a fixed Argon2id profile,
authenticated records, optional Ed25519ph signatures, and atomic no-overwrite
output publication. CPV1 and EDEKV1 files are deliberately unsupported.

## Build

The tested development and release toolchain is Rust 1.97.1. This is not a
separate minimum-supported-Rust-version promise.

```sh
rustup toolchain install 1.97.1 --profile minimal --component rustfmt,clippy
cargo build --release --locked
```

The binary is written to `target/release/chacha20_poly1305`. Linux and macOS
are source-build/test platforms. Releases include an x86-64 Linux musl binary
and unsigned macOS binaries for Intel and Apple Silicon. The macOS archives are
not code-signed or notarized, so Gatekeeper may warn before running them.

The repository intentionally has no setup, vendoring, or Docker helper that
regenerates `Cargo.lock`. Fetching dependencies and preparing an offline cache
are explicit operator actions:

```sh
cargo fetch --locked
cargo test --all-features --locked --offline
```

## Usage

```text
chacha20_poly1305 encrypt INPUT OUTPUT [--sign-key KEYPAIR.ekey]
chacha20_poly1305 decrypt INPUT OUTPUT [--verify-key PUBLIC.key]
chacha20_poly1305 keygen KEYPAIR.ekey
chacha20_poly1305 export-public KEYPAIR.ekey PUBLIC.key
```

Encryption and key generation require password confirmation. Decryption
prompts once. Passwords are UTF-8 exactly as entered, without trimming or
normalization, and must contain between 1 and 1024 bytes.

```sh
chacha20_poly1305 encrypt plain.txt secret.cpv2
chacha20_poly1305 decrypt secret.cpv2 recovered.txt

chacha20_poly1305 keygen identity.ekey
chacha20_poly1305 export-public identity.ekey identity.pub
chacha20_poly1305 encrypt plain.txt signed.cpv2 --sign-key identity.ekey
chacha20_poly1305 decrypt signed.cpv2 recovered.txt --verify-key identity.pub
```

Signed envelopes always require `--verify-key`. Supplying a verification key
for an unsigned envelope is also rejected, preventing silent signature-policy
downgrades.

Inputs must be regular non-symlink files. Outputs are created under a random
mode-0600 sibling name, synchronized, and published using an atomic hard link
which refuses every existing file, directory, or symlink. Decryption writes
only individually authenticated records to the temporary file and publishes
it only after exact finality and any required signature have passed.

## Cryptographic profile

- Custom RFC 8439 ChaCha20-Poly1305 with the complete 128-bit tag.
- One fresh 16-byte salt and 8-byte record-nonce prefix per CPV2 file.
- Argon2id version 19, 64 MiB, three passes, four lanes, 32-byte output.
- Fixed 1 MiB records with authenticated index, length, order, and finality.
- Optional strict Ed25519ph/SHA-512 signatures with explicit domain separation.
- Maximum plaintext size `2^52` bytes (`2^32` records).

The runtime intentionally retains a custom composition. A maintained
ChaCha20-Poly1305 implementation is used only as a development-time
differential-test oracle. Passing vectors and differential tests is evidence
of interoperability, not an audit or proof of side-channel safety.

See [the CPV2/EDEKV2 format specification](docs/format-v2.md) and
[the threat model](docs/threat-model.md) for the exact contract. The
[v0.53.0 dependency review](docs/dependency-review.md) records the runtime,
test-oracle, fuzz, license, build-script, proc-macro, unsafe, and toolchain
impact decisions.

## Library API

The library exposes only complete file and key operations:

- `Password`
- `encrypt_file` / `decrypt_file`
- `generate_key_bundle` / `load_signing_identity`
- `export_public_key` / `load_verification_key`
- `EnvelopeMetadata` and read-only structural validation

Raw ChaCha20 blocks, stream-cipher XOR, caller-managed counters/nonces, raw
key derivation, and unauthenticated decryption are private. Secret-bearing
types do not expose raw bytes or implement `Debug`, `Display`, or `Clone`.

## Testing

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked
cargo test --release --all-features --locked
```

The suite contains RFC 8439 vectors, an independent differential oracle,
format properties, tamper and downgrade coverage, output-publication
regressions, key symlink/no-overwrite tests, CLI tests, and real AFL parser
targets. Timing experiments are non-gating regression observations and do not
support a constant-time claim.

## Release verification

Merging an untagged Cargo version to `main` runs the release test matrix and
publishes that version. Further merges do not republish it; a release-worthy
change must update `Cargo.toml` and this changelog first.

Release assets include a CycloneDX dependency inventory and `SHA256SUMS`.
Checksums detect accidental corruption but do not independently authenticate a
release. The macOS archives are deliberately unsigned and not notarized.

```sh
sha256sum -c SHA256SUMS
# macOS alternative:
shasum -a 256 -c SHA256SUMS
```

No signed-binary, notarization, reproducible-build, production-safety, or audit
claim is made. See [release operations](docs/release.md).

## Security reports

Please follow [SECURITY.md](SECURITY.md). Paths, file sizes, salts, nonces,
ciphertext, and identifiers may themselves be sensitive metadata; avoid
including real secrets or plaintext in a report.
