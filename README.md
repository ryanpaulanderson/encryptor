# encryptor

Various encryption algorithms for my own playground.

## Available Implementations

- **chacha20_poly1305**: A command line tool implemented in Rust that performs encryption and decryption using ChaCha20-Poly1305 with an Argon2 key derivation function and optional file hash verification.

## Setup

Run `setup.sh` to install the Rust toolchain and fetch crate dependencies. The
script requires root privileges because it uses `apt-get` to install build
tools. After running it you can build the project with `cargo build`.
