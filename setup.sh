#!/usr/bin/env bash

# Simple setup script for the encryptor project.
# Installs system dependencies, Rust toolchain and pulls crate dependencies.

set -euo pipefail

if ! command -v rustc >/dev/null 2>&1; then
    apt-get update
    apt-get install -y --no-install-recommends build-essential curl
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Fetch Rust crate dependencies
cargo fetch

# Optionally build the project (uncomment to build)
# cargo build --release

echo "Setup complete."
