#!/usr/bin/env bash

# Simple setup script for the encryptor project.
# Installs system dependencies, Rust toolchain and pulls crate dependencies.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" >&2
    exit 1
fi

apt-get update
apt-get install -y --no-install-recommends \
    build-essential curl git pkg-config libssl-dev

if ! command -v rustc >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Fetch Rust crate dependencies and generate Cargo.lock
cargo fetch --locked

# Optionally build the project (uncomment to build)
# cargo build --release

echo "Setup complete."

