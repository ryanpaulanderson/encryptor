# 1. Ensure we can fetch from crates.io
export CARGO_NET_OFFLINE=false

rustup component add rustfmt
rustup component add clippy
cargo install --version ^0.17 cargo-audit

# 2. Generate or update Cargo.lock (needed so vendor knows exactly what to pull)
cargo generate-lockfile

# 3. Vendor ALL direct+transitive crates locally
cargo vendor

# 4. Now lock down to offline-only mode
export CARGO_NET_OFFLINE=true

# 5. Tell Cargo where to find vendored crates
mkdir -p .cargo
cat > .cargo/config.toml << 'EOF'
[net]
offline = true

[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF
