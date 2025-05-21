# 1. Ensure we can fetch from crates.io
export CARGO_NET_OFFLINE=false

rustup component add rustfmt
rustup component add clippy
cargo install cargo-fuzz
cargo install --version ^0.21 cargo-audit

# 2. Generate or update Cargo.lock (needed so vendor knows exactly what to pull) :contentReference[oaicite:0]{index=0}
cargo generate-lockfile

# 3. Vendor ALL direct+transitive crates locally :contentReference[oaicite:1]{index=1}
cargo vendor

# 4. Now lock down to offline-only mode :contentReference[oaicite:2]{index=2}
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