#!/usr/bin/env bash
set -euo pipefail

# Allow network access to pull crates
export CARGO_NET_OFFLINE=false

# Ensure lockfile and vendor directory are up to date
cargo generate-lockfile
cargo vendor

# Switch to offline mode for the build
export CARGO_NET_OFFLINE=true
mkdir -p .cargo
cat > .cargo/config.toml <<'EOC'
[net]
offline = true

[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOC

# Build release binary using vendored crates
cargo build --release --offline
