# Continuous Deployment Plan

This project currently provides only a binary. A simple CD approach can publish release artifacts whenever changes are merged into the `main` branch.

1. **Build**
   - Run the existing CI workflow to ensure `cargo fmt`, `cargo clippy` and `cargo test --offline` succeed.
   - Build a release binary using `cargo build --release`.

2. **Package**
   - Archive the binary from `target/release/chacha20_poly1305`.
   - Optionally create a Docker image containing the executable for easier distribution.

3. **Release**
   - Use `actions/create-release` to publish a GitHub Release with the built artifact.
   - Tag the release with the crate version from `Cargo.toml`.

4. **Deploy**
   - For internal use, download the release artifact and deploy to the target environment (e.g., copy to servers or upload to a package repository).
   - If using a container image, push it to a registry and deploy using the chosen orchestration tool.

This plan can be expanded later with automated signing, multi-platform builds and staging environments.
