# AGENTS.md

This file defines guidance for AI assistants (Codex) when interacting with the **encryptor** Rust repository. It ensures consistent, reproducible development and testing workflows.

## Purpose

* Provide clear instructions for code generation, formatting, and testing.
* Automate setup steps to handle dependencies, environment configuration, and offline workflows.
* Enforce security best practices (e.g., vendoring, offline builds).

## Recommended Setup

1. **Rust Toolchain**

   * Use Rust `stable` channel (>= 1.60.0).
   * Install via `rustup override set stable` in repo root.
   * Install Clippy for linting via `rustup component add clippy`

2. **Dependency Vendoring**

   ```sh
   # Generate Cargo.lock if missing
   cargo generate-lockfile

   # Vendor all dependencies locally
   cargo vendor
   ```

3. **Offline Configuration**
   Create `.cargo/config.toml` in the project root:

   ```toml
   [net]
   offline = true

   [source.crates-io]
   replace-with = "vendored-sources"

   [source.vendored-sources]
   directory = "vendor"
   ```

4. **Python Dependencies** (if any scripts exist)

   ```sh
   pip download -r requirements.txt -d wheelhouse/
   ```

   Use `pip install --no-index --find-links=wheelhouse/ -r requirements.txt` for offline installs.

## Code Generation Guidelines

* **Formatting**: Run `cargo fmt` after any code change.
* **Linting**: Run `cargo clippy -- -D warnings` to catch issues.
* **Testing**: Always verify with `cargo test --offline`.

## Common Tasks

* **Add New Feature**: Write unit tests first, then implement functionality, run tests.
* **Refactor**: Ensure `cargo test --offline` and `cargo clippy` pass.
* **Documentation**: Update `README.md` and doc-comments. Run `cargo doc --no-deps`.

## Security Practices

* **Zeroization**: Ensure any secret buffers use `Zeroize`.
* **AEAD**: Tag header and ciphertext with Poly1305; verify before decryption.
* **KDF Parameters**: Expose Argon2 config via CLI flags if adjustable.

## Workflow Automation

* **Pre-Commit Hook**: Enforce formatting, linting, and tests.
* **CI Configuration**: Use vendored dependencies, run `cargo test --offline`, no external network.

*End of AGENTS.md*
