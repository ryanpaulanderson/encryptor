# AGENTS.md

This file defines guidance for AI assistants (Codex) when interacting with the **encryptor** Rust repository. It ensures consistent, reproducible development and testing workflows.

## Purpose

* Provide clear instructions for code generation, formatting, and testing.
* Automate setup steps to handle dependencies, environment configuration, and offline workflows.
* Enforce security best practices (e.g., vendoring, offline builds).

## Recommended Setup

1. **Rust Toolchain**
   * Pin a `rust-toolchain.toml` to `stable` (>=1.60.0) and include components `rustfmt` and `clippy`.
   * Prefer `actions-rust-lang/setup-rust-toolchain@v1` with `cache: true` on CI.

2. **Dependencies & Vendoring**
   ```sh
   cargo generate-lockfile       # ensure Cargo.lock exists
   cargo vendor                  # vendor crates into `vendor/`
   ```
   * Add `.cargo/config.toml`:
     ```toml
     [net]
     offline = true

     [source.crates-io]
     replace-with = "vendored-sources"

     [source.vendored-sources]
     directory = "vendor"
     ```

3. **Python Scripts** (if any)
   ```sh
   pip download -r requirements.txt -d wheelhouse/
   pip install --no-index --find-links=wheelhouse/ -r requirements.txt
   ```

## Code Generation Guidelines

* **Formatting**: Run `cargo fmt` or `cargo +stable fmt -- --check`.
* **Linting**: Run `cargo clippy -- -D warnings`.
* **Testing**: Run `cargo test --offline`.

## Common Tasks

* **Add New Feature**: Write tests first (unit, proptest), implement, then run tests.
* **Refactor**: Ensure `cargo fmt`, `cargo clippy`, and `cargo test` pass.
* **Documentation**: Update `README.md` and doc-comments; run `cargo doc --no-deps`.

## Security Practices

* **Zeroization**: Wrap secrets in `secrecy::Secret` and use `Zeroize` on ephemeral buffers.
* **AEAD**: Authenticate headers & ciphertext with Poly1305; verify before decryption.
* **KDF Hardening**: Expose and bound Argon2 `mem_cost`, `time_cost`, `parallelism`.

## Workflow Automation

* **Pre-Commit Hooks**: Enforce fmt, clippy, tests.
* **CI Jobs**: Cache crates registry, git metadata, and security-tool binaries.
