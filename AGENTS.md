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

## Security Tooling

To catch vulnerabilities, enforce policy, and audit shipping binaries, ensure the following tools are installed and integrated into your setup:

1. **Vulnerability Scanning with cargo-audit**

   * **Install**: Add to setup script or CI init:

     ```sh
     rustup component add clippy
     cargo install --version ^0.17 cargo-audit
     ```
   * **Usage**: Run `"cargo audit --locked"` after vendoring/lockfile generation.
   * **CI**: Fail the build on any advisories:

     ```sh
     cargo audit --locked --deny warnings
     ```

2. **Policy Enforcement with cargo-deny**

   * **Install**:

     ```sh
     cargo install --version ^0.11 cargo-deny
     ```
   * **Configuration**: Create a `deny.toml` in the repo root to ban unwanted licenses, multiple versions, or Git dependencies:

     ```toml
     [sources.crates-io]

     [[licenses.ban]]
     name = "GPL-3.0"

     [advisories]
     deny-warnings = true
     ```
   * **Usage**: Run `"cargo deny check"` (or specific checks like `cargo deny check licenses`).

3. **Binary Auditing via cargo-auditable**

   * **Install**: The crate is published as `auditable`, so install without the `cargo-` prefix and pin to the `auditable` crate name:

     ```sh
     # Ensure the local registry is up-to-date (if not offline)
     cargo update -p auditable
     # Install the binary from the auditable crate
     cargo install auditable --version ^0.2
     ```
   * **Embed metadata**: Add a build script (`build.rs`) or CI step to run:

     ```sh
     cargo auditable generate --output src/built_info.rs
     ```

     and include it in your binary to expose dependency PKGs and versions.
   * **Runtime check**: In production or CI, run:

     ```sh
     cargo audit --json <binary_path>
     ```
   * **Embed metadata**: Add a build script (`build.rs`) or CI step to run:

     ```sh
     cargo auditable generate --output src/built_info.rs
     ```

     and include it in your binary to expose dependency PKGs and versions.
   * **Runtime check**: In production or CI, run:

     ```sh
     cargo audit --json <binary_path>
     ```

*End of AGENTS.md*

