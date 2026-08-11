# Changelog

## 0.54.0 - Unreleased

This is an intentionally breaking security release. The crate version now
matches the repository tag series. Version 0.53.0 was never published: its
release validation exposed missing committed AFL seed corpora, which are fixed
here before the first CPV2/EDEKV2 release.

- Update SHA-2, Poly1305, Ed25519, Criterion, AFL, CodeQL, checkout, and GitHub
  Pages dependencies while preserving the v2 golden formats and signatures.
- Commit canonical AFL seed corpora and keep the AFL crate and installed driver
  on version 0.18.2 so the locked release smoke test can run.
- Replace CPV1 with the bounded, record-authenticated CPV2 streaming format.
- Replace EDEKV1 and multi-file key generation with one encrypted EDEKV2 key
  bundle plus explicit public-key export.
- Remove all public raw ChaCha20, caller-managed nonce/counter, raw KDF,
  memory-locking, constant-time-file-read, and detached-signature helpers.
- Fix plaintext publication before final authentication.
- Fix private-key symlink following, overwrite, and permission-at-creation
  failures through atomic no-clobber publication.
- Fix attacker-controlled Argon2 work and unchecked MiB conversion by using a
  fixed authenticated RFC 9106 profile.
- Bound memory to a 1 MiB record plus the fixed 64 MiB Argon2 working set.
- Add Ed25519ph streaming signatures with mandatory verification policy.
- Add RFC vectors, independent differential tests, parser properties, tamper,
  finality, downgrade, filesystem, permissions, and CLI regressions.
- Replace the inaccurate fuzz setup with two locked AFL parser/state targets.
- Harden CI and releases with exact toolchains, pinned actions, minimal job
  permissions, locked validation, dependency inventories, checksums, and Linux
  plus unsigned macOS archives published automatically after a version-bumping
  merge to `main`.
- State the experimental, unaudited, not-for-important-data assurance level
  prominently and remove inaccurate constant-time, Prusti, and release claims.

### Compatibility

- CPV1 and EDEKV1 are not readable.
- The previous Rust public API and CLI KDF/hash flags are removed.
- CPV2 and EDEKV2 become immutable once v0.54.0 is published; future semantic
  cryptographic changes require new authenticated format versions.
