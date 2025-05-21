# Changelog

## Unreleased
- Enforce streaming API to take `&Secret<[u8; 32]>` keys and unwrap them once internally.
- Add RFC-8439 ChaCha20 block-function vector test.
- Private key generated with `--generate-keys` now uses `0o600` permissions and a
  warning is shown when loading a signing key that is too permissive.
