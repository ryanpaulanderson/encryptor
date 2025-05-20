# Changelog

## Unreleased
- Changed streaming functions to require `&Secret<[u8; 32]>` keys, unwrapping the secret once internally. This improves ergonomics and prevents accidental exposure.
