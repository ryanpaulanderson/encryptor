# CPV2 and EDEKV2 Format Specification

All multi-byte integers are little-endian. Parsers reject unknown flags,
algorithms, nonzero reserved bytes, noncanonical values, truncation, extension,
and trailing data. Released v2 semantics are immutable.

## CPV2 file header

The header is exactly 64 bytes.

| Offset | Length | Meaning |
| --- | ---: | --- |
| 0 | 4 | ASCII `CPV2` |
| 4 | 1 | Format version `2` |
| 5 | 1 | Flags: bit 0 signed; all others zero |
| 6 | 1 | AEAD identifier `1`: custom RFC 8439 composition |
| 7 | 1 | KDF identifier `1`: Argon2id |
| 8 | 1 | Argon2 version `0x13` |
| 9 | 1 | Derived-key length `32` |
| 10 | 2 | Zero |
| 12 | 4 | Memory `65536` KiB |
| 16 | 4 | Time cost `3` |
| 20 | 4 | Parallelism `4` |
| 24 | 4 | Record size `1048576` |
| 28 | 8 | Total plaintext length |
| 36 | 16 | Random salt |
| 52 | 8 | Random record-nonce prefix |
| 60 | 4 | Zero |

The maximum plaintext length is `2^52` bytes. Record count is
`max(1, ceil(plaintext_length / 1048576))` and must not exceed `2^32`.

## CPV2 records

Each record is a 12-byte header, ciphertext, and 16-byte tag.

| Record offset | Length | Meaning |
| --- | ---: | --- |
| 0 | 4 | Sequential record index beginning at zero |
| 4 | 4 | Plaintext/ciphertext length |
| 8 | 1 | Flags: bit 0 final; all others zero |
| 9 | 3 | Zero |
| 12 | variable | Ciphertext |
| after ciphertext | 16 | Complete Poly1305 tag |

Non-final records are exactly 1 MiB. The final record contains between zero
and 1 MiB. Empty input has one zero-length final record. There is exactly one
final record and it is last. The sum of record lengths equals the header's
plaintext length.

The 96-bit nonce is:

```text
header nonce prefix (8 bytes) || record index (u32 little-endian)
```

Associated data is:

```text
"encryptor/cpv2/record/v1" || complete CPV2 header || record header
```

RFC 8439 counter zero derives the Poly1305 one-time key. Payload encryption
starts at counter one. The full 128-bit tag is verified before decryption.

The exact unsigned encoded length is:

```text
64 + plaintext_length + record_count * (12 + 16)
```

## CPV2 signature trailer

Signed files add exactly 72 bytes after the final record:

| Offset | Length | Meaning |
| --- | ---: | --- |
| 0 | 4 | ASCII `SIG2` |
| 4 | 1 | Algorithm `1`: Ed25519ph with SHA-512 |
| 5 | 3 | Zero |
| 8 | 64 | Signature |

The SHA-512 prehash transcript is:

```text
"encryptor/cpv2/signature/v1"
|| complete CPV2 header
|| every complete encoded record in order
|| SIG2 trailer prefix (first 8 bytes)
```

The Ed25519ph context is `encryptor/cpv2/signature`. Signed inputs require a
verification key and are not published before strict verification succeeds.

## EDEKV2 key bundle

An EDEKV2 bundle is exactly 144 bytes: a 96-byte header, 32-byte encrypted
Ed25519 seed, and 16-byte tag.

| Offset | Length | Meaning |
| --- | ---: | --- |
| 0 | 6 | ASCII `EDEKV2` |
| 6 | 1 | Format version `2` |
| 7 | 1 | Flags `0` |
| 8 | 1 | AEAD identifier `1` |
| 9 | 1 | KDF identifier `1` |
| 10 | 1 | Argon2 version `0x13` |
| 11 | 1 | Derived-key length `32` |
| 12 | 4 | Memory `65536` KiB |
| 16 | 4 | Time cost `3` |
| 20 | 4 | Parallelism `4` |
| 24 | 16 | Random salt |
| 40 | 12 | Random RFC 8439 nonce |
| 52 | 32 | Ed25519 public key |
| 84 | 12 | Zero |
| 96 | 32 | Encrypted Ed25519 seed |
| 128 | 16 | Complete Poly1305 tag |

Associated data is `"encryptor/edekv2/key/v1" || complete EDEKV2 header`.
After authentication and decryption, the implementation reconstructs the
Ed25519 public key from the seed and compares it with the authenticated header.

## Compatibility

CPV1 and EDEKV1 are deliberately unsupported. Readers never negotiate,
downgrade, reinterpret v2 bytes, or accept extension data. A future semantic or
cryptographic change requires CPV3 or EDEKV3 and separate golden fixtures.
