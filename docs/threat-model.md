# Threat Model: CPV2 and EDEKV2

## Status

This threat model describes the v0.54.0 design. The project remains an
experimental custom cryptography implementation which has not been
independently audited and is not suitable for important data.

## v0.54.0 dependency and release delta

This release updates the reviewed inputs used to build, test, fuzz, analyze,
document, and publish the existing CPV2/EDEKV2 implementation. It does not
change the authenticated formats, algorithms, KDF profile, nonce allocation,
record limits, signature domain, password rules, file-publication contract, or
public error policy.

- **Assets and attackers:** passwords, keys, plaintext, authenticated format
  semantics, and release evidence remain the protected assets. The relevant
  attackers are a compromised crate or GitHub Action publisher, a malicious
  dependency update, an untrusted pull request, and attacker-controlled files
  exercising changed library internals.
- **Entry points and misuse cases:** new crate source, build scripts, procedural
  macros, action bundles, the AFL toolchain, and the release workflow are the
  changed entry points. Full action commit pins prevent mutable-tag selection;
  locked Cargo graphs, source/license policy, fresh RustSec audits, independent
  vectors, golden fixtures, and release-mode tests detect incompatible or
  unreviewed changes. Pull-request jobs retain no release authority.
- **Invariants and controls:** upgrades of SHA-2, Poly1305, and Ed25519 preserve
  the exact CPV2/EDEKV2 bytes and verification behavior. Poly1305 tags remain
  full-length and are compared before plaintext release. Ed25519ph remains
  strictly domain-separated. AFL's crate, installed driver, real targets, and
  committed nonempty seed corpora use one reviewed version so locked builds and
  release smoke tests cannot silently select different instrumentation.
- **Unchanged attack classes:** resource-exhaustion bounds, nonce uniqueness and
  counter overflow checks, downgrade rejection, symlink/path-race defenses,
  crash-residue handling, timing limitations, and ciphertext/signature tamper
  handling are unchanged and continue to be exercised by the existing tests.
- **Residual risk and validation:** upstream source and transitive dependencies
  are not independently audited here, GitHub-hosted runners and the maintainer
  account remain trusted, and passing checks cannot prove absence of supply-chain
  or side-channel defects. Validation includes RFC and differential vectors,
  golden fixtures, tamper and filesystem regressions, parser properties, both
  locked dependency-policy graphs, workflow lint, both real AFL targets, and the
  complete release-mode matrix.

## Assets

- File and signing-key passwords.
- Argon2-derived keys and ChaCha20/Poly1305 intermediate material.
- Plaintext file contents and provisional authenticated plaintext.
- Ed25519 private seeds and signing state.
- Integrity and authenticity of CPV2 ciphertext, authenticated metadata,
  record order/finality, and optional signatures.
- Integrity of EDEKV2 public/private key association.
- Input preservation and non-overwrite/durability of output paths.
- Integrity of dependency, CI, build, SBOM, checksum, and release evidence.

## Attackers and entry points

In scope:

- An attacker supplying arbitrary CPV2, EDEKV2, or public-key bytes.
- An attacker controlling encoded lengths, flags, reserved bytes, algorithms,
  KDF fields, records, tags, signatures, truncation, extension, reordering,
  duplication, and splicing.
- An attacker pre-creating the requested output as a file, directory, or
  symlink, or racing names inside the destination directory without control of
  the process account.
- Interrupted, short, or failed reads/writes, flushes, synchronization,
  publication, and cleanup.
- A malicious pull request attempting to obtain write tokens, release
  authority, OIDC credentials, trusted caches, or publishable artifacts.
- A compromised or vulnerable dependency, action, scanner, advisory database,
  toolchain, or container input.

Out of scope:

- A compromised kernel, hypervisor, firmware, hardware, or random source.
- An attacker controlling the same user account, process memory, debugger,
  swap, crash dump, or destination-directory permissions.
- Physical and microarchitectural attacks.
- Recovery of secrets from compiler-created copies or registers after
  zeroization.
- Hiding plaintext length, ciphertext length, paths, timestamps, access
  patterns, salts, nonces, or the presence of a signature.

## Trust boundaries and controls

### Untrusted bytes to KDF

The 64-byte CPV2 and 96-byte EDEKV2 headers are parsed canonically before
Argon2. Magic, version, flags, algorithms, reserved bytes, fixed KDF profile,
record size, declared lengths, checked encoded size, and file metadata must
match exactly. The only accepted KDF is Argon2id v19 with 64 MiB, three passes,
four lanes, and a 32-byte output. Invalid input cannot select more work.

### Derived key to records

A fresh 16-byte salt derives one key for one envelope. CPV2 uses a fresh
8-byte prefix plus a checked little-endian `u32` record index as the RFC 8439
nonce. At most `2^32` records are permitted. Each record authenticates the
complete file header and its exact index, length, and final flag. Non-final
records are exactly 1 MiB and exactly one final record is required.

Counter zero derives the Poly1305 one-time key; payload blocks begin at one.
The record-size bound prevents payload counter exhaustion. The full 128-bit tag
is compared before decrypting the record. Authentication failure zeroizes the
record buffer and releases no plaintext.

### Authenticated records to filesystem

Decryption creates no output until the first record authenticates. Later
authenticated plaintext is written to a random mode-0600 sibling temporary
file. The final name appears only after all records, exact EOF, and any required
Ed25519ph signature pass. Publication uses a pinned directory descriptor,
same-directory hard link, file and directory synchronization, and no-overwrite
semantics. RAII removes temporary paths on prepublication failure.

A process crash may leave a randomly named mode-0600 temporary file containing
only individually AEAD-authenticated plaintext records. Deletion is cleanup,
not secure erasure. A post-publication cleanup or sync problem is reported
explicitly rather than treating the operation as an ordinary prepublication
failure.

### Signing keys

Key generation produces one encrypted EDEKV2 bundle rather than attempting to
publish two filenames transactionally. Its public key is authenticated as AAD
with the encrypted private seed. Loading verifies the tag and then confirms the
decrypted seed reconstructs the authenticated public key. Public-key export
does not authenticate the source independently; users must distribute and
verify public-key fingerprints through an appropriate trusted channel.

### CI and release authority

Pull-request jobs have read-only or empty token permissions and no secrets or
OIDC. A merge to `main` runs the locked release checks when the Cargo version
does not yet have a corresponding tag. Platform build jobs have read-only
repository access. The final publication job has only `contents: write`, does
not check out repository code, and uploads the exact archives produced by the
build jobs, the generated dependency inventory, and freshly verified checksums.
This is deliberately operable by a sole maintainer and does not claim
independent release approval or protection from compromise of the maintainer's
GitHub account.

The release AFL smoke sets `AFL_DEBUG_CHILD=1` to preserve target-process
diagnostics when the AFL++ forkserver cannot start a child. This is a
diagnostic-only control: it does not disable the forkserver, change corpus
inputs, grant permissions, or alter artifact publication. Child output is
attacker-influenced and must be treated as untrusted CI log data; the current
targets do not receive passwords, keys, plaintext, or release credentials.
There is no security-model change to the encrypted formats or release
authority. Validation is a release-workflow rerun with inspection of the
resulting child diagnostics.

## Misuse cases and fail-closed behavior

- CPV1/EDEKV1, unknown versions/algorithms, noncanonical KDF profiles, unknown
  flags, and nonzero reserved bytes are rejected without fallback.
- Empty or more-than-1024-byte passwords are rejected. UTF-8 is not normalized
  or trimmed.
- Signed files require a verification key; unsigned files reject one.
- Existing outputs and symlinks are never replaced.
- RNG failure, KDF failure, authentication failure, signature failure, changing
  input length, short I/O, and publication failure never weaken algorithms,
  reuse a nonce, or publish partial output.
- Wrong passwords, wrong keys, changed tags, and signature failures share the
  public authentication-failure class after secret work begins.

## Validation

- RFC 8439 block and AEAD vectors.
- Differential ciphertext/tag tests against RustCrypto ChaCha20Poly1305.
- Header/record property tests and AFL parser/state targets.
- All-field tamper, truncation, extension, ordering, finality, downgrade,
  wrong-password/key, and signature regressions.
- Symlink/no-overwrite, permissions-at-creation, cleanup, and atomic-publication
  tests.
- Locked dependency audit/deny checks over the root and fuzz graphs.
- Exact-toolchain CI, release-mode tests, Miri/sanitizer jobs, a weekly
  dependency-intelligence artifact, release AFL smoke, platform build jobs, a
  CycloneDX dependency inventory, and checksums.

Timing observations on shared hardware are regression signals only. They do not
prove constant-time behavior. External cryptographic implementation review
would increase assurance, but is not a release prerequisite for this personal
experiment and would not by itself constitute an independent product audit.
