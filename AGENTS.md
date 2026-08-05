# AGENTS.md

## Scope and intent

This file applies to the entire repository. A nested `AGENTS.md` or
`AGENTS.override.md` may add subtree-specific rules but may not weaken the
security, correctness, or completion requirements here.

This repository handles passwords, keys, plaintext, ciphertext, signatures,
and attacker-controlled files. Treat every code path as security-sensitive.
The README and crate docs describe this repository as experimental and not for
production use. It contains hand-written cryptographic composition, and no
independent audit evidence is recorded here. Preserve that honest assurance
level until the implementation, format, operations, and release process receive
appropriate independent review. High-quality changes do not alone justify
claiming the whole product is audited or production-safe.

The words **must**, **must not**, **required**, **should**, and **should not**
are deliberate. If a task cannot satisfy a **must**, report the exact blocker;
never silently lower the bar.

## Production-complete delivery contract

Every accepted change must be a finished, production-grade vertical slice
within its stated scope and the repository's current assurance level. Do not
deliver an MVP, proof of concept, prototype, scaffold, demo-only path, or
intentionally partial implementation. Completeness makes a change merge-ready;
it does not upgrade the whole product's audit or production-safety status.

A change is complete only when its affected behavior and artifacts satisfy the
following, as applicable:

- Acceptance criteria and externally visible behavior are fully implemented.
- Valid, invalid, boundary, adversarial, failure, cleanup, and recovery paths
  behave deliberately and have bounded resource use.
- Security invariants and secure defaults are implemented, not deferred.
- Public API, CLI, encrypted-format, platform, and operational compatibility are
  preserved or have an explicit, versioned, tested migration.
- Tests provide strong evidence for important behavior and reproduce every fixed
  defect. Security-critical claims also need review and, where appropriate,
  independent vectors or differential validation.
- User, API, security, and operational documentation matches reality.
- Required checks pass on the final diff with no new warnings.
- Superseded code, dependencies, flags, and temporary compatibility paths are
  removed.
- There are no new or in-scope `TODO`, `FIXME`, `todo!`, `unimplemented!`,
  placeholders, disabled checks, unexplained ignored tests, insecure fallbacks,
  or promises to finish correctness/security later. Report unrelated pre-existing
  instances without expanding scope unless they block safe completion.

If the original scope is too large, implement a smaller end-to-end capability
only if it independently satisfies the user’s need and every rule above. Do not
hide incomplete work behind a feature flag. Do not turn a narrow task into an
unrelated rewrite: production-grade means complete, not maximum, scope.

## Engineering priorities and design

When requirements compete, prioritize: (1) confidentiality, integrity, memory
safety, and correctness; (2) fail-closed behavior, durability, and compatibility;
(3) simplicity and auditability; (4) measured performance and bounded resources;
(5) delivery speed.

“Least amount of code” means the smallest clear implementation and dependency
surface that completely enforces the required invariants. It does not mean code
golf, duplicated shortcuts, omitted validation, or custom cryptography used to
avoid a dependency.

- Prefer the standard library and existing reviewed abstractions when they meet
  the requirement. Prefer mature, reviewed cryptographic libraries over bespoke
  code even when they add a dependency.
- Keep one source of truth. Separate parsing/validation, cryptographic policy,
  file publication, and CLI presentation behind narrow boundaries. The library
  must not print, prompt, exit, or own process-global presentation policy.
- Keep items private or `pub(crate)` unless downstream users need them. Every
  public item, feature, re-export, trait implementation, and dependency type in
  a signature is a compatibility commitment.
- Encode invariants with enums, newtypes, private fields, and checked constructors.
  Avoid boolean modes, primitive-heavy signatures, and caller-enforced security.
- Add a trait, generic, builder, macro, feature flag, registry, or layer only for
  a present requirement or demonstrated reduction in duplicated policy. Do not
  build speculative extension points.
- Use explicit capabilities and authenticated format versions for extensibility;
  never use permissive parsing, silent negotiation, or downgrade fallback.
- Prefer small pure functions and composition. Remove meaningful duplication
  when one invariant is otherwise enforced in multiple places, but do not couple
  unrelated concepts merely to be “DRY.”
- Optimize for readability and auditability rather than raw line count.

## Repository realities

- `src/lib.rs` contains the library, Argon2id derivation, hand-written
  ChaCha20/Poly1305 composition, key-file support, signing, and memory locking.
  `src/main.rs` owns CLI and file workflows; `src/error.rs` owns current errors.
- `tests/` includes RFC vectors, integration/tamper, property, compile-fail,
  signing, key-generation, and timing tests. `benches/` uses Criterion.
- `fuzz/` is a separate package with a nightly toolchain file and an AFL target.
  Its docs also mention libFuzzer; inspect the manifest and real targets before
  claiming a fuzzing path works.
- `.github/workflows/` is production code. `README.md`, `CHANGELOG.md`, and
  `SECURITY.md` are part of applicable deliverables.
- The crate uses edition 2021. `rust-toolchain.toml` follows moving `stable` and
  includes `rustfmt` and `clippy`. No MSRV is declared; do not claim one.
- `Cargo.lock` is format 4 and requires Cargo 1.78 or newer to consume. Never
  hand-edit it. Change format only in an explicit toolchain/MSRV migration,
  generate it with the selected Cargo, and validate the resulting locked graph.
- Repository tags currently reach `v0.51.0` while `Cargo.toml` says `0.1.0`.
  Do not infer or auto-increment versions from this mismatch; reconcile crate,
  CLI, format, and release versions deliberately in release/versioning work.
- No `vendor/` or `.cargo/config.toml` is tracked. Offline checks work only when
  exact locked crates/index data are locally available.
- `setup.sh` and `build.sh` are networked, unpinned, lockfile-regenerating setup
  tools that vendor dependencies and create Cargo configuration. They are not
  approved release paths until hardened. Run them only when the task explicitly
  needs that workflow and review every generated change.
- The current `.github/workflows/release.yml` publishes from `main` with broad
  write authority, mutable action/toolchain references, online unlocked builds,
  and no complete signing/provenance/SBOM chain. It is not an approved
  production-release path and must not publish until it satisfies this file's
  release contract.

## Required workflow

1. **Baseline:** Read relevant code, tests, public docs, format description, and
   recent history. Inspect `git status` and preserve unrelated/user changes. Run
   a narrow relevant check before editing when practical and record pre-existing
   failures.
2. **Design:** Identify inputs, outputs, invariants, trust boundaries, validation
   ownership, failures, cleanup, resource limits, compatibility, and the smallest
   cohesive solution. Define the tests and docs that provide evidence of
   completeness.
3. **Implement:** Add a failing regression test first for defects when feasible.
   Make the safe path the easiest path, keep the diff focused, fix newly exposed
   in-scope security/correctness defects, and delete replaced code.
4. **Verify:** Run applicable final-diff gates. Inspect for secret leakage, panic
   paths, unchecked arithmetic, partial cleanup, format drift, dependency churn,
   and unrelated edits. Run `git diff --check`. Report exact checks and gaps; do
   not claim completion while an in-scope gate is red.

Before a change that alters a security invariant, trust boundary, untrusted-input
path, crypto/format behavior, secret lifecycle, file-publication guarantee,
dependency trust decision, privileged CI path, or release authority, write a
proportionate threat-model delta. If one of these areas is touched without a
security-model change, record “no security-model change” and why. Cover assets,
attackers, entry points, misuse cases, invariants, controls, residual risk, and
validating tests, including resource exhaustion, nonce reuse, downgrade,
filesystem races, crash residue, timing, dependency compromise, and tampering.

## Rust engineering standards

### Toolchain, manifests, and compatibility

- Preserve edition 2021 unless an explicit migration is requested. Before any
  release, install an exact reviewed stable Rust release and record it in build
  metadata; use moving `stable` only in a compatibility-canary job. Pin unavoidable
  nightly toolchains by date. Treat toolchain changes as compatibility and
  supply-chain changes.
- Treat edition, development toolchain, and MSRV separately. If adopting an
  MSRV, declare `[package].rust-version`, test every target and locked dependency
  on it in CI, and document the support policy.
- Commit `Cargo.lock` for this release-producing package and use `--locked` in CI
  and release commands. Make targeted dependency updates and avoid unrelated
  lockfile churn.
- Use `--offline`/`--frozen` only with a prepared cache or tracked verified
  vendor configuration. `--frozen` means locked plus offline; it does not fetch
  missing sources.
- Apply Cargo SemVer guidance to public changes. Version ciphertext/key formats
  independently from the crate and protect compatibility with golden fixtures.

### APIs, errors, and arithmetic

- Validate attacker-controlled values before slicing, allocation, parallel work,
  I/O, or expensive KDF work. Make invalid states unrepresentable where practical.
- Give public structs private fields and the smallest checked constructor/accessor
  API. Consider `#[non_exhaustive]` for types intended to grow and seal traits not
  intended for downstream implementation.
- Prefer standard traits (`TryFrom`, `From`, `AsRef`, `Read`, `Write`, iterators)
  when they improve interoperability without obscuring invariants. Expose a
  dependency type publicly only as a deliberate SemVer commitment.
- Do not derive `Debug`, `Display`, `Clone`, `Copy`, serialization, or equality
  for secret-bearing types unless the security effect is deliberate. Raw secret
  output is forbidden; redacted `Debug` is acceptable.
- Return typed `Result` errors for malformed input, entropy/resource failure,
  I/O, authentication failure, and every caller-recoverable condition.
- Production library paths must not use `unwrap`, `expect`, `panic!`,
  `unreachable!`, or potentially panicking indexing for attacker/environmental
  input. Validate first or use checked parsing/`get`. An invariant-only `expect`
  needs a precise local proof.
- Library errors do not print or change global verbosity. Preserve useful error
  sources internally when safe; redact secrets and oracle-forming detail at the
  CLI boundary.
- Use checked arithmetic and fallible conversions for lengths, offsets, counters,
  MiB/KiB conversion, capacities, and platform-sized values. Cryptographic
  counters must never wrap.
- Never recover by weakening an algorithm/KDF, reusing a nonce, accepting a
  permissive format, using insecure permissions, or emitting partial output.

### Unsafe Rust, platforms, documentation, and performance

- Safe Rust is the default. New unsafe code needs a demonstrated necessity,
  focused review, and targeted tests; assumed speed is not a reason.
- Isolate unavoidable unsafe/FFI in the smallest private module. A change touching
  such a module must leave it passing source-level
  `#![deny(unsafe_op_in_unsafe_fn)]` and
  `#![deny(clippy::undocumented_unsafe_blocks)]`. Put a `// SAFETY:` proof before
  each minimal block, covering applicable pointer, length, alignment, aliasing,
  lifetime, initialization, concurrency, unwind, and platform obligations.
  Public unsafe APIs need an exact `# Safety` contract.
- Prefer safe slice operations over pointer arithmetic. Do not use
  `#[inline(always)]` without measurement.
- Platform security behavior must be explicit and tested. A no-op reporting
  success is not a security control. Use typed unsupported errors where needed.
  Use RAII for locked memory, temporary files, and other cleanup-sensitive state.
- Document every public item. Where applicable, cover invariants, `# Errors`,
  reachable `# Panics`, `# Safety`, and platform behavior. Give public workflows
  and non-obvious APIs runnable doctests; do not add examples that teach nothing.
  Keep README, CLI help, format docs, changelog, and errors synchronized. Never
  overstate constant-time, zeroization, audit, compliance, or production claims.
- Optimize only for a stated requirement using representative release-mode
  measurements. Concurrency must be bounded, deterministic, panic-safe, and
  worth its overhead. Shared-runner benchmark deltas are investigation signals.

## Cryptographic rules

- Do not invent or casually modify primitives, modes, compositions, key
  schedules, padding, signatures, or formats. Prefer a maintained, reviewed,
  standards-conformant high-level AEAD implementation.
- Treat the hand-written ChaCha20/Poly1305 path as high-risk compatibility code,
  not a template. Changes require RFC 8439 known-answer and negative vectors,
  differential tests against an independent implementation, side-channel review,
  and review by someone qualified in cryptographic implementation.
- The public `encrypt_decrypt*` helpers are unauthenticated stream-cipher
  operations. Do not use them as a production encryption API or add similar
  footguns. Migrate compatibly toward an AEAD API that cannot release
  unauthenticated plaintext.
- Use the complete 128-bit Poly1305 tag and constant-time verification. Never
  truncate it. Authenticate ciphertext plus all security-relevant metadata:
  magic/version, algorithm/KDF identifiers and parameters, lengths, flags,
  chunk order, and finality.
- Bind signatures to an unambiguous domain, format version, algorithm, and
  canonical byte representation. Use strict verification. A signature does not
  replace AEAD authentication.
- Document whether each derived key is single-use or reused. In the password
  format, a fresh random salt derives a key used for exactly one envelope and the
  nonce also comes from the OS CSPRNG. A key reused across messages or records
  needs a collision-free, overflow-checked nonce allocation or reviewed STREAM
  construction; a different construction requires a new authenticated version.
- In the existing RFC 8439 compatibility path, counter 0 derives the Poly1305
  one-time key and payload blocks use `1..=u32::MAX`, limiting one invocation to
  `(2^32 - 1) * 64 = 274,877,906,880` bytes. New code uses a high-level AEAD and
  does not manage this internal counter. Record limits belong to the selected
  reviewed streaming construction.
- Generate keys, salts, permitted-random nonces, and unpredictable values only
  from the OS CSPRNG. Propagate RNG failure; never unwrap or use a weak fallback.
- Keep authoritative RFC 8439 block and AEAD vectors. Round trips alone are
  insufficient because matching defects can cancel out.

### Password KDF

- Use Argon2id version 19 (`0x13`), a fresh 16-byte OS-CSPRNG salt, and a
  32-byte derived key.
  RFC 9106 profiles are 2 GiB/`t=1`/`p=4`, or for memory-constrained systems
  64 MiB/`t=3`/`p=4`. Choose and version a documented profile from measured
  deployment limits; never silently change parameters required by existing data.
- Writers enforce the current minimum-security profile and hard maximums. Readers
  validate RFC 9106 constraints (`p >= 1`, `t >= 1`, `m >= 8 * p` KiB) plus hard
  resource maximums before Argon2. A versioned reader may accept explicitly
  supported legacy profiles below current writer minimums but never emit them.
- Include exact canonical KDF algorithm, version, parameters, output length, and
  salt bytes in AEAD associated data. Authentication completes only after the
  bounded KDF. Reject unknown, noncanonical, and downgraded combinations.
- When one application master key feeds independent purposes, derive labeled
  subkeys with a standard construction such as HKDF. Do not alter key derivation
  internal to a standardized AEAD, including RFC 8439’s Poly1305 one-time key.
- Define password bytes exactly (currently UTF-8 as entered), with no implicit
  trimming or normalization. Never accept passwords in process arguments, logs,
  or debug output.

### Secrets and side channels

- Own passwords, keys, and sensitive intermediates in `secrecy`/`zeroize` types
  that redact output and zeroize on drop. Expose only inside the crypto boundary,
  for the shortest practical scope and minimum accesses; never clone merely to
  satisfy an exposure-count rule.
- Use zeroize-on-drop RAII for passwords, derived keys, private-key seeds, and
  owned secret intermediates. Zeroize owned provisional plaintext on failed
  authentication, and design APIs to avoid creating such plaintext.
- State zeroization limits honestly: it cannot prove removal of compiler copies,
  registers, swap, crash dumps, microarchitectural leakage, or physical traces.
- Prefer AEAD, MAC, and signature libraries’ verification APIs. Use reviewed
  constant-time primitives such as `subtle` only for comparisons/selections not
  covered by those APIs; never implement tag or signature verification manually.
  Avoid secret-dependent branches, tables, memory access, loop counts, and errors.
- Collapse wrong-password, wrong-key, and tag failures into one public
  authentication failure after secret work begins. Distinguish structural errors
  only when they cannot create a useful oracle.
- Timing checks use optimized artifacts and supported hardware and are regression
  evidence, never proof. File I/O and full CLI execution are not constant-time.
- Never log passwords, keys, derived material, plaintext, secret buffers, or
  command/environment values containing them. Treat paths, sizes, salts, nonces,
  ciphertext, and identifiers as potentially sensitive metadata.

## Formats, parsing, and file safety

- Treat every byte, length, flag, version, path, CLI value, and serialized KDF
  field as attacker-controlled.
- Parse in phases: minimum size; magic/version/flags/reserved bytes and bounded
  integers; checked offsets and resource limits; then allocation/crypto. Reject
  malformed, ambiguous, duplicate, truncated, overflowing, unsupported,
  noncanonical, and unexpected trailing data unless a safe extension is defined.
- Released format versions are immutable. Never reinterpret bytes or silently
  change decryption defaults. Use a new version for semantic/cryptographic change,
  add golden fixtures, preserve intentional read compatibility, and migrate data.
- Never write unverified plaintext, including to a temporary file. A safe
  whole-message AEAD API returns plaintext only after authentication. A record
  format authenticates each record before writing it to a mode-`0600` temporary
  file, then publishes atomically only after an authenticated final record,
  complete structure validation, and required signature verification. Remove
  temporary files on failure; never claim secure erasure by deletion/overwriting.
- Streaming formats must authenticate each chunk, index/order, finality, and
  total structure so truncation, duplication, reordering, and splicing fail.
  Carrying a stream-cipher counter between chunks is not streaming AEAD.
- Preserve input. Create output/key files without overwrite by default and with
  restrictive permissions at creation, not by later chmod. Address symlink/path
  races as the threat model requires. Handle short I/O, flush, sync, close,
  rename, interruption, and cleanup failures.
- Use same-filesystem atomic publication where promised and sync the file/parent
  directory when the durability contract requires it.
- Bound file size, KDF work, allocation, vector/signature-transcript growth, and
  parallelism before resource consumption. Streaming code must use bounded memory.
- Treat unkeyed SHA-256 as a corruption checksum, never as authenticity or a
  substitute for AEAD/signature verification; CLI names and docs must say so.

## Dependencies and supply chain

- Add a dependency only when its concrete security, correctness, interoperability,
  or maintenance benefit outweighs its attack surface and lifecycle cost. Review
  provenance, maintenance/advisories, unsafe code, build scripts/proc macros,
  enabled features, transitive/duplicate graph, source, MSRV, and license. Do not
  reimplement security code merely to reduce dependency count.
- Prefer registry releases. Pin Git dependencies to a reviewed immutable full
  revision; never track a branch or introduce an unapproved registry/source.
- Treat manifests, both lockfiles, vendored code, toolchains, workflows, and
  release tooling as security-sensitive review surfaces.
- If vendoring is adopted, generate exact locked sources with Cargo, commit its
  source-replacement config, never hand-edit vendored crates, review updates as
  source changes, and verify a clean frozen build. Vendoring gives source
  availability and repeatable dependency inputs, not trust, freshness, a
  hermetic environment, or reproducible artifacts.

Maintain two separate lanes:

1. **Network-isolated locked build:** use the committed lockfile and, when
   tracked, verified vendor tree with `--locked --offline`/`--frozen`, without
   dependency resolution or network. This is hermetic only when the toolchain,
   linker, native inputs, runner image, environment, build scripts, and every
   other input are pinned and locally supplied. Call artifacts reproducible only
   after independent builds produce and compare identical digests.
2. **Fresh intelligence:** in a separate no-secrets job, on every dependency
   change, at least weekly, and immediately before release, refresh advisory and
   registry data and fail closed on network/scanner failure. Pin or verify each
   scanner and database input. Emit signed or attested evidence bound to the
   SHA-256 digests of both lockfiles, scanner version, advisory-database revision
   and time, registry refresh result, policy digest, and an expiry no later than
   seven days. The isolated builder/publisher rejects missing, expired, or
   digest-mismatched evidence.

- Audit both graphs explicitly with `cargo audit --file Cargo.lock --deny warnings`
  and `cargo audit --file fuzz/Cargo.lock --deny warnings` for dependency,
  security, and release work. Pin the scanner version; never trust a cached
  executable tool without verifying its digest.
- A reviewed, committed `deny.toml` (or an equally enforceable policy) covering
  advisories, allowed registries/Git sources, licenses, duplicate/banned crates,
  and documented exceptions is required before dependency or production-release
  work may pass. Apply it to both dependency graphs. Exceptions require
  applicability analysis, controls, an owner, a tracking issue, and a near-term
  expiry.
- Review lockfile changes with `cargo tree -e features` or equivalent inverse
  views; avoid broad update churn.

## CI, release, and vulnerability response

- Every workflow declares `permissions: {}` or the minimum read permissions;
  never rely on repository defaults. Grant elevated permissions only to the exact
  job. Build/test jobs receive no write token, release secret, or OIDC capability,
  and checkout uses `persist-credentials: false`. Pin every action—including
  GitHub-owned `actions/*`—and reusable workflow to a reviewed full commit SHA,
  with the release tag in a comment and an automated reviewed update path.
- Pass untrusted GitHub context as quoted environment data or typed input, never
  shell source. Untrusted PR code receives no secrets/write token and cannot
  create artifacts or caches later trusted by privileged jobs. Never execute an
  untrusted checkout through privileged `pull_request_target`/`workflow_run`.
- Run untrusted changes only on clean, ephemeral, isolated runners without a
  sensitive network path; persistent self-hosted runners must not process public
  or untrusted changes. Treat caches as performance hints, never trusted evidence
  or executable release inputs.
- Required checks trigger for every file capable of changing source,
  dependencies, vendoring, toolchains, build scripts, security policy, workflows,
  or release behavior; path filters must not bypass them. Validate workflows and
  shell with pinned `actionlint` and `shellcheck`.
- Protect workflows, cryptographic/format code, dependency policy, lockfiles, and
  release configuration with independent review and branch/tag protection.
- Release from a protected immutable tag/exact commit. Separate build and publish
  authority and publish the exact tested artifact—never rebuild between test,
  attestation/signing, and upload.
- Attester and publisher jobs must not execute repository code, build scripts,
  proc macros, or artifact-provided executables. Prefer short-lived OIDC identity
  over stored signing credentials. Before upload, verify artifact digests and the
  attestation's repository, workflow, ref, builder identity, and subject digest.
- A production release includes an exact toolchain and locked graph, release
  tests, reconciled version/changelog, platform signing/notarization where
  applicable, and per-artifact checksums plus an SPDX or CycloneDX SBOM covering
  transitive runtime/build materials. Bind the SBOM, signed provenance/artifact
  attestation, source commit, and checksums to each artifact digest; verify before
  publication, retain the evidence, and document consumer verification. Checksums
  detect corruption but do not authenticate artifacts. Claim a SLSA level only
  when retained evidence satisfies every requirement.
- Keep `SECURITY.md` current with supported versions, private reporting, response
  expectations, and coordinated disclosure. A vulnerability fix includes a
  regression, affected-version/attack-path analysis, root-cause fix, variant
  search, threat-model update, and prevention control; coordinate GHSA/CVE and
  RustSec publication when applicable.

## Verification matrix

Rust-affecting changes require this core gate on the final diff:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked
```

After exact sources are prepared, repeat locked checks with `--offline` or
`--frozen`. A missing-cache failure is not a code failure. A clean network-free
pass proves only that declared dependency sources were locally available; it
does not by itself prove hermeticity or artifact reproducibility.

Additional gates by risk:

- Crypto, parsing, unsafe, arithmetic, concurrency, or releases: release-mode
  tests plus targeted boundary, tamper, resource, and failure tests.
- Public/shared-library API: doctests, integration and compile-pass/fail coverage,
  SemVer review, and compilation of every in-repository consumer. For the fuzz
  consumer, build its real AFL target using the workflow-selected pinned toolchain.
- Persistent formats: authoritative vectors, golden files per version, all-field
  tamper, truncation/extension, wrong-key/password, and independent differential
  tests where possible.
- Dependencies/releases: fresh audits of both lockfiles, configured source/
  license/bans policy, release build, and artifact/evidence inspection.
- Unsafe code: targeted Miri where the exercised code/platform is supported plus
  the specific sanitizer selected by the threat model and supported by the pinned
  toolchain/target. Name the tool/target; unsupported execution is a gap, not pass.
- Parsers/state machines: property tests and bounded fuzz smoke tests against the
  real target in `fuzz/Cargo.toml`; every crash/timeout becomes a regression.
  Format/check/build that separate package explicitly with its pinned toolchain,
  `--manifest-path fuzz/Cargo.toml`, `--locked`, and feature `afl`; root workspace
  commands do not cover it.
- Performance: `cargo bench --bench encryptor_benchmarks --locked` before/after
  on a controlled host, with meaningful variance explained.
- Platform behavior: test every OS/architecture in the documented support matrix.
  If none exists, do not infer support from a compile or `cfg`; define intended
  scope or report release support as undefined.
- Docs-only: verify links, commands, examples, and consistency; run code gates
  when examples or commands are executable.

Tests cover success, invalid input, exact/one-past boundaries, partial I/O,
cleanup, and recovery—not only round trips. Use Proptest for parser/serializer,
round-trip, streaming, and chunk invariants, preserving minimized failures.
Timing tests must be release-mode, defensible, and non-flaky; they cannot prove
constant time.

At handoff, state the completed behavior; security/compatibility decisions;
changed APIs/formats and migration; exact checks/results; and any check not run.
Mention remaining risk only when pre-existing and out of scope—never call
unfinished in-scope work a follow-up.

## Authoritative references

Re-check these when changing crypto, KDF policy, Rust compatibility, dependencies,
CI, or releases; recommendations and tools evolve.

- [NIST SP 800-218 SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
- [Codex `AGENTS.md` guidance](https://learn.chatgpt.com/docs/agent-configuration/agents-md.md)
- [CISA Secure by Design](https://www.cisa.gov/sites/default/files/2023-10/Shifting-the-Balance-of-Cybersecurity-Risk-Principles-and-Approaches-for-Secure-by-Design-Software.pdf)
- [SLSA 1.2 Build Track](https://slsa.dev/spec/v1.2/build-track-basics)
- [RFC 8439: ChaCha20-Poly1305](https://www.rfc-editor.org/rfc/rfc8439)
- [RFC 5116: authenticated-encryption interface](https://www.rfc-editor.org/rfc/rfc5116)
- [RFC 9771: AEAD properties](https://www.rfc-editor.org/rfc/rfc9771)
- [RFC 9106: Argon2](https://www.rfc-editor.org/rfc/rfc9106)
- [RFC 8032: EdDSA](https://www.rfc-editor.org/rfc/rfc8032)
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/checklist.html)
- [Cargo `rust-version`](https://doc.rust-lang.org/stable/cargo/reference/rust-version.html)
- [Cargo SemVer guide](https://doc.rust-lang.org/stable/cargo/reference/semver.html)
- [Cargo locked/offline options](https://doc.rust-lang.org/cargo/commands/cargo-test.html#manifest-options)
- [Rust undefined-behavior reference](https://doc.rust-lang.org/stable/reference/behavior-considered-undefined.html)
- [Rust Fuzz Book](https://rust-fuzz.github.io/book/)
- [RustSec `cargo audit`](https://github.com/RustSec/rustsec/tree/main/cargo-audit)
- [`cargo-deny` checks](https://embarkstudios.github.io/cargo-deny/checks/)
- [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use)
- [RustCrypto `chacha20poly1305`](https://docs.rs/chacha20poly1305/latest/chacha20poly1305/)
- [RustCrypto `secrecy`](https://docs.rs/secrecy/latest/secrecy/),
  [`zeroize`](https://docs.rs/zeroize/latest/zeroize/), and
  [`subtle`](https://docs.rs/subtle/latest/subtle/)
