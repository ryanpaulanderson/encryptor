# Release Operations

This is a sole-maintainer hobby project. Releases keep the technical validation
that catches format, cryptographic, parser, dependency, and packaging mistakes,
without requiring organization-only controls such as a second approver,
protected environments, OIDC attestations, or manually administered tags.

The project remains an experimental custom cryptography implementation. A
successful release does not make it audited or suitable for important data.

## Release trigger and version

Every merge to `main` starts the release workflow. The workflow reads the exact
version from `Cargo.toml`:

- If `v<version>` already exists, the workflow exits without publishing.
- If that tag does not exist, the full release validation and platform builds
  run. Publication creates the tag at the merged commit and creates the GitHub
  release from the resulting archives.

For a release-worthy change, update `Cargo.toml` and summarize the release in
`CHANGELOG.md`; the CLI version comes from the Cargo package. The changelog may
retain an `Unreleased` heading because the merge date is not known in advance,
and its date is not a publication gate. Ordinary merges which do not change the
version do not create duplicate releases. The first reconciled release is
`v0.54.0`. The attempted v0.53.0 release did not publish because its release
validation correctly failed on missing committed AFL seed corpora.

## Validation and publication

The validation job uses Rust 1.97.1 and runs formatting, strict Clippy, debug
and release tests, documentation warnings, an offline test after cache
preparation, both real AFL targets with a five-minute combined release smoke,
and audit/deny checks for both locked dependency graphs. The AFL smoke keeps the
normal forkserver path but sets `AFL_DEBUG_CHILD=1` so target-process output is
available when a forkserver startup fails; this output is untrusted diagnostic
data and must be reviewed before being shared outside the repository. It also
emits a CycloneDX dependency inventory. Separate read-only jobs build and
exercise each platform archive.

The final job does not check out or build repository code. It downloads those
exact archives, creates and verifies `SHA256SUMS`, and publishes them with the
job-local `contents: write` permission. This separation reduces accidental
publication mistakes; it is not independent approval when one person owns the
repository.

Release assets for v0.54.0 are:

```text
chacha20_poly1305-v0.54.0-x86_64-unknown-linux-musl.tar.gz
chacha20_poly1305-v0.54.0-x86_64-apple-darwin.tar.gz
chacha20_poly1305-v0.54.0-aarch64-apple-darwin.tar.gz
chacha20_poly1305-v0.54.0.cdx.json
SHA256SUMS
```

The macOS binaries are deliberately unsigned and not notarized. Gatekeeper may
warn or require a user override. Their presence is a convenience for this
personal project, not a platform-trust claim.

## Consumer verification

On Linux:

```sh
sha256sum -c SHA256SUMS
```

On macOS:

```sh
shasum -a 256 -c SHA256SUMS
```

The CycloneDX file inventories the resolved dependency graph; without an
independent signature it is informational evidence, not authentication.
SHA-256 checksums detect accidental corruption. They do not authenticate the
publisher when downloaded from the same GitHub release as the archive. No
code-signing, notarization, artifact-attestation, reproducible-build, SLSA, or
product-security claim is made.

## Incident and rollback

Before v0.54.0, rollback is a complete revert of the unreleased v2 work. After
publication, do not silently replace an asset or move the tag. Mark a
compromised release, publish appropriate security guidance, and issue a new
version. If format semantics must change, use a new authenticated format
version rather than modifying CPV2/EDEKV2 interpretation.
