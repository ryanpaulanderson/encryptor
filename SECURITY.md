# Security Policy

## Assurance and supported versions

This repository is an educational custom cryptography experiment. It has not
been independently audited, is not production-safe, and must not be used to
protect important data. Maintenance and tests do not upgrade that assurance
level.

Before v0.54.0 is published, no released version is supported. After release,
only the latest 0.x release receives best-effort security fixes. There is no
response-time or remediation-time service-level agreement.

CPV2 and EDEKV2 are immutable released formats. A defect which cannot be fixed
without changing their interpretation will receive a new authenticated format
version rather than a silent reinterpretation or downgrade fallback.

## Private reporting

Use GitHub's **Report a vulnerability** feature. If that is unavailable, email
`gh-vulnerabilities.judge874@simplelogin.com`.

Please include:

- affected commit, tag, platform, and command/API;
- the security invariant you believe is broken;
- minimal reproduction steps using synthetic data;
- impact and required attacker preconditions;
- whether public disclosure has already occurred.

Do not send real passwords, keys, plaintext, private files, or sensitive paths.
Treat sizes, salts, nonces, ciphertext, and identifiers as potentially
sensitive metadata.

## Response and coordinated disclosure

The maintainer will acknowledge reports on a best-effort basis, validate the
affected path, and coordinate a disclosure date appropriate to the impact and
availability of a complete fix. Please avoid public disclosure until a fix and
release guidance are available. A vulnerability release should include a
regression, affected-version and variant analysis, threat-model update, and
appropriate GitHub/RustSec coordination.

## Release evidence

Releases contain Linux x86-64 musl plus unsigned, unnotarized macOS Intel and
Apple Silicon archives. A CycloneDX dependency inventory accompanies them.
SHA-256 checksums help detect accidental corruption, but do not independently
authenticate the release. These hobby-project release controls are not a
cryptographic audit, a reproducible-build claim, or a guarantee that the custom
cipher composition is correct or side-channel resistant.
