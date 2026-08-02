# Release process

Public release is intentionally gated because `pkgscope` is a working title and audits the package managers used to install itself.

## One-time gates

Before the first public release, record evidence that the intended npm scope/name, GitHub repository name, search identity, and relevant trademarks have been reviewed. Configure a protected GitHub `release` environment requiring approval.

Configure these release-environment secrets:

- `APPLE_CERTIFICATE_P12_BASE64`: Developer ID Application certificate and private key in PKCS#12 form, base64 encoded.
- `APPLE_CERTIFICATE_PASSWORD`: PKCS#12 password.
- `APPLE_SIGNING_IDENTITY`: exact Developer ID Application identity.
- `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_APP_PASSWORD`: notarization credentials for `notarytool`.

npm publishing uses trusted publishing/OIDC and must not use a long-lived npm token. Register this repository and the release workflow as trusted publishers for `pkgscope`, `@pkgscope/darwin-arm64`, and `@pkgscope/darwin-x64` before enabling the publish job.

## Per release

1. Set the same semver (without `v`) in `Cargo.toml` and `npm/package.json`; update `CHANGELOG.md`.
2. Run the complete test gate documented in the README.
3. Create an annotated `vX.Y.Z` tag and push it.
4. Approve the protected release environment after the workflow validates the version and package-name gate.
5. The workflow builds both Darwin architectures, imports the Developer ID certificate into a temporary keychain, signs each Mach-O binary with hardened runtime and timestamping, verifies the signature, archives it, and submits it to Apple notarization.
6. The workflow publishes SHA-256 checksums, CycloneDX SBOMs, GitHub build provenance, platform npm packages, the thin npm launcher, and an architecture-aware Homebrew formula.
7. Verify installation through all three routes on a clean machine: native archive, npm/npx, and the generated Homebrew formula. Run `pkgscope doctor`, a scan, JSON validation, TUI start/quit, a removal plan, confirmation cancellation, and an uninstall against a disposable fixture package.

Apple cannot staple a notarization ticket directly to a standalone command-line executable. The ZIP is notarized and Gatekeeper can validate it online; the release workflow records the accepted submission. If distribution later moves to a `.pkg` or app bundle, staple and validate the ticket on that container.

The program never self-updates. npm installations update with npm, Homebrew installations with Homebrew, and native archives through a new signed download.
