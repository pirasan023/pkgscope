# Release process

Public release is intentionally gated because `pkgscope` is a working title and audits the package managers used to install itself.

## One-time gates

Before the first public release, record evidence that the intended npm scope/name, GitHub repository name, search identity, and relevant trademarks have been reviewed. Configure a protected GitHub `release` environment requiring approval. No paid Apple Developer account or Apple signing secret is used.

npm publishing uses trusted publishing/OIDC and must not use a long-lived npm token. Register this repository and the release workflow as trusted publishers for `pkgscope`, `@pkgscope/darwin-arm64`, and `@pkgscope/darwin-x64` before enabling the publish job.

## Per release

1. Set the same semver (without `v`) in `Cargo.toml` and `npm/package.json`; update `CHANGELOG.md`.
2. Run the complete test gate documented in the README.
3. Create an annotated `vX.Y.Z` tag and push it.
4. Approve the protected release environment after the workflow validates the version and package-name gate.
5. The workflow builds both Darwin architectures, verifies each Mach-O architecture, and archives the unsigned binaries.
6. The workflow publishes SHA-256 checksums, CycloneDX SBOMs, GitHub build provenance, platform npm packages, the thin npm launcher, and an architecture-aware Homebrew formula.
7. Verify installation through all three routes on a clean machine: native archive, npm/npx, and the generated Homebrew formula. Run `pkgscope doctor`, a scan, JSON validation, TUI start/quit, a removal plan, confirmation cancellation, and an uninstall against a disposable fixture package.

The published binaries are not signed or notarized by Apple. macOS may therefore block or warn about a downloaded binary. Users should only bypass a warning when they trust the repository and have verified the archive against the published `SHA256SUMS`. This tradeoff avoids requiring a paid Apple Developer Program membership and must not be described as equivalent to Apple notarization.

The program never self-updates. npm installations update with npm, Homebrew installations with Homebrew, and native archives through a new signed download.
