# Release process

v0.3.0 is published only after the full macOS/Linux quality gate succeeds. The release is deliberately retry-safe: npm packages whose exact version already exists are verified and skipped, while any missing artifact fails the workflow.

## One-time setup

1. Confirm the npm scope, all five package names, repository identity, and relevant trademark/search results.
2. Configure the protected GitHub `release` environment and require approval.
3. Create the two new Linux native packages once with an npm CLI-authenticated maintainer session:
   - `@pirasan023/pkgscope-linux-x64`
   - `@pirasan023/pkgscope-linux-arm64`
4. Configure npm trusted publishing for this repository and `.github/workflows/release.yml` on the launcher and all four native packages. No long-lived npm token is stored in GitHub.

The first CLI-authenticated publication uses the same staged package metadata and binaries produced by the release procedure. Never publish placeholders. Once a package exists and trusted publishing is configured, the workflow owns later versions.

## Required pre-release gate

1. Set the same version in `Cargo.toml`, `Cargo.lock`, `npm/package.json`, and every optional native dependency. Add the versioned `CHANGELOG.md` section.
2. Run formatting, warning-free Clippy, all Rust targets/tests, npm tests, schema validation, `cargo package`, and `cargo audit --deny warnings`.
3. Pass macOS regression CI and the Linux jobs for:
   - Ubuntu and Debian apt;
   - npm, pnpm, pipx, uv, Cargo, and Snap on Ubuntu;
   - Fedora DNF4 and DNF5;
   - Arch pacman;
   - Alpine static-binary startup and npm installation;
   - the official Linuxbrew environment;
   - a local Flatpak repository installed into user, default-system, and named-system scopes;
   - native Ubuntu ARM64 build, npm installation, and startup.
4. Pass the pseudo-terminal TUI flow, including both sort directions, search, detail scrolling, cancellation, wrong-name rejection, disposable-package deletion, and post-action rescan.
5. Build the two musl targets with Rust's `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` targets on native x64 and ARM64 GitHub runners. Confirm exact ELF machine type, no dynamic `NEEDED` entries, and real `--version` startup.

## Publication

1. Create and push an annotated `vX.Y.Z` tag only from the reviewed commit.
2. Approve the protected `release` environment after the validate job confirms every version and schema.
3. Four native jobs test and archive `aarch64-apple-darwin`, `x86_64-apple-darwin`, `aarch64-unknown-linux-musl`, and `x86_64-unknown-linux-musl`.
4. The workflow generates a CycloneDX SBOM and GitHub build-provenance attestation for each archive, one `SHA256SUMS`, and a Formula containing all four target checksums.
5. The four native npm packages and launcher are published with provenance. An existing exact version is skipped; npm's immutable versions prevent replacement.
6. The GitHub Release receives all archives, SBOM files, checksums, and `pkgscope.rb`.
7. Fresh native x64 and ARM64 jobs install `@pirasan023/pkgscope`, download the matching GitHub archive, verify checksums and attestations, test static linking/CPU/startup, run `--version`, `doctor`, table/JSON/JSONL/CSV, validate schema v2 and Linux host data, and drive the published binary through the TUI deletion-safety test.

The release is complete only when every job succeeds and the published artifacts can be downloaded again. A failed post-publication check is a release incident: do not overwrite an npm version or GitHub asset; fix forward with a new patch version.

## Signing and updates

Artifacts are not Apple-signed or notarized, and Linux archives do not carry a distribution-vendor signature. Describe them as unsigned. SHA-256, SBOM, and GitHub provenance are provided for integrity and traceability, not as code-signing equivalents.

pkgscope never self-updates. npm installations update through npm, Homebrew/Linuxbrew installations through Homebrew, and archive installations through a newly verified download.
