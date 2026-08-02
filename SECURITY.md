# Security policy

## Reporting

Report suspected vulnerabilities privately through GitHub Security Advisories for this repository. Do not include credentials, full shell history, private registry output, or other secrets. A minimal redacted reproducer is preferred.

## Runtime boundary

pkgscope treats manager executables, local manager metadata, paths, filenames, and terminal text as untrusted. Processes are invoked with an executable and argument array, never through a shell. Output is bounded and timed out, control characters are removed, and symlinks are not recursively followed for size scans.

TUI uninstall requires exact-name confirmation followed by a fresh identity, ownership, version, dependency, privilege, and action revalidation. pkgscope refuses self-removal, manager/runtime removal, and known managed-dependent removal. apt, DNF, and pacman removal proceeds only if local dry-run/test commands prove an exact target-only transaction. No safety proof means refusal. pkgscope does not launch `sudo`; system actions run only when the process is already privileged. Snap data, Flatpak user data, related Flatpak refs, and Homebrew zap data are not deleted.

Snapshot state excludes registry credentials, environment dumps, raw shell history, and project-file contents. Inventory does not require network access. Telemetry is disabled and not implemented.

## Release boundary

Release binaries are intentionally unsigned and Apple-notarization is not claimed. Every release is instead required to provide SHA-256 checksums, a CycloneDX SBOM for each target, and GitHub build-provenance attestations. Linux artifacts must also pass static-link, exact-CPU, and startup checks. Clean Linux x64 and ARM64 jobs re-download and exercise both npm and GitHub artifacts after publication.

Users should verify the downloaded archive against `SHA256SUMS` and its GitHub attestation. These checks establish artifact integrity and recorded build provenance; they are not a substitute for platform code signing.
